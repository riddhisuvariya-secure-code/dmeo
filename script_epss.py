from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import pymongo
from dotenv import load_dotenv
from pymongo import UpdateOne
from pymongo.errors import ServerSelectionTimeoutError
from tqdm import tqdm

load_dotenv()

# =========================================================
# CONFIG
# =========================================================

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("MONGO_URI environment variable required")

DB_NAME = os.getenv("MONGO_DB_NAME", "nvd")

COLLECTION_CVES = "nvd_cvesss"
COLLECTION_EPSS = "epss_scores"

RESULTS_PER_PAGE = 2000
EPSS_PAGE_SIZE = 100

CONCURRENCY_LIMIT = 5
DB_BATCH_SIZE = 1000

MAX_RETRIES = 5
BASE_DELAY = 2
MAX_DELAY = 60

REQUEST_TIMEOUT = 120

USER_AGENT = "NVD-EPSS-Importer/1.0"

# =========================================================
# MONGODB
# =========================================================

print("Connecting to MongoDB...")

client = pymongo.MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=30000,
    connectTimeoutMS=30000,
    socketTimeoutMS=60000,
    maxPoolSize=20,
    retryWrites=True,
    retryReads=True,
)

db = client[DB_NAME]

col_cves = db[COLLECTION_CVES]
col_epss = db[COLLECTION_EPSS]


def ensure_indexes():

    # CVE indexes
    cve_indexes = [i.get("name") for i in col_cves.list_indexes()]

    if "cve_id_1" not in cve_indexes:
        col_cves.create_index("cve_id", unique=True)

    # EPSS indexes
    epss_indexes = [i.get("name") for i in col_epss.list_indexes()]

    if "cve_1" not in epss_indexes:
        col_epss.create_index("cve", unique=True)

    if "epss_1" not in epss_indexes:
        col_epss.create_index("epss")


try:
    client.admin.command("ping")
    ensure_indexes()

except ServerSelectionTimeoutError as e:
    print(f"MongoDB connection failed: {e}")
    raise SystemExit(1)

print("MongoDB ready.\n")

# =========================================================
# HELPERS
# =========================================================


def sha256_data(data: Any) -> str:
    raw = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def backoff(attempt: int) -> float:
    ceiling = min(MAX_DELAY, BASE_DELAY * (2**attempt))
    return random.uniform(1, ceiling)


# =========================================================
# HTTP FETCH
# =========================================================


async def fetch_json(
    session: aiohttp.ClientSession,
    url: str,
    params: dict,
) -> Optional[dict]:

    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    for attempt in range(MAX_RETRIES):

        try:

            async with session.get(
                url,
                params=params,
                headers=headers,
                timeout=timeout,
            ) as response:

                if response.status == 200:
                    return await response.json()

                if response.status == 429:
                    wait = 30 + random.uniform(1, 10)
                    print(f"[429] Sleeping {wait:.1f}s")
                    await asyncio.sleep(wait)
                    continue

                if response.status in [500, 502, 503, 504]:
                    wait = backoff(attempt)
                    print(f"[{response.status}] retry in {wait:.1f}s")
                    await asyncio.sleep(wait)
                    continue

                print(f"HTTP {response.status}")
                return None

        except (
            asyncio.TimeoutError,
            aiohttp.ClientError,
            aiohttp.ServerDisconnectedError,
        ) as e:

            wait = backoff(attempt)

            print(f"Request error: {e}")
            print(f"Retry in {wait:.1f}s")

            await asyncio.sleep(wait)

    return None


# =========================================================
# NVD FETCH
# =========================================================


async def fetch_nvd_page(
    session: aiohttp.ClientSession,
    start_index: int,
) -> Tuple[int, Optional[dict]]:

    params = {
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE,
    }

    data = await fetch_json(
        session,
        NVD_API_BASE,
        params,
    )

    return start_index, data


# =========================================================
# EPSS FETCH
# =========================================================


async def fetch_epss_page(
    session: aiohttp.ClientSession,
    offset: int,
) -> Tuple[int, Optional[dict]]:

    params = {
        "limit": EPSS_PAGE_SIZE,
        "offset": offset,
    }

    data = await fetch_json(
        session,
        EPSS_API_BASE,
        params,
    )

    return offset, data


# =========================================================
# BUILD OPS
# =========================================================


def build_nvd_ops(
    vulnerabilities: List[dict],
    fetched_at: datetime,
) -> List[UpdateOne]:

    ops = []

    for item in vulnerabilities:

        cve = item.get("cve", {})

        cve_id = cve.get("id")

        if not cve_id:
            continue

        doc = {
            "cve_id": cve_id,
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified"),
            "fetched_at": fetched_at,
            "sha": sha256_data(item),
            "raw": item,
        }

        ops.append(
            UpdateOne(
                {"cve_id": cve_id},
                {"$set": doc},
                upsert=True,
            )
        )

    return ops


def build_epss_ops(
    rows: List[dict],
    fetched_at: datetime,
) -> List[UpdateOne]:

    ops = []

    for row in rows:

        cve = row.get("cve")

        if not cve:
            continue

        doc = {
            "cve": cve,
            "epss": float(row.get("epss", 0)),
            "percentile": float(row.get("percentile", 0)),
            "date": row.get("date"),
            "fetched_at": fetched_at,
            "sha": sha256_data(row),
            "raw": row,
        }

        ops.append(
            UpdateOne(
                {"cve": cve},
                {"$set": doc},
                upsert=True,
            )
        )

    return ops


# =========================================================
# DB WRITE
# =========================================================


async def write_batch(
    loop,
    collection,
    ops,
):

    if not ops:
        return

    try:

        fn = lambda: collection.bulk_write(
            ops,
            ordered=False,
        )

        await loop.run_in_executor(None, fn)

    except pymongo.errors.BulkWriteError as e:
        print(f"Bulk write error: {e.details}")

    except Exception as e:
        print(f"DB write error: {e}")


# =========================================================
# IMPORT NVD
# =========================================================


async def import_nvd(session, loop):

    print("\nStarting NVD import...\n")

    fetched_at = datetime.now(timezone.utc)

    _, first_data = await fetch_nvd_page(session, 0)

    if not first_data:
        print("Failed first NVD request")
        return

    total_results = first_data.get("totalResults", 0)

    print(f"Total NVD CVEs: {total_results:,}")

    vulnerabilities = first_data.get("vulnerabilities", [])

    first_ops = build_nvd_ops(
        vulnerabilities,
        fetched_at,
    )

    await write_batch(
        loop,
        col_cves,
        first_ops,
    )

    processed = len(vulnerabilities)

    pbar = tqdm(
        total=total_results,
        initial=processed,
        desc="NVD",
        unit=" CVE",
    )

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def sem_fetch(idx):
        async with semaphore:
            return await fetch_nvd_page(session, idx)

    tasks = []

    for start_index in range(
        RESULTS_PER_PAGE,
        total_results,
        RESULTS_PER_PAGE,
    ):
        tasks.append(
            asyncio.create_task(
                sem_fetch(start_index)
            )
        )

    batch_ops = []

    for future in asyncio.as_completed(tasks):

        _, data = await future

        if not data:
            continue

        vulns = data.get("vulnerabilities", [])

        ops = build_nvd_ops(
            vulns,
            fetched_at,
        )

        batch_ops.extend(ops)

        processed += len(vulns)

        pbar.update(len(vulns))

        if len(batch_ops) >= DB_BATCH_SIZE:

            await write_batch(
                loop,
                col_cves,
                batch_ops,
            )

            batch_ops.clear()

    if batch_ops:
        await write_batch(
            loop,
            col_cves,
            batch_ops,
        )

    pbar.close()

    print(f"NVD import complete: {processed:,}")


# =========================================================
# IMPORT EPSS
# =========================================================


async def import_epss(session, loop):

    print("\nStarting EPSS import...\n")

    fetched_at = datetime.now(timezone.utc)

    offset = 0
    total_processed = 0

    pbar = tqdm(
        desc="EPSS",
        unit=" rows",
    )

    while True:

        _, data = await fetch_epss_page(
            session,
            offset,
        )

        if not data:
            break

        rows = data.get("data", [])

        if not rows:
            break

        ops = build_epss_ops(
            rows,
            fetched_at,
        )

        await write_batch(
            loop,
            col_epss,
            ops,
        )

        count = len(rows)

        total_processed += count

        pbar.update(count)

        offset += EPSS_PAGE_SIZE

    pbar.close()

    print(f"EPSS import complete: {total_processed:,}")


# =========================================================
# MAIN
# =========================================================


async def worker():

    loop = asyncio.get_running_loop()

    connector = aiohttp.TCPConnector(
        limit=CONCURRENCY_LIMIT,
        limit_per_host=CONCURRENCY_LIMIT,
    )

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    async with aiohttp.ClientSession(
        connector=connector,
        headers=headers,
    ) as session:

        await import_nvd(
            session,
            loop,
        )

        await import_epss(
            session,
            loop,
        )


# =========================================================
# ENTRY
# =========================================================


def main():

    try:
        asyncio.run(worker())

    except KeyboardInterrupt:
        print("\nStopped by user")

    except Exception as e:
        print(f"Fatal error: {e}")


if __name__ == "__main__":
    main()