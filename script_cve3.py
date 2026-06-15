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

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("MONGO_URI environment variable is required.")

DB_NAME = os.getenv("MONGO_DB_NAME", "nvd")

COLLECTION_NAME = "nvd_cves"

# NVD max = 2000
RESULTS_PER_PAGE = 2000

# concurrency
CONCURRENCY_LIMIT = 5

# DB
DB_BATCH_SIZE = 1000

# retry
MAX_RETRIES = 5
BASE_DELAY = 2
MAX_DELAY = 60

# timeout
REQUEST_TIMEOUT = 120

# user-agent
USER_AGENT = "NVD-CVE-Importer/1.0"

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
collection = db[COLLECTION_NAME]


def ensure_indexes():
    indexes = [i.get("name") for i in collection.list_indexes()]

    if "cve_id_1" not in indexes:
        print("Creating index on cve_id...")
        collection.create_index("cve_id", unique=True)

    if "published_1" not in indexes:
        collection.create_index("published")

    if "lastModified_1" not in indexes:
        collection.create_index("lastModified")


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
# FETCH
# =========================================================


async def fetch_page(
    session: aiohttp.ClientSession,
    start_index: int,
) -> Tuple[int, Optional[dict]]:

    params = {
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE,
    }

    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    for attempt in range(MAX_RETRIES):

        try:
            async with session.get(
                NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=timeout,
            ) as response:

                if response.status == 200:
                    data = await response.json()
                    return start_index, data

                if response.status == 429:
                    wait = 30 + random.uniform(1, 10)
                    print(f"[429] Rate limited. Sleeping {wait:.1f}s")
                    await asyncio.sleep(wait)
                    continue

                if response.status in [500, 502, 503, 504]:
                    wait = backoff(attempt)
                    print(f"[{response.status}] Retry in {wait:.1f}s")
                    await asyncio.sleep(wait)
                    continue

                print(f"HTTP {response.status} at index {start_index}")
                return start_index, None

        except (
            asyncio.TimeoutError,
            aiohttp.ClientError,
            aiohttp.ServerDisconnectedError,
        ) as e:
            wait = backoff(attempt)
            print(f"Request error: {e} | retry in {wait:.1f}s")
            await asyncio.sleep(wait)

    return start_index, None


# =========================================================
# BUILD DB OPS
# =========================================================


def build_bulk_ops(
    vulnerabilities: List[dict],
    fetched_at: datetime,
) -> List[UpdateOne]:

    ops = []

    for item in vulnerabilities:

        cve = item.get("cve", {})

        cve_id = cve.get("id")

        if not cve_id:
            continue

        published = cve.get("published")
        last_modified = cve.get("lastModified")

        sha = sha256_data(item)

        doc = {
            "cve_id": cve_id,
            "published": published,
            "lastModified": last_modified,
            "fetched_at": fetched_at,
            "sha": sha,
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


# =========================================================
# DB WRITE
# =========================================================


async def write_batch(
    loop: asyncio.AbstractEventLoop,
    ops: List[UpdateOne],
):

    if not ops:
        return

    try:
        fn = lambda: collection.bulk_write(ops, ordered=False)

        await loop.run_in_executor(None, fn)

    except pymongo.errors.BulkWriteError as e:
        print(f"Bulk write error: {e.details}")

    except Exception as e:
        print(f"DB write error: {e}")


# =========================================================
# MAIN WORKER
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

    fetched_at = datetime.now(timezone.utc)

    async with aiohttp.ClientSession(
        connector=connector,
        headers=headers,
    ) as session:

        # first request
        _, first_data = await fetch_page(session, 0)

        if not first_data:
            print("Failed initial request.")
            return

        total_results = first_data.get("totalResults", 0)

        vulnerabilities = first_data.get("vulnerabilities", [])

        print(f"Total CVEs: {total_results:,}")

        total_pages = (
            total_results // RESULTS_PER_PAGE
        ) + 1

        print(f"Total pages: {total_pages:,}")

        # save first page
        first_ops = build_bulk_ops(
            vulnerabilities,
            fetched_at,
        )

        await write_batch(loop, first_ops)

        processed = len(vulnerabilities)

        pbar = tqdm(
            total=total_results,
            initial=processed,
            desc="Importing CVEs",
            unit=" CVE",
        )

        semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

        async def sem_fetch(idx):
            async with semaphore:
                return await fetch_page(session, idx)

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

            start_index, data = await future

            if not data:
                continue

            vulns = data.get("vulnerabilities", [])

            ops = build_bulk_ops(
                vulns,
                fetched_at,
            )

            batch_ops.extend(ops)

            processed += len(vulns)

            pbar.update(len(vulns))

            if len(batch_ops) >= DB_BATCH_SIZE:
                await write_batch(loop, batch_ops)
                batch_ops.clear()

        if batch_ops:
            await write_batch(loop, batch_ops)

        pbar.close()

        print("\nImport complete.")
        print(f"Total processed: {processed:,}")


# =========================================================
# ENTRY
# =========================================================

def main():

    try:
        asyncio.run(worker())

    except KeyboardInterrupt:
        print("\nStopped by user.")

    except Exception as e:
        print(f"Fatal error: {e}")


if __name__ == "__main__":
    main()