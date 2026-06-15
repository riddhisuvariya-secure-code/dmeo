import asyncio
import aiohttp
import pymongo
import functools
import os
import json
import requests
import time
from tqdm import tqdm
from datetime import datetime, timezone
from typing import Dict
from dotenv import load_dotenv

from calculator_sha import PackageDocument, compare

# ================= CONFIG =================

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("MONGO_DB_NAME")

if not MONGO_URI:
    raise ValueError("MONGO_URI missing")

if not DB_NAME:
    raise ValueError("MONGO_DB_NAME missing")

COLLECTION_NAME = "Updated_npm_metadata"

CONCURRENCY_LIMIT = int(os.getenv("NPM_CONCURRENCY_LIMIT", "20"))
BATCH_SIZE = int(os.getenv("NPM_BATCH_SIZE", "200"))
MAX_FETCH_RETRIES = 5
MAX_ALL_DOCS_RETRIES = 6
FETCH_BACKOFF_BASE_SECONDS = float(os.getenv("NPM_FETCH_BACKOFF_BASE_SECONDS", "0.8"))
ALL_DOCS_BACKOFF_BASE_SECONDS = float(os.getenv("NPM_ALL_DOCS_BACKOFF_BASE_SECONDS", "1.5"))
TOTAL_ROWS_TOLERANCE_FRACTION = 0.01

REPLICATE_ALL_DOCS_URL = "https://replicate.npmjs.com/_all_docs"
REGISTRY_URL = "https://registry.npmjs.org/{}"

# ================= MONGODB =================

print("Connecting to MongoDB...")

client = pymongo.MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=30000,
    connectTimeoutMS=30000,
    socketTimeoutMS=60000,
    maxPoolSize=50
)

db = client[DB_NAME]
collection = db[COLLECTION_NAME]

collection.create_index("package_name", unique=True)

print("MongoDB connected")

# ================= FETCH PACKAGE =================

def _backoff_seconds(base_seconds: float, attempt: int) -> float:

    # 0-based attempt -> exponential backoff
    return base_seconds * (2 ** attempt)


def _normalize_license_value(value):

    if value is None:
        return None

    if isinstance(value, str):
        license_text = value.strip()
        return license_text or None

    if isinstance(value, dict):
        # Common npm forms: {"type": "MIT"} or {"name": "MIT"}
        license_text = value.get("type") or value.get("name")
        if isinstance(license_text, str):
            license_text = license_text.strip()
            return license_text or None
        return None

    if isinstance(value, list):
        normalized_items = []
        for item in value:
            normalized = _normalize_license_value(item)
            if normalized:
                normalized_items.append(normalized)
        if normalized_items:
            return " OR ".join(sorted(set(normalized_items)))
        return None

    return None


def _extract_package_license(data):

    # 1) Top-level "license"
    normalized = _normalize_license_value(data.get("license"))
    if normalized:
        return normalized, data.get("license")

    # 2) Top-level legacy "licenses"
    normalized = _normalize_license_value(data.get("licenses"))
    if normalized:
        return normalized, data.get("licenses")

    # 3) Latest version license via dist-tags.latest
    versions = data.get("versions") or {}
    dist_tags = data.get("dist-tags") or {}
    latest_version = dist_tags.get("latest")

    if latest_version and latest_version in versions:
        latest_meta = versions.get(latest_version) or {}
        normalized = _normalize_license_value(latest_meta.get("license"))
        if normalized:
            return normalized, latest_meta.get("license")
        normalized = _normalize_license_value(latest_meta.get("licenses"))
        if normalized:
            return normalized, latest_meta.get("licenses")

    # 4) Fallback: first version that has license
    for ver_data in versions.values():
        if not isinstance(ver_data, dict):
            continue
        normalized = _normalize_license_value(ver_data.get("license"))
        if normalized:
            return normalized, ver_data.get("license")
        normalized = _normalize_license_value(ver_data.get("licenses"))
        if normalized:
            return normalized, ver_data.get("licenses")

    return "UNKNOWN", None


async def fetch_package_metadata(session, package_name, semaphore):

    url = REGISTRY_URL.format(package_name)
    retryable_statuses = {408, 425, 429, 500, 502, 503, 504}

    async with semaphore:

        last_reason = "unknown"

        for attempt in range(MAX_FETCH_RETRIES):

            try:
                async with session.get(url, timeout=60) as resp:

                    if resp.status == 200:
                        return {
                            "package_name": package_name,
                            "data": await resp.json(),
                            "status": "ok",
                        }

                    if resp.status == 404:
                        return {
                            "package_name": package_name,
                            "data": None,
                            "status": "not_found",
                            "reason": "http_404",
                        }

                    last_reason = f"http_{resp.status}"

                    if resp.status not in retryable_statuses:
                        break

            except Exception as e:
                last_reason = f"exception_{type(e).__name__}"

            if attempt < MAX_FETCH_RETRIES - 1:
                await asyncio.sleep(_backoff_seconds(FETCH_BACKOFF_BASE_SECONDS, attempt))

        return {
            "package_name": package_name,
            "data": None,
            "status": "failed",
            "reason": last_reason,
        }


# ================= PROCESS BATCH =================

async def process_npm_batch(valid_data, current_time, counters):

    operations = []

    batch_package_names = [data.get("name") for data in valid_data if data.get("name")]
    existing_sha_map = {}

    if batch_package_names:
        existing_docs = collection.find(
            {"package_name": {"$in": batch_package_names}},
            {"package_name": 1, "sha": 1}
        )
        for doc in existing_docs:
            existing_sha_map[doc["package_name"]] = doc.get("sha")

    for data in valid_data:

        pkg_name = data.get("name")

        if not pkg_name:
            continue

        if "description" in data and data["description"]:
            if len(str(data["description"])) > 10000:
                data["description"] = str(data["description"])[:10000]

        normalized_license, raw_license = _extract_package_license(data)
        data["license"] = normalized_license
        data["license_raw"] = raw_license

        if "versions" in data:

            minimal_versions = {}

            for ver, ver_data in data["versions"].items():

                minimal_versions[ver] = {
                    "name": ver_data.get("name"),
                    "version": ver_data.get("version"),
                    "license": _normalize_license_value(ver_data.get("license"))
                    or _normalize_license_value(ver_data.get("licenses"))
                    or "UNKNOWN",
                    "dist": ver_data.get("dist", {}),
                    "dependencies": ver_data.get("dependencies", {})
                }

            data["versions"] = minimal_versions

        existing_sha = existing_sha_map.get(pkg_name)

        new_sha, processed_data, action = compare(
            data,
            existing_sha,
            pkg_name,
            current_time
        )

        counters["total"] += 1

        if action == "insert":
            counters["inserted"] += 1

        elif action == "update":
            counters["updated"] += 1

        elif action == "skip":
            counters["skipped"] += 1
            continue

        doc_data = {
            "package_name": pkg_name,
            "sha": new_sha,
            "object": data
        }

        if action == "update":
            doc_data["updated_time"] = current_time

        try:

            package_doc = PackageDocument(**doc_data)

            doc_dict = package_doc.model_dump(exclude_none=True)

        except Exception as e:
            print(f"Pydantic error for {pkg_name}: {e}")
            continue

        operations.append(

            pymongo.UpdateOne(
                {"package_name": pkg_name},
                {"$set": doc_dict},
                upsert=True
            )

        )

    return operations


# ================= WORKER =================

async def worker(package_names):

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    connector = aiohttp.TCPConnector(limit=CONCURRENCY_LIMIT)

    loop = asyncio.get_running_loop()

    counters = {
        "total": 0,
        "inserted": 0,
        "updated": 0,
        "skipped": 0,
        "fetch_failed": 0,
        "not_found": 0,
    }

    failed_packages = []

    async with aiohttp.ClientSession(connector=connector) as session:

        progress = tqdm(total=len(package_names), unit="pkg")

        for i in range(0, len(package_names), BATCH_SIZE):

            batch = package_names[i:i+BATCH_SIZE]

            tasks = [
                fetch_package_metadata(session, name, semaphore)
                for name in batch
            ]

            results = await asyncio.gather(*tasks)

            valid_data = []

            for result in results:
                if not result:
                    counters["fetch_failed"] += 1
                    continue

                status = result.get("status")

                if status == "ok":
                    valid_data.append(result["data"])
                elif status == "not_found":
                    counters["not_found"] += 1
                else:
                    counters["fetch_failed"] += 1
                    if len(failed_packages) < 500:
                        failed_packages.append({
                            "package_name": result.get("package_name"),
                            "reason": result.get("reason", "unknown"),
                        })

            if valid_data:

                operations = await process_npm_batch(
                    valid_data,
                    datetime.now(timezone.utc),
                    counters
                )

                if operations:

                    try:
                        write_func = functools.partial(
                            collection.bulk_write,
                            operations,
                            ordered=False
                        )

                        await loop.run_in_executor(None, write_func)
                    except Exception as e:
                        print(f"DB Write Error: {e}")
                        print(f"Failed to write batch of {len(operations)} operations")

            progress.update(len(batch))

        progress.close()

    return counters, failed_packages


# ================= STREAMED PACKAGE LIST FUNCTION =================

def iter_all_package_name_batches(state):

    print("Fetching npm package list...")

    headers = {
        "Accept": "application/json",
        "User-Agent": "npm-importer",
        "npm-replication-opt-in": "true"  # Required header for npm replicate API
    }

    limit = 10000
    startkey = None
    fetched_count = 0
    expected_total_rows = None
    page_number = 0

    while True:

        params = {"limit": limit}

        if startkey is not None:
            params["startkey"] = json.dumps(startkey)

        data = None
        last_error = "unknown"

        for attempt in range(MAX_ALL_DOCS_RETRIES):
            try:
                r = requests.get(
                    REPLICATE_ALL_DOCS_URL,
                    headers=headers,
                    params=params,
                    timeout=120
                )

                if r.status_code == 200:
                    data = r.json()
                    break

                last_error = f"HTTP {r.status_code}: {r.text[:200]}"
            except Exception as e:
                last_error = f"{type(e).__name__}: {e}"

            if attempt < MAX_ALL_DOCS_RETRIES - 1:
                sleep_for = _backoff_seconds(ALL_DOCS_BACKOFF_BASE_SECONDS, attempt)
                print(f"_all_docs page retry {attempt+1}/{MAX_ALL_DOCS_RETRIES-1} in {sleep_for:.1f}s ({last_error})")
                time.sleep(sleep_for)

        if data is None:
            raise RuntimeError(
                f"Failed to fetch npm _all_docs page after {MAX_ALL_DOCS_RETRIES} attempts. "
                f"startkey={startkey!r}, error={last_error}"
            )

        if expected_total_rows is None:
            expected_total_rows = data.get("total_rows")
            state["expected_total_rows"] = expected_total_rows

        rows = data.get("rows", [])

        if not rows:
            break

        names = [row["id"] for row in rows if row.get("id")]

        # Skip first row if paginating (it's a duplicate of last row from previous page)
        if startkey is not None and names:
            names = names[1:]

        fetched_count += len(names)
        page_number += 1
        state["pages"] = page_number
        state["fetched_names"] = fetched_count

        print(f"Fetched {fetched_count:,} packages (page {page_number})...")

        if names:
            yield names

        if len(rows) < limit:
            break

        # Get the last key for next iteration
        if rows:
            startkey = rows[-1].get("id")
        else:
            break

    print(f"\nTotal packages retrieved: {fetched_count:,}")

    if expected_total_rows is not None:
        print(f"npm reported total_rows: {expected_total_rows:,}")

        min_expected = int(expected_total_rows * (1 - TOTAL_ROWS_TOLERANCE_FRACTION))

        if fetched_count < min_expected:
            raise RuntimeError(
                "Package list completeness check failed: "
                f"retrieved={fetched_count:,}, total_rows={expected_total_rows:,}, "
                f"tolerance={TOTAL_ROWS_TOLERANCE_FRACTION:.2%}"
            )

    state["expected_total_rows"] = expected_total_rows
    state["fetched_names"] = fetched_count


def run_final_coverage_check(collection, expected_total_rows, failed_packages, counters):

    if expected_total_rows is None:
        print("Coverage check skipped: npm total_rows missing")
        return

    mongo_count = collection.estimated_document_count()
    effective_expected = max(expected_total_rows - counters.get("not_found", 0), 0)
    coverage = (mongo_count / effective_expected) * 100 if effective_expected else 0

    print("\n========= COVERAGE CHECK =========")
    print(f"Mongo docs in {COLLECTION_NAME}: {mongo_count:,}")
    print(f"npm total_rows:               {expected_total_rows:,}")
    print(f"effective expected docs:      {effective_expected:,}")
    print(f"Coverage:                     {coverage:.2f}%")
    print(f"Failed package fetches:       {len(failed_packages):,}")

    if failed_packages:
        print("Sample failed packages:")
        for item in failed_packages[:20]:
            print(f"  - {item.get('package_name')}: {item.get('reason')}")

    if failed_packages or mongo_count < effective_expected:
        raise RuntimeError(
            "Final coverage check failed: dataset incomplete or package fetch failures detected."
        )


# ================= MAIN =================

if __name__ == "__main__":

    listing_state = {}

    aggregate_counters = {
        "total": 0,
        "inserted": 0,
        "updated": 0,
        "skipped": 0,
        "fetch_failed": 0,
        "not_found": 0,
    }
    failed_packages = []
    page_batch_count = 0

    try:
        for package_batch in iter_all_package_name_batches(listing_state):
            if not package_batch:
                continue

            page_batch_count += 1
            counters, failed_batch = asyncio.run(worker(package_batch))

            for key in aggregate_counters:
                aggregate_counters[key] += counters.get(key, 0)

            if len(failed_packages) < 500 and failed_batch:
                room = 500 - len(failed_packages)
                failed_packages.extend(failed_batch[:room])

    except KeyboardInterrupt:
        print("Stopped by user")
        exit()

    print("\n========= SUMMARY =========")

    print(f"Page batches processed: {page_batch_count:,}")
    print(f"Package IDs listed: {listing_state.get('fetched_names', 0):,}")
    print(f"Total processed: {aggregate_counters['total']:,}")
    print(f"Inserted: {aggregate_counters['inserted']:,}")
    print(f"Updated: {aggregate_counters['updated']:,}")
    print(f"Skipped: {aggregate_counters['skipped']:,}")
    print(f"Fetch failed: {aggregate_counters['fetch_failed']:,}")
    print(f"Not found: {aggregate_counters['not_found']:,}")

    run_final_coverage_check(
        collection,
        listing_state.get("expected_total_rows"),
        failed_packages,
        aggregate_counters,
    )

    print("Import finished")