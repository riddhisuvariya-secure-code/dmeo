import asyncio
import aiohttp
import pymongo
from pymongo.errors import ServerSelectionTimeoutError
import functools
import os
import random
from tqdm import tqdm
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Literal
from dotenv import load_dotenv

load_dotenv()

from calculator_sha import PackageDocument, compare

# ================= CONFIGURATION =================
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("MONGO_URI environment variable is required.")
DB_NAME = os.getenv("MONGO_DB_NAME")
if not DB_NAME:
    raise ValueError("MONGO_DB_NAME environment variable is required.")
COLLECTION_NAME = "Updated_pypi_metadata"

# ================= Concurrency =================
# Start at 10. Raise to 15 only if fail= stays 0 for 10+ minutes.
CONCURRENCY_LIMIT = 10

# Number of successfully fetched records to accumulate before writing to MongoDB.
# Unrelated to HTTP concurrency.
DB_BATCH_SIZE = 200

# ================= Retry / Timeout =================
MAX_RETRIES     = 6     # total attempts per package (1st try + 5 retries)
BASE_DELAY      = 1.0   # base back-off seconds (doubles each retry + jitter)
MAX_DELAY       = 60.0  # cap on any single wait
REQUEST_TIMEOUT = 60    # per-request HTTP timeout in seconds

# ================= Rate-limit cooldown =================
# When ANY worker gets a 429, ALL workers pause this long.
# PyPI's window is 60 s; 65 s gives it time to fully reset.
RATE_LIMIT_PAUSE = 65.0

# == Startup stagger =====
# The first CONCURRENCY_LIMIT tasks each sleep a random amount up to this value
# before their first request. Spreads the initial burst over ~5 seconds.
STARTUP_STAGGER_MAX = 5.0
    
# ================= PyPI endpoints =================
SIMPLE_INDEX_URL = "https://pypi.org/simple/"
JSON_API_URL     = "https://pypi.org/pypi/{}/json"


# ================= DATABASE SETUP =================
print("Connecting to MongoDB...")
client = pymongo.MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=30_000,
    connectTimeoutMS=30_000,
    socketTimeoutMS=60_000,
    maxPoolSize=10,
    minPoolSize=2,
    retryWrites=True,
    retryReads=True,
)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

try:
    # Force a fast connection check with a clear error if unreachable.
    client.admin.command("ping")
    idx_names = [i.get("name") for i in collection.list_indexes()]
    if "package_name_1" not in idx_names:
        print("Creating unique index on 'package_name'...")
        collection.create_index("package_name", unique=True)
        print("Index created.")
    else:
        print("Index already exists.")
except ServerSelectionTimeoutError as e:
    print("\n[ERROR] Could not connect to MongoDB.")
    print(f"  MONGO_URI: {MONGO_URI!r}")
    print(f"  Database:  {DB_NAME!r}")
    print("  Fix: start MongoDB locally, or set MONGO_URI to a reachable server.")
    print(f"  Details: {e}")
    raise SystemExit(2)
except pymongo.errors.OperationFailure as e:
    if e.code == 14031:
        print(f"[WARN] Not enough disk space for index: {e}")
    else:
        raise
print("MongoDB ready.\n")


# ================= SHA MAP =================
def load_existing_sha_map(col) -> Dict[str, str]:
    sha_map: Dict[str, str] = {}
    try:
        for doc in col.find({}, {"package_name": 1, "sha": 1, "_id": 0}):
            if "package_name" in doc and "sha" in doc:
                sha_map[doc["package_name"]] = doc["sha"]
    except Exception as e:
        print(f"[WARN] Could not load SHA map: {e}")
    return sha_map


# ================= BACK-OFF HELPER =================
def _backoff(attempt: int, base: float = BASE_DELAY, cap: float = MAX_DELAY) -> float:
    """Full-jitter exponential back-off: Uniform(0.1, min(cap, base * 2^attempt))"""
    ceiling = min(cap, base * (2 ** attempt))
    return random.uniform(0.1, ceiling)


# ================= GLOBAL RATE-LIMIT GATE =================
# Set inside worker() once an event loop is running — never at module level.
_rl_event: Optional[asyncio.Event] = None
_rl_lock:  Optional[asyncio.Lock]  = None


async def _pause_all_workers(who: str):
    """
    The first worker to see a 429  the lock and pauses everyone.
    Subsequent workers see the event is already set and return immediately.
    """
    async with _rl_lock:
        if _rl_event.is_set():
            return  # another worker already triggered the pause
        _rl_event.set()
        print(f"\n[429] '{who}' rate-limited — pausing ALL workers "
              f"for {RATE_LIMIT_PAUSE:.0f}s …")
        await asyncio.sleep(RATE_LIMIT_PAUSE)
        _rl_event.clear()
        print("[429] Cooldown done — resuming.\n")


async def _wait_for_cooldown():
    """Block until the rate-limit pause clears, with a random stagger on wake-up."""
    if _rl_event.is_set():
        await asyncio.sleep(random.uniform(0.1, 3.0))  # prevent thundering herd
        while _rl_event.is_set():
            await asyncio.sleep(0.5)


# ================= FETCH ONE PACKAGE =================
FetchStatus = Literal["ok", "missing", "failed"]


async def fetch_one(
    session:       aiohttp.ClientSession,
    name:          str,
    semaphore:     asyncio.Semaphore,
    startup_delay: float = 0.0,
) -> Tuple[str, FetchStatus, Optional[Dict]]:
    """
    Fetch PyPI JSON for one package.
    Returns:
      - (name, "ok", data) on success
      - (name, "missing", None) when package is 404/410
      - (name, "failed", None) when retries are exhausted

    startup_delay  — seconds to sleep before the very first attempt.
                     Used to stagger the initial burst of connections.
    """
    url = JSON_API_URL.format(name)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

    async with semaphore:
        if startup_delay > 0:
            await asyncio.sleep(startup_delay)

        for attempt in range(MAX_RETRIES):
            await _wait_for_cooldown()

            try:
                async with session.get(url, timeout=timeout) as resp:

                    if resp.status == 200:
                        return name, "ok", await resp.json(content_type=None)

                    if resp.status in (404, 410):
                        # Package doesn't exist or was yanked — not a failure
                        return name, "missing", None

                    if resp.status == 429:
                        # Trigger global cooldown; also back off personally
                        asyncio.create_task(_pause_all_workers(name))
                        await asyncio.sleep(_backoff(attempt, base=BASE_DELAY * 5))
                        continue

                    if resp.status in (500, 502, 503, 504):
                        await asyncio.sleep(_backoff(attempt))
                        continue

                    # 400, 403, or anything else — give up immediately
                    return name, "failed", None

            except (asyncio.TimeoutError,
                    aiohttp.ServerDisconnectedError,
                    aiohttp.ClientConnectorError,
                    aiohttp.ClientResponseError,
                    aiohttp.ClientPayloadError):
                await asyncio.sleep(_backoff(attempt))

            except Exception:
                await asyncio.sleep(_backoff(attempt))

        return name, "failed", None   # all retries exhausted


# ================= BUILD MONGO OPERATIONS =================
def build_mongo_ops(
    records:      List[Dict],
    sha_map:      Dict[str, str],
    current_time: datetime,
    counters:     Dict[str, int],
) -> List[pymongo.UpdateOne]:
    ops: List[pymongo.UpdateOne] = []

    for data in records:
        pkg_name = data.get("info", {}).get("name")
        if not pkg_name:
            continue

        # Strip large fields to stay under BSON 16 MB limit
        data.get("info", {}).pop("description", None)
        if "releases" in data:
            data["releases"] = {
                ver: [
                    {
                        "digests": f.get("digests", {}),
                        "url": f.get("url", ""),
                        "packagetype": f.get("packagetype", ""),
                    }
                    for f in files
                ]
                for ver, files in data["releases"].items()
            }

        existing_sha = sha_map.get(pkg_name)
        new_sha, _, action = compare(data, existing_sha, pkg_name, current_time)
        sha_map[pkg_name] = new_sha

        counters["total"] += 1
        if action == "insert":
            counters["inserted"] += 1
        elif action == "update":
            counters["updated"] += 1
        elif action == "skip":
            counters["skipped"] += 1
            continue

        doc = {"package_name": pkg_name, "sha": new_sha, "object": data}
        if action == "update":
            doc["updated_time"] = current_time

        try:
            validated = PackageDocument(**doc).model_dump(exclude_none=True)
        except Exception as e:
            print(f"[VALIDATION] {pkg_name}: {e}")
            counters["validation_errors"] += 1
            continue

        ops.append(pymongo.UpdateOne(
            {"package_name": pkg_name},
            {"$set": validated},
            upsert=True,
        ))

    return ops


# ================= DB WRITE WITH RETRY =================
async def db_write(
    loop: asyncio.AbstractEventLoop,
    ops:  List[pymongo.UpdateOne],
):
    for attempt in range(4):
        try:
            fn = functools.partial(collection.bulk_write, ops, ordered=False)
            await loop.run_in_executor(None, fn)
            return
        except pymongo.errors.BulkWriteError as bwe:
            non_dup = [e for e in bwe.details.get("writeErrors", [])
                       if e.get("code") != 11000]
            if non_dup:
                print(f"[DB] Non-duplicate write errors: {non_dup[:2]}")
            return
        except (pymongo.errors.AutoReconnect,
                pymongo.errors.NetworkTimeout,
                pymongo.errors.ConnectionFailure) as e:
            wait = 5 * (attempt + 1)
            print(f"[DB] Connection error (attempt {attempt+1}/4), retry in {wait}s: {e}")
            await asyncio.sleep(wait)
        except Exception as e:
            print(f"[DB] Unexpected error: {e}")
            return


# ================= MAIN WORKER =================
async def worker(
    package_names: List[str],
    sha_map:       Dict[str, str],
) -> Dict[str, int]:

    # Initialise asyncio primitives inside the running event loop
    global _rl_event, _rl_lock
    _rl_event = asyncio.Event()
    _rl_lock  = asyncio.Lock()

    loop         = asyncio.get_running_loop()
    semaphore    = asyncio.Semaphore(CONCURRENCY_LIMIT)
    current_time = datetime.now(timezone.utc)

    counters: Dict[str, int] = {
        "total": 0, "inserted": 0, "updated": 0,
        "skipped": 0, "fetch_failed": 0, "not_found": 0, "validation_errors": 0,
    }

    connector = aiohttp.TCPConnector(
        limit=CONCURRENCY_LIMIT,
        limit_per_host=CONCURRENCY_LIMIT,   # all requests go to pypi.org
        force_close=False,
        enable_cleanup_closed=True,
        keepalive_timeout=60,
        ttl_dns_cache=300,
    )
    session_headers = {
        "User-Agent":  "GeminiSec-Importer/3.0",
        "Accept": "application/json",
        "Cache-Control": "no-cache",
    }

    pbar = tqdm(
        total=len(package_names),
        unit=" pkg",
        desc="Importing PyPI",
        dynamic_ncols=True,
    )

    async with aiohttp.ClientSession(connector=connector,headers=session_headers) as session:
        # Keep only CONCURRENCY_LIMIT tasks in flight.
        # This avoids creating hundreds of thousands of tasks in memory.
        pending: set[asyncio.Task] = set()
        next_idx = 0
        startup_slots_used = 0
        batch_records: List[Dict] = []

        while next_idx < len(package_names) and len(pending) < CONCURRENCY_LIMIT:
            name = package_names[next_idx]
            next_idx += 1
            delay = 0.0
            if startup_slots_used < CONCURRENCY_LIMIT:
                delay = random.uniform(0, STARTUP_STAGGER_MAX)
                startup_slots_used += 1
            pending.add(asyncio.create_task(fetch_one(session, name, semaphore, delay)))

        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )

            for task in done:
                name, status, data = await task
                pbar.update(1)

                if status == "ok" and data is not None:
                    batch_records.append(data)
                elif status == "missing":
                    counters["not_found"] += 1
                else:
                    counters["fetch_failed"] += 1

                # Write to DB whenever we've accumulated a full batch
                if len(batch_records) >= DB_BATCH_SIZE:
                    ops = build_mongo_ops(batch_records, sha_map, current_time, counters)
                    if ops:
                        await db_write(loop, ops)
                    batch_records.clear()

            while next_idx < len(package_names) and len(pending) < CONCURRENCY_LIMIT:
                name = package_names[next_idx]
                next_idx += 1
                pending.add(asyncio.create_task(fetch_one(session, name, semaphore, 0.0)))

            pbar.set_postfix({
                "ins":  counters["inserted"],
                "upd":  counters["updated"],
                "skip": counters["skipped"],
                "404":  counters["not_found"],
                "fail": counters["fetch_failed"],
            })

        # Flush any remaining records
        if batch_records:
            ops = build_mongo_ops(batch_records, sha_map, current_time, counters)
            if ops:
                await db_write(loop, ops)

    pbar.close()

    return counters


# ================= GET PACKAGE LIST =================
def get_all_package_names() -> List[str]:
    import requests
    print("Fetching master package list from pypi.org/simple/ …")
    try:
        r = requests.get(
            SIMPLE_INDEX_URL,
            headers={
                "Accept":     "application/vnd.pypi.simple.v1+json",
                "User-Agent": "GeminiSec-Importer/3.0",
            },
            timeout=60,
        )
        if r.status_code == 200:
            names = [p["name"] for p in r.json().get("projects", [])]
            # PyPI simple index should be unique, but de-dup defensively
            # to avoid same-run insert->skip noise on repeated names.
            unique_names = list(dict.fromkeys(names))
            dup_count = len(names) - len(unique_names)
            if dup_count:
                print(f"Retrieved {len(names):,} package names "
                      f"({dup_count:,} duplicates removed).")
            else:
                print(f"Retrieved {len(unique_names):,} package names.")
            print()
            return unique_names
        print(f"HTTP {r.status_code} from PyPI simple index.")
        return []
    except Exception as e:
        print(f"Network error fetching package list: {e}")
        return []


# ================= SUMMARY =================
def print_summary(label: str, counters: Dict[str, int]):
    print(f"\n{'='*60}")
    print(f" {label}")
    print(f"{'='*60}")
    print(f"  Total processed    : {counters.get('total',             0):>10,}")
    print(f"  Inserted           : {counters.get('inserted',          0):>10,}")
    print(f"  Updated            : {counters.get('updated',           0):>10,}")
    print(f"  Skipped (no change): {counters.get('skipped',           0):>10,}")
    print(f"  Not found (404/410): {counters.get('not_found',         0):>10,}")
    print(f"  Fetch failed       : {counters.get('fetch_failed',      0):>10,}")
    print(f"  Validation errors  : {counters.get('validation_errors', 0):>10,}")
    print(f"{'='*60}\n")


# ================= MAIN =================
if __name__ == "__main__":
    # ================= Full import =================
    all_packages = get_all_package_names()
    if not all_packages:
        print("Could not retrieve package list. Exiting.")
        raise SystemExit(1)

    print("Loading SHA map from database …")
    sha_map = load_existing_sha_map(collection)
    print(f"SHA map loaded ({len(sha_map):,} entries).")
    print(f"Starting import of {len(all_packages):,} packages "
          f"with concurrency={CONCURRENCY_LIMIT} …\n")

    try:
        counters = asyncio.run(worker(all_packages, sha_map))
    except KeyboardInterrupt:
        print("\nStopped by user.")
        raise SystemExit(0)

    print_summary("PYPI IMPORT SUMMARY", counters)