import asyncio
import aiohttp
import pymongo
import functools
import json
import os
import random
import urllib.parse
from tqdm import tqdm
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple, Optional, Literal, Set
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
COLLECTION_NAME = "Updated_go_metadata"

# ================= Concurrency =================
CONCURRENCY_LIMIT  = 10   
PKGDEV_CONCURRENCY = 5    

# Flush to DB every N successful records
DB_BATCH_SIZE = 10

# ================= Retry / Timeout =================
MAX_RETRIES     = 6
BASE_DELAY      = 1.0
MAX_DELAY       = 60.0
REQUEST_TIMEOUT = 60
PKGDEV_TIMEOUT  = 30

# ================= Rate-limit cooldown =================
RATE_LIMIT_PAUSE = 65.0
PKGDEV_RL_PAUSE  = 60.0

# ================= Startup stagger =================
STARTUP_STAGGER_MAX = 5.0

# ================= Go endpoints =================
INDEX_URL        = "https://index.golang.org/index"  #all packages
PROXY_INFO_URL   = "https://proxy.golang.org/{}/@v/{}.info"  #info for specific version
DEPSDEV_URL      = "https://api.deps.dev/v3alpha/systems/go/packages/{}/versions/{}" #use for license 
PROXY_LATEST_URL = "https://proxy.golang.org/{}/@latest"  #for latest version
INDEX_PAGE_SIZE  = 2000
INDEX_IMPORT_QUEUE_MAX = 10_000

_QUEUE_END = object()

# Global graceful-shutdown flag
_shutdown = False


def new_run_counters() -> Dict[str, int]:
    return {
        "total": 0,
        "inserted": 0,
        "updated": 0,
        "skipped": 0,
        "fetch_failed": 0,
        "not_found": 0,
        "validation_errors": 0,
    }


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
    idx_names = [i.get("name") for i in collection.list_indexes()]
    if "package_name_1" not in idx_names:
        print("Creating unique index on 'package_name'...")
        collection.create_index("package_name", unique=True)
        print("Index created.")
    else:
        print("Index already exists.")
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
    ceiling = min(cap, base * (2 ** attempt))
    return random.uniform(0.1, ceiling)


# ================= GLOBAL RATE-LIMIT GATES =================
_rl_event:     Optional[asyncio.Event] = None
_rl_lock:      Optional[asyncio.Lock]  = None
_pkgdev_event: Optional[asyncio.Event] = None
_pkgdev_lock:  Optional[asyncio.Lock]  = None


async def _pause_all_proxy_workers(who: str):
    async with _rl_lock:
        if _rl_event.is_set():
            return
        _rl_event.set()
        print(f"\n[PROXY 429] '{who}' — pausing {RATE_LIMIT_PAUSE:.0f}s ...")
        await asyncio.sleep(RATE_LIMIT_PAUSE)
        _rl_event.clear()
        print("[PROXY 429] Cooldown done — resuming.\n")


async def _pause_all_pkgdev_workers(who: str):
    async with _pkgdev_lock:
        if _pkgdev_event.is_set():
            return
        _pkgdev_event.set()
        print(f"\n[DEPSDEV 429] '{who}' — pausing {PKGDEV_RL_PAUSE:.0f}s ...")
        await asyncio.sleep(PKGDEV_RL_PAUSE)
        _pkgdev_event.clear()
        print("[DEPSDEV 429] Cooldown done — resuming.\n")


async def _wait_for_proxy_cooldown():
    if _rl_event.is_set():
        await asyncio.sleep(random.uniform(0.1, 3.0))
        while _rl_event.is_set():
            await asyncio.sleep(0.5)


async def _wait_for_pkgdev_cooldown():
    if _pkgdev_event.is_set():
        await asyncio.sleep(random.uniform(0.1, 3.0))
        while _pkgdev_event.is_set():
            await asyncio.sleep(0.5)


def _escape_go_path_component(value: str) -> str:
    out: List[str] = []
    for ch in value:
        if ch.isupper():
            out.append("!" + ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def _build_proxy_info_url(path: str, version: str) -> str:
    escaped_path    = _escape_go_path_component(path)
    escaped_version = _escape_go_path_component(version)
    encoded_path    = urllib.parse.quote(escaped_path, safe="/")
    encoded_version = urllib.parse.quote(escaped_version, safe="")
    return PROXY_INFO_URL.format(encoded_path, encoded_version)


def _build_depsdev_url(module_path: str, version: str) -> str:
    encoded_path    = urllib.parse.quote(module_path, safe="")
    encoded_version = urllib.parse.quote(version, safe="")
    return DEPSDEV_URL.format(encoded_path, encoded_version)

# ====== LATEST VERSION FETCHER ======

PROXY_LATEST_URL = "https://proxy.golang.org/{}/@latest"

latest_cache: Dict[str, str] = {}

async def fetch_latest_version(session, package_name: str) -> Optional[str]:
    # Cache hit
    if package_name in latest_cache:
        return latest_cache[package_name]

    url = PROXY_LATEST_URL.format(
        urllib.parse.quote(_escape_go_path_component(package_name), safe="/")
    )

    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

    for attempt in range(MAX_RETRIES):
        try:
            async with session.get(url, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    latest = data.get("Version")
                    if latest:
                        latest_cache[package_name] = latest
                    return latest

                if resp.status in (404, 410):
                    return None

                if resp.status in (429, 500, 502, 503, 504):
                    await asyncio.sleep(_backoff(attempt))
                    continue

                return None

        except Exception:
            await asyncio.sleep(_backoff(attempt))

    return None

# ====== deps.dev LICENSE FETCHER ======

def _parse_depsdev_response(data: Dict) -> Dict:
    """
    Extract license from deps.dev version response.

    Response shape:
    {
      "versionKey": { "system": "GO", "name": "...", "version": "..." },
      "licenses": ["MIT"],
      ...
    }
    """
    licenses = data.get("licenses", [])
    if licenses:
        return {"license": ", ".join(licenses)}
    return {}


async def fetch_pkgdev(
    session:     aiohttp.ClientSession,
    module_path: str,
    version:     str,
    semaphore:   asyncio.Semaphore,
) -> Dict:
   
    url     = _build_depsdev_url(module_path, version)
    timeout = aiohttp.ClientTimeout(total=PKGDEV_TIMEOUT)

    async with semaphore:
        for attempt in range(MAX_RETRIES):
            await _wait_for_pkgdev_cooldown()
            try:
                async with session.get(url, timeout=timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        return _parse_depsdev_response(data)
                    if resp.status in (404, 410):
                        return {}
                    if resp.status == 429:
                        asyncio.create_task(_pause_all_pkgdev_workers(module_path))
                        await asyncio.sleep(_backoff(attempt, base=BASE_DELAY * 5))
                        continue
                    if resp.status in (500, 502, 503, 504):
                        await asyncio.sleep(_backoff(attempt))
                        continue
                    return {}
            except Exception:
                await asyncio.sleep(_backoff(attempt))
    return {}


# ====== FETCH ONE MODULE ======

FetchStatus = Literal["ok", "missing", "failed"]


async def fetch_one(
    session:        aiohttp.ClientSession,
    package_name:   str,
    version:        str,
    proxy_sem:      asyncio.Semaphore,
    pkgdev_session: aiohttp.ClientSession,
    pkgdev_sem:     asyncio.Semaphore,
    startup_delay:  float = 0.0,
) -> Tuple[str, FetchStatus, Optional[Dict]]:

    pkg_key = f"{package_name}@{version}"
    url     = _build_proxy_info_url(package_name, version)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

    async with proxy_sem:
        if startup_delay > 0:
            await asyncio.sleep(startup_delay)

        for attempt in range(MAX_RETRIES):
            await _wait_for_proxy_cooldown()
            try:
                async with session.get(url, timeout=timeout) as resp:
                    if resp.status == 200:
                        info = await resp.json(content_type=None)

                        resolved_version = info.get("Version", version)

                        # Fetch real latest version ONLY when needed (optimization)
                        if version.startswith("v0.0.0-") or True:
                            latest_version = await fetch_latest_version(session, package_name)
                        else:
                            latest_version = resolved_version

                        normalized: Dict = {
                            "name": package_name,
                            "version": version,
                            # "resolved_version": resolved_version,
                            "latest_version": latest_version or resolved_version,
                            "timestamp": info.get("Time"),
                            "source": "proxy.golang.org",
                            "raw_info": info,
                        }

                        # Use version from proxy response (canonical form)
                        resolved_version = info.get("Version", version)

                        pkgdev_data = await fetch_pkgdev(
                            pkgdev_session, package_name, resolved_version, pkgdev_sem
                        )
                        if pkgdev_data.get("license"):
                            normalized["license"] = pkgdev_data["license"]

                        return pkg_key, "ok", normalized

                    if resp.status in (404, 410):
                        return pkg_key, "missing", None
                    if resp.status == 429:
                        asyncio.create_task(_pause_all_proxy_workers(pkg_key))
                        await asyncio.sleep(_backoff(attempt, base=BASE_DELAY * 5))
                        continue
                    if resp.status in (500, 502, 503, 504):
                        await asyncio.sleep(_backoff(attempt))
                        continue
                    return pkg_key, "failed", None

            except (
                asyncio.TimeoutError,
                aiohttp.ServerDisconnectedError,
                aiohttp.ClientConnectorError,
                aiohttp.ClientResponseError,
                aiohttp.ClientPayloadError,
            ):
                await asyncio.sleep(_backoff(attempt))
            except Exception:
                await asyncio.sleep(_backoff(attempt))

        return pkg_key, "failed", None


# ====== BUILD MONGO OPERATIONS ======

def build_mongo_ops(
    records:      List[Dict],
    sha_map:      Dict[str, str],
    current_time: datetime,
    counters:     Dict[str, int],
) -> List[pymongo.UpdateOne]:
    ops: List[pymongo.UpdateOne] = []

    for data in records:
        pkg_name = data.get("name")
        if not pkg_name:
            continue

        existing_sha = sha_map.get(pkg_name)

        new_sha, enriched_data, action = compare(data, existing_sha, pkg_name, current_time)

        sha_map[pkg_name] = new_sha

        counters["total"] += 1
        if action == "insert":
            counters["inserted"] += 1
        elif action == "update":
            counters["updated"] += 1
        elif action == "skip":
            counters["skipped"] += 1
            continue

        doc = {
            "package_name": pkg_name,
            "sha":          new_sha,
            "object":       data,
        }
        if action == "update":
            doc["updated_time"] = current_time

        try:
            validated = PackageDocument(**doc).model_dump(exclude_none=True)
        except Exception as e:
            print(f"[VALIDATION] {pkg_name}: {e}")
            counters["validation_errors"] += 1
            continue

        ops.append(
            pymongo.UpdateOne(
                {"package_name": pkg_name},
                {"$set": validated},
                upsert=True,
            )
        )

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
            non_dup = [
                e for e in bwe.details.get("writeErrors", []) if e.get("code") != 11000
            ]
            if non_dup:
                print(f"[DB] Non-duplicate write errors: {non_dup[:2]}")
            return
        except (
            pymongo.errors.AutoReconnect,
            pymongo.errors.NetworkTimeout,
            pymongo.errors.ConnectionFailure,
        ) as e:
            wait = 5 * (attempt + 1)
            print(f"[DB] Connection error (attempt {attempt+1}/4), retry in {wait}s: {e}")
            await asyncio.sleep(wait)
        except Exception as e:
            print(f"[DB] Unexpected error: {e}")
            return


# ====== FLUSH HELPER ======

async def _flush_batch(
    batch_records: List[Dict],
    sha_map:       Dict[str, str],
    current_time:  datetime,
    counters:      Dict[str, int],
    loop:          asyncio.AbstractEventLoop,
):
    if not batch_records:
        return
    ops = build_mongo_ops(batch_records, sha_map, current_time, counters)
    if ops:
        await db_write(loop, ops)
    batch_records.clear()


# ====== Go index helpers ======

def _parse_go_ts(ts: str) -> datetime:
    core = ts.rstrip("Z")
    if "." in core:
        head, frac = core.split(".", 1)
        core = f"{head}.{(frac + '000000')[:6]}"
    return datetime.fromisoformat(core).replace(tzinfo=timezone.utc)


def _format_go_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"


def _advance_since(last_timestamp: str) -> str:
    try:
        dt  = _parse_go_ts(last_timestamp)
        dt += timedelta(microseconds=1)
        return _format_go_ts(dt)
    except Exception:
        return last_timestamp


def _row_key(item: Dict[str, str]) -> Tuple[datetime, str, str]:
    return (_parse_go_ts(item["Timestamp"]), item["Path"], item["Version"])


def _merge_latest_and_enqueue(
    latest: Dict[str, Dict[str, str]], path: str, version: str, timestamp: str,
) -> bool:
    prev = latest.get(path)
    if prev is None:
        latest[path] = {"version": version, "timestamp": timestamp}
        return True
    try:
        if _parse_go_ts(timestamp) >= _parse_go_ts(prev["timestamp"]):
            latest[path] = {"version": version, "timestamp": timestamp}
            return True
    except Exception:
        latest[path] = {"version": version, "timestamp": timestamp}
        return True
    return False


async def _fetch_index_body(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    timeout = aiohttp.ClientTimeout(total=120)
    for attempt in range(6):
        try:
            async with session.get(url, timeout=timeout) as resp:
                if resp.status == 200:
                    return (await resp.text()).strip()
                if resp.status in (429, 500, 502, 503, 504):
                    delay = _backoff(attempt)
                    print(
                        f"[WARN] HTTP {resp.status} index "
                        f"(attempt {attempt+1}/6); retry {delay:.1f}s"
                    )
                    await asyncio.sleep(delay)
                    continue
                print(f"[WARN] HTTP {resp.status} from Go index. Stopping.")
                return None
        except (
            asyncio.TimeoutError,
            aiohttp.ServerDisconnectedError,
            aiohttp.ClientConnectorError,
            aiohttp.ClientPayloadError,
        ):
            await asyncio.sleep(_backoff(attempt))
        except Exception as e:
            print(f"[WARN] Index network error (attempt {attempt+1}/6): {e}")
            await asyncio.sleep(_backoff(attempt))
    return None


# ====== MAIN PARALLEL IMPORT ======

async def scan_and_import_parallel(
    sha_map:  Dict[str, str],
    counters: Dict[str, int],
) -> Dict[str, int]:
    global _rl_event, _rl_lock, _pkgdev_event, _pkgdev_lock, _shutdown

    _shutdown = False
    _rl_event     = asyncio.Event()
    _rl_lock      = asyncio.Lock()
    _pkgdev_event = asyncio.Event()
    _pkgdev_lock  = asyncio.Lock()

    loop         = asyncio.get_running_loop()
    latest: Dict[str, Dict[str, str]] = {}
    stats        = {"page": 0, "index_rows": 0, "enqueued": 0}
    stats_lock   = asyncio.Lock()

    queue: asyncio.Queue = asyncio.Queue(maxsize=INDEX_IMPORT_QUEUE_MAX)
    proxy_sem    = asyncio.Semaphore(CONCURRENCY_LIMIT)
    pkgdev_sem   = asyncio.Semaphore(PKGDEV_CONCURRENCY)
    current_time = datetime.now(timezone.utc)

    common_headers = {
        "User-Agent": "GeminiSec-Importer/3.0",
        "Accept": "application/json",
        "Cache-Control": "no-cache",
    }

    proxy_connector = aiohttp.TCPConnector(
        limit=CONCURRENCY_LIMIT, limit_per_host=CONCURRENCY_LIMIT,
        force_close=False, enable_cleanup_closed=True,
        keepalive_timeout=60, ttl_dns_cache=300,
    )
    pkgdev_connector = aiohttp.TCPConnector(
        limit=PKGDEV_CONCURRENCY, limit_per_host=PKGDEV_CONCURRENCY,
        force_close=False, enable_cleanup_closed=True,
        keepalive_timeout=60, ttl_dns_cache=300,
    )

    pbar = tqdm(unit=" mod", desc="Importing", dynamic_ncols=True)

    # ====== Producer ======
    async def producer():
        since            = ""
        page             = 0
        total_index_rows = 0
        prev_high_key: Optional[Tuple[datetime, str, str]] = None
        print(f"Streaming Go index (queue max {INDEX_IMPORT_QUEUE_MAX:,}) …")
        try:
            async with aiohttp.ClientSession(headers=common_headers) as idx_session:
                while not _shutdown:
                    url = (
                        f"{INDEX_URL}?since={urllib.parse.quote(since, safe='')}&limit={INDEX_PAGE_SIZE}"
                        if since else f"{INDEX_URL}?limit={INDEX_PAGE_SIZE}"
                    )
                    body = await _fetch_index_body(idx_session, url)
                    if not body:
                        break

                    lines = body.splitlines()
                    if not lines:
                        break

                    page += 1

                    unfiltered: List[Dict[str, str]] = []
                    for line in lines:
                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        p = item.get("Path")
                        v = item.get("Version")
                        t = item.get("Timestamp")
                        if p and v and t:
                            unfiltered.append({"Path": p, "Version": v, "Timestamp": t})

                    parsed_rows = (
                        [r for r in unfiltered if _row_key(r) > prev_high_key]
                        if prev_high_key is not None else list(unfiltered)
                    )

                    enq_this_page = 0
                    for row in parsed_rows:
                        if _merge_latest_and_enqueue(
                            latest, row["Path"], row["Version"], row["Timestamp"]
                        ):
                            await queue.put((row["Path"], row["Version"]))
                            enq_this_page += 1

                    total_index_rows += len(parsed_rows)
                    if parsed_rows:
                        prev_high_key = _row_key(parsed_rows[-1])

                    async with stats_lock:
                        stats["page"]       = page
                        stats["index_rows"] = total_index_rows
                        stats["enqueued"]  += enq_this_page

                    if page % 20 == 0:
                        async with stats_lock:
                            eq = stats["enqueued"]
                        print(
                            f"Index progress: {page:,} pages | rows: {total_index_rows:,} | "
                            f"unique: {len(latest):,} | enqueued: {eq:,}"
                        )

                    if len(lines) < INDEX_PAGE_SIZE:
                        break
                    if not unfiltered:
                        print("[WARN] Full page, no valid JSON; stopping.")
                        break

                    last_ts    = unfiltered[-1]["Timestamp"]
                    next_since = last_ts if parsed_rows else _advance_since(last_ts)
                    since = next_since
        except asyncio.CancelledError:
            pass
        finally:
            async with stats_lock:
                eq = stats["enqueued"]
            print(
                f"Index done: {page:,} pages | rows: {total_index_rows:,} | "
                f"unique: {len(latest):,} | enqueued: {eq:,}\n"
            )
            cur = asyncio.current_task()
            if cur is not None and cur.cancelling():
                return
            try:
                await queue.put(_QUEUE_END)
            except (asyncio.CancelledError, RuntimeError):
                pass

    prod_task = asyncio.create_task(producer())

    try:
        async with (
            aiohttp.ClientSession(connector=proxy_connector,  headers=common_headers) as proxy_session,
            aiohttp.ClientSession(connector=pkgdev_connector, headers=common_headers) as pkgdev_session,
        ):
            pending: set[asyncio.Task] = set()
            startup_slots_used  = 0
            batch_records: List[Dict] = []
            producer_closed     = False
            dispatched: Set[str] = set()

            try:
                while not _shutdown:
                    while len(pending) < CONCURRENCY_LIMIT:
                        try:
                            item = queue.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        if item is _QUEUE_END:
                            producer_closed = True
                            break
                        name, version = item

                        if name in dispatched:
                            continue
                        dispatched.add(name)

                        delay = (
                            random.uniform(0, STARTUP_STAGGER_MAX)
                            if startup_slots_used < CONCURRENCY_LIMIT else 0.0
                        )
                        if startup_slots_used < CONCURRENCY_LIMIT:
                            startup_slots_used += 1
                        pending.add(asyncio.create_task(
                            fetch_one(
                                proxy_session, name, version, proxy_sem,
                                pkgdev_session, pkgdev_sem, delay,
                            )
                        ))

                    if not pending:
                        if producer_closed and queue.empty():
                            break
                        item = await queue.get()
                        if item is _QUEUE_END:
                            producer_closed = True
                            continue
                        name, version = item

                        if name in dispatched:
                            continue
                        dispatched.add(name)

                        pending.add(asyncio.create_task(
                            fetch_one(
                                proxy_session, name, version, proxy_sem,
                                pkgdev_session, pkgdev_sem, 0.0,
                            )
                        ))
                        continue

                    done, pending = await asyncio.wait(
                        pending, return_when=asyncio.FIRST_COMPLETED
                    )

                    async with stats_lock:
                        sp  = stats.get("page", 0)
                        sir = stats.get("index_rows", 0)
                        um  = len(latest)

                    for task in done:
                        _, status, data = await task
                        pbar.update(1)
                        pbar.set_postfix({
                            "page": sp, "idx": sir, "uniq": um,
                            "ins":  counters["inserted"],
                            "upd":  counters["updated"],
                            "skip": counters["skipped"],
                            "404":  counters["not_found"],
                            "fail": counters["fetch_failed"],
                            "verr": counters["validation_errors"],
                        })

                        if status == "ok" and data is not None:
                            batch_records.append(data)
                        elif status == "missing":
                            counters["not_found"] += 1
                        else:
                            counters["fetch_failed"] += 1

                        if len(batch_records) >= DB_BATCH_SIZE:
                            await _flush_batch(
                                batch_records, sha_map, current_time, counters, loop
                            )

            except asyncio.CancelledError:
                _shutdown = True
                raise
            finally:
                for t in pending:
                    t.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                if not prod_task.done():
                    prod_task.cancel()
                try:
                    await prod_task
                except asyncio.CancelledError:
                    pass
                await _flush_batch(batch_records, sha_map, current_time, counters, loop)
    finally:
        pbar.close()

    return counters


# ====== WORKER (retry mode) ======

async def worker(
    packages: List[Tuple[str, str]],
    sha_map:  Dict[str, str],
) -> Dict[str, int]:
    global _rl_event, _rl_lock, _pkgdev_event, _pkgdev_lock

    _rl_event     = asyncio.Event()
    _rl_lock      = asyncio.Lock()
    _pkgdev_event = asyncio.Event()
    _pkgdev_lock  = asyncio.Lock()

    loop         = asyncio.get_running_loop()
    proxy_sem    = asyncio.Semaphore(CONCURRENCY_LIMIT)
    pkgdev_sem   = asyncio.Semaphore(PKGDEV_CONCURRENCY)
    current_time = datetime.now(timezone.utc)

    counters: Dict[str, int] = {
        "total": 0, "inserted": 0, "updated": 0, "skipped": 0,
        "fetch_failed": 0, "not_found": 0, "validation_errors": 0,
    }

    common_headers = {
        "User-Agent": "GeminiSec-Importer/3.0",
        "Accept": "application/json",
        "Cache-Control": "no-cache",
    }

    proxy_connector = aiohttp.TCPConnector(
        limit=CONCURRENCY_LIMIT, limit_per_host=CONCURRENCY_LIMIT,
        force_close=False, enable_cleanup_closed=True,
        keepalive_timeout=60, ttl_dns_cache=300,
    )
    pkgdev_connector = aiohttp.TCPConnector(
        limit=PKGDEV_CONCURRENCY, limit_per_host=PKGDEV_CONCURRENCY,
        force_close=False, enable_cleanup_closed=True,
        keepalive_timeout=60, ttl_dns_cache=300,
    )

    pbar = tqdm(
        total=len(packages), unit=" mod",
        desc="Retrying", dynamic_ncols=True,
    )

    async with (
        aiohttp.ClientSession(connector=proxy_connector,  headers=common_headers) as proxy_session,
        aiohttp.ClientSession(connector=pkgdev_connector, headers=common_headers) as pkgdev_session,
    ):
        pending: set[asyncio.Task] = set()
        next_idx           = 0
        startup_slots_used = 0
        batch_records: List[Dict] = []

        while next_idx < len(packages) and len(pending) < CONCURRENCY_LIMIT:
            name, version = packages[next_idx]; next_idx += 1
            delay = (
                random.uniform(0, STARTUP_STAGGER_MAX)
                if startup_slots_used < CONCURRENCY_LIMIT else 0.0
            )
            if startup_slots_used < CONCURRENCY_LIMIT:
                startup_slots_used += 1
            pending.add(asyncio.create_task(
                fetch_one(
                    proxy_session, name, version, proxy_sem,
                    pkgdev_session, pkgdev_sem, delay,
                )
            ))

        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    _, status, data = await task
                    pbar.update(1)

                    if status == "ok" and data is not None:
                        batch_records.append(data)
                    elif status == "missing":
                        counters["not_found"] += 1
                    else:
                        counters["fetch_failed"] += 1

                    if len(batch_records) >= DB_BATCH_SIZE:
                        await _flush_batch(
                            batch_records, sha_map, current_time, counters, loop
                        )

                while next_idx < len(packages) and len(pending) < CONCURRENCY_LIMIT:
                    name, version = packages[next_idx]; next_idx += 1
                    pending.add(asyncio.create_task(
                        fetch_one(
                            proxy_session, name, version, proxy_sem,
                            pkgdev_session, pkgdev_sem, 0.0,
                        )
                    ))

                pbar.set_postfix({
                    "ins":  counters["inserted"],
                    "upd":  counters["updated"],
                    "skip": counters["skipped"],
                    "404":  counters["not_found"],
                    "fail": counters["fetch_failed"],
                    "verr": counters["validation_errors"],
                })
        finally:
            await _flush_batch(batch_records, sha_map, current_time, counters, loop)

    pbar.close()
    return counters


# ================= SUMMARY =================
def print_summary(label: str, counters: Dict[str, int]):
    print(f"\nIMPORT SUMMARY: {label}")
    print(f"{'='*60}")
    print(f"  Total processed    : {counters.get('total', 0):>10,}")
    print(f"  Inserted           : {counters.get('inserted',0):>10,}")
    print(f"  Updated            : {counters.get('updated',0):>10,}")
    print(f"  Skipped (no change): {counters.get('skipped',0):>10,}")
    print(f"  Not found (404/410): {counters.get('not_found', 0):>10,}")
    print(f"  Fetch failed       : {counters.get('fetch_failed',0):>10,}")
    print(f"  Validation errors  : {counters.get('validation_errors',0):>10,}")
    print(f"{'='*60}\n")


# ================= MAIN =================
if __name__ == "__main__":
    print("Loading SHA map from database …")
    sha_map = load_existing_sha_map(collection)
    print(f"SHA map loaded ({len(sha_map):,} entries).\n")

    counters = new_run_counters()
    try:
        asyncio.run(scan_and_import_parallel(sha_map, counters))
    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        print_summary("GO IMPORT", counters)