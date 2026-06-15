"""
================================================================================
  Go Module Full Importer  —  script_go_v2.py
================================================================================

HOW GO'S PUBLIC APIs WORK (no hard-coded pages needed)
-------------------------------------------------------

┌─────────────────────────────────────────────────────────────────────────────┐
│  API 1 — Discovery: index.golang.org/index                                  │
│                                                                             │
│  Purpose : Streams EVERY module version ever published, in chronological   │
│            order.  This is the single source of truth for "all packages".  │
│                                                                             │
│  How to paginate (no page numbers needed):                                 │
│    • First call  → https://index.golang.org/index?limit=2000               │
│    • Next call   → ?since=<Timestamp of last row>&limit=2000               │
│    • Keep going until the response has < 2000 rows  (end of feed)          │
│                                                                             │
│  Each row is newline-delimited JSON:                                        │
│    {"Path":"github.com/foo/bar","Version":"v1.2.3",                        │
│     "Timestamp":"2023-01-15T10:22:00.000000Z"}                             │
│                                                                             │
│  Optional params:                                                           │
│    limit=N        max rows per response (default 2000, max 2000)           │
│    include=all    include ALL versions ever served, not just cached ones    │
│                                                                             │
│  Reference: https://proxy.golang.org (section "index.golang.org")          │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  API 2 — Metadata: proxy.golang.org/<module>/@v/<version>.info             │
│                                                                             │
│  Purpose : Returns JSON metadata for one specific module@version.          │
│                                                                             │
│  Example : GET https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.info │
│  Returns :  {"Version":"v1.2.3","Time":"2023-01-15T10:22:00Z"}             │
│                                                                             │
│  Special versions:                                                          │
│    @latest  → resolves to the latest stable version                        │
│    @v/list  → newline-separated list of all known versions (API 3)         │
│                                                                             │
│  Encoding rule (Go-specific):                                               │
│    Uppercase letters in module paths must be escaped as "!<lowercase>".    │
│    e.g.  github.com/BurntSushi  →  github.com/!burnt!sushi                │
│                                                                             │
│  Reference: https://go.dev/ref/mod#goproxy-protocol                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  API 3 — Version list: proxy.golang.org/<module>/@v/list                   │
│                                                                             │
│  Purpose : Returns ALL known versions for a module (one per line).         │
│                                                                             │
│  Example : GET https://proxy.golang.org/github.com/foo/bar/@v/list        │
│  Returns :  v1.0.0\nv1.1.0\nv1.2.3\n                                      │
│                                                                             │
│  When to use:  When you want every version of a module, not just the       │
│                latest one discovered in the index feed.                     │
│                                                                             │
│  Note: This script uses API 1 + API 2 by default (latest-version mode).   │
│        Set FETCH_ALL_VERSIONS=true in .env to also use API 3.              │
└─────────────────────────────────────────────────────────────────────────────┘

PIPELINE OVERVIEW
-----------------
  [index.golang.org feed]  ──page by page (since=<ts>)──►  producer()
                                                               │
                                              queue (Path, Version, action)
                                                               │
                        ┌──────────────────────────────────────┘
                        ▼  (CONCURRENCY_LIMIT workers in parallel)
              fetch_module_info()   →  proxy.golang.org/<m>/@v/<v>.info
                     [optional]     →  proxy.golang.org/<m>/@v/list
                        │
                        ▼
              build_mongo_ops()     →  upsert into MongoDB (batch)
                        │
                        ▼
                    db_write()      →  collection.bulk_write()

RESUMING
--------
  The script saves the last-seen index timestamp to GO_INDEX_CURSOR_FILE.
  On the next run it picks up exactly where it left off — no re-scanning.
  Delete the cursor file to do a full re-import from the beginning.

ENVIRONMENT VARIABLES (.env)
-----------------------------
  MONGO_URI            MongoDB connection string  (required)
  MONGO_DB_NAME        Database name              (required)
  FETCH_ALL_VERSIONS   "true" to store every version, not just latest
                       default: false  (only keeps latest version per module)
  CONCURRENCY_LIMIT    parallel proxy fetches     default: 20
  DB_BATCH_SIZE        upserts per bulk_write     default: 200
  INDEX_PAGE_SIZE      rows per index page        default: 2000 (max)
  INCLUDE_ALL          "true"  →  include=all in index query
                       default: false  (only cached/redistributable modules)
================================================================================
"""

import asyncio
import aiohttp
import pymongo
import functools
import json
import os
import random
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple, Optional, Literal
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Local imports (same as original script)
# ---------------------------------------------------------------------------
from calculator_sha import PackageDocument, compare

# ============================================================
#  CONFIGURATION  (all overridable via .env)
# ============================================================
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("MONGO_URI environment variable is required.")

DB_NAME = os.getenv("MONGO_DB_NAME")
if not DB_NAME:
    raise ValueError("MONGO_DB_NAME environment variable is required.")

COLLECTION_NAME      = "New_go_metadata"
CONCURRENCY_LIMIT    = int(os.getenv("CONCURRENCY_LIMIT", "20"))
DB_BATCH_SIZE        = int(os.getenv("DB_BATCH_SIZE", "200"))
INDEX_PAGE_SIZE      = min(int(os.getenv("INDEX_PAGE_SIZE", "2000")), 2000)   # API max = 2000
FETCH_ALL_VERSIONS   = os.getenv("FETCH_ALL_VERSIONS", "false").lower() == "true"
INCLUDE_ALL          = os.getenv("INCLUDE_ALL", "false").lower() == "true"

# ---- retry / timeouts ----
MAX_RETRIES          = 6
BASE_DELAY           = 1.0
MAX_DELAY            = 60.0
REQUEST_TIMEOUT      = 60
RATE_LIMIT_PAUSE     = 65.0
STARTUP_STAGGER_MAX  = 5.0
INDEX_QUEUE_MAX      = 20_000   # back-pressure: producer waits when full

# ---- file paths ----
SCRIPT_DIR           = os.path.dirname(os.path.abspath(__file__))
FAILED_FILE          = os.path.join(SCRIPT_DIR, "failed_go_packages.txt")
NOT_FOUND_FILE       = os.path.join(SCRIPT_DIR, "not_found_go_packages.txt")
# Cursor file stores the timestamp of the last row we processed.
# Delete this file to restart a full import from the beginning.
CURSOR_FILE          = os.path.join(SCRIPT_DIR, "go_index_cursor.json")

# ============================================================
#  Go API endpoints  (documented at top of file)
# ============================================================
#
#  API 1 — index feed
#    Paginate by advancing `since` to the Timestamp of the last row.
#    No page numbers.  Stop when response has < INDEX_PAGE_SIZE rows.
INDEX_BASE_URL = "https://index.golang.org/index"

#  API 2 — module .info  (metadata for one module@version)
#    Path encoding: uppercase → "!<lowercase>"  (see _escape_go_path)
PROXY_INFO_URL = "https://proxy.golang.org/{}/@v/{}.info"

#  API 3 — version list  (all versions for one module)
#    Used only when FETCH_ALL_VERSIONS=true
PROXY_LIST_URL = "https://proxy.golang.org/{}/@v/list"

# Internal sentinel to signal end-of-queue to consumers
_QUEUE_END = object()


# ============================================================
#  MONGODB SETUP
# ============================================================
print("Connecting to MongoDB...")
_mongo_client = pymongo.MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=30_000,
    connectTimeoutMS=30_000,
    socketTimeoutMS=60_000,
    maxPoolSize=10,
    minPoolSize=2,
    retryWrites=True,
    retryReads=True,
)
db         = _mongo_client[DB_NAME]
collection = db[COLLECTION_NAME]

try:
    existing_indexes = [i.get("name") for i in collection.list_indexes()]
    if "package_name_1" not in existing_indexes:
        print("Creating unique index on 'package_name'...")
        collection.create_index("package_name", unique=True)
        print("Index created.")
    else:
        print("Index already exists.")
except pymongo.errors.OperationFailure as exc:
    if exc.code == 14031:
        print(f"[WARN] Not enough disk space for index: {exc}")
    else:
        raise
print("MongoDB ready.\n")


# ============================================================
#  SHA MAP  (avoid re-fetching unchanged modules)
# ============================================================
def load_sha_map(col) -> Dict[str, str]:
    """Load {package_name: sha} for all existing documents."""
    sha_map: Dict[str, str] = {}
    try:
        for doc in col.find({}, {"package_name": 1, "sha": 1, "_id": 0}):
            if "package_name" in doc and "sha" in doc:
                sha_map[doc["package_name"]] = doc["sha"]
    except Exception as exc:
        print(f"[WARN] Could not load SHA map: {exc}")
    return sha_map


# ============================================================
#  CURSOR  (resume point for index.golang.org pagination)
# ============================================================
def load_cursor() -> str:
    """
    Returns the RFC3339Nano timestamp of the last processed index row.
    Empty string means "start from the very beginning of the index".
    """
    if not os.path.exists(CURSOR_FILE):
        return ""
    try:
        with open(CURSOR_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data.get("since", "")
    except Exception as exc:
        print(f"[WARN] Could not read cursor file: {exc}")
        return ""


def save_cursor(since: str) -> None:
    """Persist the current pagination cursor so the next run can resume."""
    with open(CURSOR_FILE, "w", encoding="utf-8") as fh:
        json.dump({"since": since, "saved_at": datetime.now(timezone.utc).isoformat()}, fh)


def reset_cursor() -> None:
    """Delete cursor file — next run will start from the beginning."""
    if os.path.exists(CURSOR_FILE):
        os.remove(CURSOR_FILE)
        print("Cursor reset. Next run will re-import from the beginning.")


# ============================================================
#  URL BUILDING  (API 1 / 2 / 3)
# ============================================================
def _escape_go_path(value: str) -> str:
    """
    Apply Go's module path encoding:
      uppercase letter  →  '!' + lowercase letter
    Required by proxy.golang.org per the GOPROXY protocol.
    Reference: https://go.dev/ref/mod#module-path-normalization
    """
    out: List[str] = []
    for ch in value:
        if ch.isupper():
            out.append("!" + ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def build_info_url(module_path: str, version: str) -> str:
    """
    API 2: metadata for one module@version.
    https://proxy.golang.org/<escaped-path>/@v/<escaped-version>.info
    """
    ep = _escape_go_path(module_path)
    ev = _escape_go_path(version)
    encoded_path    = urllib.parse.quote(ep, safe="/")
    encoded_version = urllib.parse.quote(ev, safe="")
    return PROXY_INFO_URL.format(encoded_path, encoded_version)


def build_list_url(module_path: str) -> str:
    """
    API 3: all known versions for a module.
    https://proxy.golang.org/<escaped-path>/@v/list
    """
    ep = _escape_go_path(module_path)
    encoded_path = urllib.parse.quote(ep, safe="/")
    return PROXY_LIST_URL.format(encoded_path)


def build_index_url(since: str) -> str:
    """
    API 1: chronological feed of all module versions.
    Pagination is driven purely by the `since` timestamp — no page numbers.

    If `since` is empty → returns the very first page (beginning of history).
    If `since` is set   → returns rows whose Timestamp > since.
    """
    params: Dict[str, str] = {"limit": str(INDEX_PAGE_SIZE)}
    if since:
        params["since"] = since
    if INCLUDE_ALL:
        # include=all  →  show every version ever served (not just cached ones)
        params["include"] = "all"
    return INDEX_BASE_URL + "?" + urllib.parse.urlencode(params)


# ============================================================
#  TIMESTAMP HELPERS
# ============================================================
def _parse_ts(ts: str) -> datetime:
    """Parse RFC3339/RFC3339Nano timestamp → UTC datetime."""
    core = ts.rstrip("Z")
    if "." in core:
        head, frac = core.split(".", 1)
        core = f"{head}.{(frac + '000000')[:6]}"
    return datetime.fromisoformat(core).replace(tzinfo=timezone.utc)


def _advance_ts(ts: str) -> str:
    """Nudge timestamp +1µs to avoid infinite loops on stuck pages."""
    try:
        dt = _parse_ts(ts) + timedelta(microseconds=1)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"
    except Exception:
        return ts


# ============================================================
#  GLOBAL RATE-LIMIT GATE
# ============================================================
_rl_event: Optional[asyncio.Event] = None
_rl_lock:  Optional[asyncio.Lock]  = None


async def _pause_all_workers(who: str) -> None:
    """If a 429 is received, pause ALL workers for RATE_LIMIT_PAUSE seconds."""
    async with _rl_lock:
        if _rl_event.is_set():
            return   # another worker already triggered cooldown
        _rl_event.set()
        print(f"\n[429] '{who}' rate-limited — pausing ALL workers for {RATE_LIMIT_PAUSE:.0f}s ...")
        await asyncio.sleep(RATE_LIMIT_PAUSE)
        _rl_event.clear()
        print("[429] Cooldown done — resuming.\n")


async def _wait_for_cooldown() -> None:
    if _rl_event.is_set():
        await asyncio.sleep(random.uniform(0.1, 3.0))
        while _rl_event.is_set():
            await asyncio.sleep(0.5)


def _backoff(attempt: int) -> float:
    ceiling = min(MAX_DELAY, BASE_DELAY * (2 ** attempt))
    return random.uniform(0.1, ceiling)


# ============================================================
#  FILE HELPERS
# ============================================================
def _clear_tracking_files() -> None:
    for path in (FAILED_FILE, NOT_FOUND_FILE):
        open(path, "w", encoding="utf-8").close()


def _append_line(path: str, value: str) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{value}\n")


# ============================================================
#  API 1: INDEX FEED  (producer coroutine)
# ============================================================
async def producer(
    queue: asyncio.Queue,
    stats: dict,
    stats_lock: asyncio.Lock,
    session: aiohttp.ClientSession,
    start_since: str,
) -> None:
    """
    Streams index.golang.org page by page and pushes (path, version) tuples
    onto the queue for consumers to fetch via proxy.golang.org.

    Pagination works by advancing the `since` timestamp to the last row's
    Timestamp on each page — no page numbers are ever hard-coded.

    The cursor is saved to disk every 20 pages so the next run can resume.
    """
    since       = start_since
    page        = 0
    total_rows  = 0
    # Track the latest version per module path so we only enqueue updates.
    # {module_path: {"version": str, "timestamp": str}}
    latest: Dict[str, Dict[str, str]] = {}

    print(f"Starting index scan (since={'<beginning>' if not since else since}) ...")
    if FETCH_ALL_VERSIONS:
        print("  FETCH_ALL_VERSIONS=true: will also fetch version lists per module.")
    if INCLUDE_ALL:
        print("  INCLUDE_ALL=true: index query includes all historically-served versions.")
    print()

    try:
        while True:
            url  = build_index_url(since)
            body = await _fetch_text(session, url, label="index feed")
            if body is None:
                print("[WARN] Could not fetch index page. Stopping producer.")
                break
            body = body.strip()
            if not body:
                break   # empty response = end of feed

            lines = body.splitlines()
            rows: List[Dict] = []
            for line in lines:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                path      = item.get("Path")
                version   = item.get("Version")
                timestamp = item.get("Timestamp")
                if path and version and timestamp:
                    rows.append({"Path": path, "Version": version, "Timestamp": timestamp})

            page       += 1
            total_rows += len(rows)

            for row in rows:
                path      = row["Path"]
                version   = row["Version"]
                timestamp = row["Timestamp"]

                if FETCH_ALL_VERSIONS:
                    # Enqueue EVERY version (API 3 will be called later for full list)
                    await queue.put(("list", path, None))
                else:
                    # Only keep track of the latest version per module path.
                    # Enqueue if this row is newer than what we have seen so far.
                    prev = latest.get(path)
                    if prev is None or _parse_ts(timestamp) >= _parse_ts(prev["timestamp"]):
                        latest[path] = {"version": version, "timestamp": timestamp}
                        await queue.put(("info", path, version))

            async with stats_lock:
                stats["pages"]      = page
                stats["index_rows"] = total_rows

            if page % 20 == 0:
                print(
                    f"  Index: page {page:,} | rows this run: {total_rows:,} | "
                    f"unique modules seen: {len(latest):,}"
                )
                # Save cursor so the next run can resume from here
                if rows:
                    save_cursor(rows[-1]["Timestamp"])

            # Stop condition: fewer rows than page size means we are at the end
            if len(rows) < INDEX_PAGE_SIZE:
                print(f"\nIndex scan complete: {page:,} pages, {total_rows:,} rows.")
                break

            if not rows:
                print("[WARN] Page had no valid JSON rows. Stopping.")
                break

            # Advance `since` to the last row's timestamp (this IS the pagination)
            last_ts = rows[-1]["Timestamp"]
            if last_ts == since:
                # Safety: if timestamp didn't advance, nudge +1µs
                since = _advance_ts(last_ts)
            else:
                since = last_ts

    finally:
        if since:
            save_cursor(since)
        await queue.put(_QUEUE_END)
        print(f"Producer done. Cursor saved: {since or '<none>'}")


# ============================================================
#  GENERIC HTTP FETCH WITH RETRY
# ============================================================
async def _fetch_text(
    session: aiohttp.ClientSession,
    url: str,
    label: str = "",
) -> Optional[str]:
    """Fetch a URL and return its text body, with retry + rate-limit handling."""
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT * 2)
    for attempt in range(MAX_RETRIES):
        await _wait_for_cooldown()
        try:
            async with session.get(url, timeout=timeout) as resp:
                if resp.status == 200:
                    return await resp.text()
                if resp.status in (404, 410):
                    return None   # caller checks None → missing
                if resp.status == 429:
                    asyncio.create_task(_pause_all_workers(label or url))
                    await asyncio.sleep(_backoff(attempt) * 5)
                    continue
                if resp.status in (500, 502, 503, 504):
                    await asyncio.sleep(_backoff(attempt))
                    continue
                return None
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
    return None


# ============================================================
#  API 2: MODULE .INFO  (fetch metadata for one module@version)
# ============================================================
FetchStatus = Literal["ok", "missing", "failed"]


async def fetch_module_info(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    module_path: str,
    version: str,
    startup_delay: float = 0.0,
) -> Tuple[str, FetchStatus, Optional[Dict]]:
    """
    Calls proxy.golang.org/<module>/@v/<version>.info

    Returns (pkg_key, status, normalized_data_or_None).
    status is 'ok', 'missing' (404/410), or 'failed' (all retries exhausted).
    """
    pkg_key = f"{module_path}@{version}"
    url     = build_info_url(module_path, version)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

    async with semaphore:
        if startup_delay > 0:
            await asyncio.sleep(startup_delay)

        for attempt in range(MAX_RETRIES):
            await _wait_for_cooldown()
            try:
                async with session.get(url, timeout=timeout) as resp:
                    if resp.status == 200:
                        info = await resp.json(content_type=None)
                        normalized = {
                            "name":           module_path,
                            "latest_version": version,
                            "timestamp":      info.get("Time"),
                            "source":         "proxy.golang.org",
                            "raw_info":       info,
                        }
                        return pkg_key, "ok", normalized

                    if resp.status in (404, 410):
                        return pkg_key, "missing", None

                    if resp.status == 429:
                        asyncio.create_task(_pause_all_workers(pkg_key))
                        await asyncio.sleep(_backoff(attempt) * 5)
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


# ============================================================
#  API 3: VERSION LIST  (all versions for one module)
# ============================================================
async def fetch_all_versions(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    module_path: str,
) -> List[Tuple[str, FetchStatus, Optional[Dict]]]:
    """
    Calls proxy.golang.org/<module>/@v/list to get ALL versions,
    then calls fetch_module_info() for each one.

    Only used when FETCH_ALL_VERSIONS=true.
    """
    url  = build_list_url(module_path)
    body = await _fetch_text(session, url, label=f"version-list:{module_path}")
    if body is None:
        return [(f"{module_path}@list", "missing", None)]

    versions = [v.strip() for v in body.splitlines() if v.strip()]
    results: List[Tuple[str, FetchStatus, Optional[Dict]]] = []
    for version in versions:
        result = await fetch_module_info(session, semaphore, module_path, version)
        results.append(result)
    return results


# ============================================================
#  MONGODB  —  build upsert operations
# ============================================================
def build_mongo_ops(
    records: List[Dict],
    sha_map: Dict[str, str],
    current_time: datetime,
    counters: Dict[str, int],
) -> List[pymongo.UpdateOne]:
    ops: List[pymongo.UpdateOne] = []
    for data in records:
        pkg_name = data.get("name")
        if not pkg_name:
            continue

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
        except Exception as exc:
            print(f"[VALIDATION] {pkg_name}: {exc}")
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


# ============================================================
#  MONGODB  —  write with retry
# ============================================================
async def db_write(
    loop: asyncio.AbstractEventLoop,
    ops: List[pymongo.UpdateOne],
) -> None:
    for attempt in range(4):
        try:
            fn = functools.partial(collection.bulk_write, ops, ordered=False)
            await loop.run_in_executor(None, fn)
            return
        except pymongo.errors.BulkWriteError as bwe:
            non_dup = [e for e in bwe.details.get("writeErrors", []) if e.get("code") != 11000]
            if non_dup:
                print(f"[DB] Non-duplicate write errors: {non_dup[:2]}")
            return
        except (
            pymongo.errors.AutoReconnect,
            pymongo.errors.NetworkTimeout,
            pymongo.errors.ConnectionFailure,
        ) as exc:
            wait = 5 * (attempt + 1)
            print(f"[DB] Connection error (attempt {attempt+1}/4), retry in {wait}s: {exc}")
            await asyncio.sleep(wait)
        except Exception as exc:
            print(f"[DB] Unexpected error: {exc}")
            return


# ============================================================
#  MAIN PIPELINE  —  producer + consumers
# ============================================================
async def run_pipeline(sha_map: Dict[str, str]) -> Dict[str, int]:
    """
    Full pipeline:
      1. producer() streams index.golang.org and pushes jobs onto a queue.
      2. consumer loop picks jobs, calls proxy.golang.org, batches DB writes.

    Queue items are tuples:
      ("info", module_path, version)  → call API 2 (single .info fetch)
      ("list", module_path, None)     → call API 3 then API 2 for each version
    """
    global _rl_event, _rl_lock
    _rl_event = asyncio.Event()
    _rl_lock  = asyncio.Lock()

    loop         = asyncio.get_running_loop()
    since        = load_cursor()
    queue: asyncio.Queue = asyncio.Queue(maxsize=INDEX_QUEUE_MAX)
    semaphore    = asyncio.Semaphore(CONCURRENCY_LIMIT)
    stats        = {"pages": 0, "index_rows": 0}
    stats_lock   = asyncio.Lock()
    current_time = datetime.now(timezone.utc)

    counters: Dict[str, int] = {
        "total": 0, "inserted": 0, "updated": 0, "skipped": 0,
        "fetch_failed": 0, "not_found": 0, "validation_errors": 0,
    }
    failed:    List[str] = []
    not_found: List[str] = []

    # Separate connector for proxy calls (keep-alive, DNS cache)
    proxy_connector = aiohttp.TCPConnector(
        limit=CONCURRENCY_LIMIT,
        limit_per_host=CONCURRENCY_LIMIT,
        force_close=False,
        enable_cleanup_closed=True,
        keepalive_timeout=60,
        ttl_dns_cache=300,
    )
    headers = {
        "User-Agent":      "GoModImporter/2.0",
        "Accept":          "application/json",
        "Cache-Control":   "no-cache",
    }

    pbar = tqdm(unit=" mod", desc="Fetching modules", dynamic_ncols=True)

    # ---- start producer (index feed) ----
    async with aiohttp.ClientSession(headers=headers) as idx_session:
        prod_task = asyncio.create_task(
            producer(queue, stats, stats_lock, idx_session, since)
        )

        # ---- consumer loop ----
        async with aiohttp.ClientSession(connector=proxy_connector, headers=headers) as proxy_session:
            pending: set = set()
            batch_records: List[Dict] = []
            startup_slots_used = 0
            producer_done = False

            try:
                while True:
                    # Fill pending tasks up to CONCURRENCY_LIMIT
                    while len(pending) < CONCURRENCY_LIMIT:
                        try:
                            item = queue.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        if item is _QUEUE_END:
                            producer_done = True
                            break

                        action, path, version = item
                        delay = 0.0
                        if startup_slots_used < CONCURRENCY_LIMIT:
                            delay = random.uniform(0, STARTUP_STAGGER_MAX)
                            startup_slots_used += 1

                        if action == "info":
                            # API 2: single .info call
                            task = asyncio.create_task(
                                fetch_module_info(proxy_session, semaphore, path, version, delay)
                            )
                            pending.add(task)
                        elif action == "list":
                            # API 3: version-list call (returns multiple results)
                            task = asyncio.create_task(
                                fetch_all_versions(proxy_session, semaphore, path)
                            )
                            pending.add(task)

                    if not pending:
                        if producer_done and queue.empty():
                            break
                        # Wait for next queue item
                        item = await queue.get()
                        if item is _QUEUE_END:
                            producer_done = True
                            continue
                        action, path, version = item
                        if action == "info":
                            pending.add(asyncio.create_task(
                                fetch_module_info(proxy_session, semaphore, path, version, 0.0)
                            ))
                        elif action == "list":
                            pending.add(asyncio.create_task(
                                fetch_all_versions(proxy_session, semaphore, path)
                            ))
                        continue

                    done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

                    for task in done:
                        result = await task

                        # fetch_all_versions returns a list; fetch_module_info returns a single tuple
                        if isinstance(result, list):
                            results_list = result
                        else:
                            results_list = [result]

                        for pkg_key, status, data in results_list:
                            pbar.update(1)
                            if status == "ok" and data is not None:
                                batch_records.append(data)
                            elif status == "missing":
                                counters["not_found"] += 1
                                not_found.append(pkg_key)
                                _append_line(NOT_FOUND_FILE, pkg_key)
                            else:
                                counters["fetch_failed"] += 1
                                failed.append(pkg_key)
                                _append_line(FAILED_FILE, pkg_key)

                        pbar.set_postfix({
                            "page":  stats.get("pages", 0),
                            "ins":   counters["inserted"],
                            "upd":   counters["updated"],
                            "skip":  counters["skipped"],
                            "404":   counters["not_found"],
                            "fail":  counters["fetch_failed"],
                        })

                        if len(batch_records) >= DB_BATCH_SIZE:
                            ops = build_mongo_ops(batch_records, sha_map, current_time, counters)
                            if ops:
                                await db_write(loop, ops)
                            batch_records.clear()

            finally:
                await prod_task

            # Flush remaining records
            if batch_records:
                ops = build_mongo_ops(batch_records, sha_map, current_time, counters)
                if ops:
                    await db_write(loop, ops)

    pbar.close()

    # Write final failure files
    with open(FAILED_FILE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(failed))
    with open(NOT_FOUND_FILE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(not_found))

    if failed:
        print(f"\n{len(failed):,} modules failed all retries → '{FAILED_FILE}'")
    else:
        print(f"\nNo failures.")
    if not_found:
        print(f"{len(not_found):,} modules returned 404/410 → '{NOT_FOUND_FILE}'")

    return counters


# ============================================================
#  RETRY WORKER  (re-process previously failed modules)
# ============================================================
async def retry_failed(
    retry_list: List[Tuple[str, str]],
    sha_map: Dict[str, str],
) -> Dict[str, int]:
    """
    Re-runs only the modules from FAILED_FILE.
    Useful after a network outage or rate-limit storm.
    """
    global _rl_event, _rl_lock
    _rl_event = asyncio.Event()
    _rl_lock  = asyncio.Lock()

    loop         = asyncio.get_running_loop()
    semaphore    = asyncio.Semaphore(CONCURRENCY_LIMIT)
    current_time = datetime.now(timezone.utc)

    counters: Dict[str, int] = {
        "total": 0, "inserted": 0, "updated": 0, "skipped": 0,
        "fetch_failed": 0, "not_found": 0, "validation_errors": 0,
    }
    failed: List[str]    = []
    not_found: List[str] = []

    connector = aiohttp.TCPConnector(limit=CONCURRENCY_LIMIT, limit_per_host=CONCURRENCY_LIMIT)
    headers   = {"User-Agent": "GoModImporter/2.0", "Accept": "application/json"}

    pbar = tqdm(total=len(retry_list), unit=" mod", desc="Retrying failed", dynamic_ncols=True)

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        pending: set   = set()
        next_idx       = 0
        batch_records: List[Dict] = []

        # Seed initial tasks
        while next_idx < len(retry_list) and len(pending) < CONCURRENCY_LIMIT:
            path, version = retry_list[next_idx]
            next_idx += 1
            delay = random.uniform(0, STARTUP_STAGGER_MAX) if next_idx <= CONCURRENCY_LIMIT else 0.0
            pending.add(asyncio.create_task(
                fetch_module_info(session, semaphore, path, version, delay)
            ))

        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                pkg_key, status, data = await task
                pbar.update(1)
                if status == "ok" and data is not None:
                    batch_records.append(data)
                elif status == "missing":
                    counters["not_found"] += 1
                    not_found.append(pkg_key)
                    _append_line(NOT_FOUND_FILE, pkg_key)
                else:
                    counters["fetch_failed"] += 1
                    failed.append(pkg_key)
                    _append_line(FAILED_FILE, pkg_key)

                if len(batch_records) >= DB_BATCH_SIZE:
                    ops = build_mongo_ops(batch_records, sha_map, current_time, counters)
                    if ops:
                        await db_write(loop, ops)
                    batch_records.clear()

            # Refill pending
            while next_idx < len(retry_list) and len(pending) < CONCURRENCY_LIMIT:
                path, version = retry_list[next_idx]
                next_idx += 1
                pending.add(asyncio.create_task(
                    fetch_module_info(session, semaphore, path, version, 0.0)
                ))

        if batch_records:
            ops = build_mongo_ops(batch_records, sha_map, current_time, counters)
            if ops:
                await db_write(loop, ops)

    pbar.close()
    with open(FAILED_FILE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(failed))
    with open(NOT_FOUND_FILE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(not_found))
    return counters


# ============================================================
#  SUMMARY PRINTER
# ============================================================
def print_summary(label: str, counters: Dict[str, int]) -> None:
    print(f"\n{'='*62}")
    print(f"  {label}")
    print(f"{'='*62}")
    print(f"  Total processed    : {counters.get('total',             0):>12,}")
    print(f"  Inserted           : {counters.get('inserted',          0):>12,}")
    print(f"  Updated            : {counters.get('updated',           0):>12,}")
    print(f"  Skipped (no change): {counters.get('skipped',           0):>12,}")
    print(f"  Not found (404/410): {counters.get('not_found',         0):>12,}")
    print(f"  Fetch failed       : {counters.get('fetch_failed',      0):>12,}")
    print(f"  Validation errors  : {counters.get('validation_errors', 0):>12,}")
    print(f"{'='*62}\n")


# ============================================================
#  ENTRY POINT
# ============================================================
if __name__ == "__main__":
    _clear_tracking_files()

    print("=" * 62)
    print("  Go Module Full Importer")
    print("=" * 62)
    print(f"  Mode       : {'all versions per module' if FETCH_ALL_VERSIONS else 'latest version per module'}")
    print(f"  Index scope: {'all ever served (include=all)' if INCLUDE_ALL else 'cached/redistributable only'}")
    print(f"  Concurrency: {CONCURRENCY_LIMIT}")
    print(f"  Batch size : {DB_BATCH_SIZE}")
    cursor_ts = load_cursor()
    print(f"  Resume from: {cursor_ts or '<beginning of index>'}")
    print("=" * 62 + "\n")

    # ---- Check for previously failed modules and offer to retry ----
    if os.path.exists(FAILED_FILE):
        with open(FAILED_FILE, encoding="utf-8") as fh:
            retry_list_raw = [ln.strip() for ln in fh if ln.strip()]
        if retry_list_raw:
            print(f"Found {len(retry_list_raw):,} previously failed modules in '{FAILED_FILE}'.")
            choice = input("Options: [r]etry failed only / [f]ull scan / [q]uit: ").strip().lower()
            if choice == "q":
                raise SystemExit(0)
            if choice == "r":
                retry_pkgs: List[Tuple[str, str]] = []
                for entry in retry_list_raw:
                    if "@" in entry:
                        path, version = entry.rsplit("@", 1)
                        retry_pkgs.append((path, version))
                print(f"\nLoading SHA map ...")
                sha_map = load_sha_map(collection)
                print(f"SHA map: {len(sha_map):,} entries.\n")
                try:
                    counters = asyncio.run(retry_failed(retry_pkgs, sha_map))
                except KeyboardInterrupt:
                    raise SystemExit(0)
                print_summary("RETRY SUMMARY", counters)
                raise SystemExit(0)

    # ---- Option to reset cursor (full re-import) ----
    if cursor_ts:
        choice = input(
            "Cursor found — resume from last position? [Y/n]: "
        ).strip().lower()
        if choice == "n":
            reset_cursor()

    print(f"\nLoading SHA map from MongoDB ...")
    sha_map = load_sha_map(collection)
    print(f"SHA map: {len(sha_map):,} entries.\n")

    try:
        counters = asyncio.run(run_pipeline(sha_map))
    except KeyboardInterrupt:
        print("\nStopped by user. Cursor was saved — next run will resume.")
        raise SystemExit(0)

    print_summary("GO IMPORT SUMMARY", counters)
