from __future__ import annotations
import argparse
import asyncio
import functools
import hashlib
import json
import os
import random
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

import aiohttp
import pymongo
from dotenv import load_dotenv
from pymongo.errors import ServerSelectionTimeoutError
from tqdm import tqdm

load_dotenv()

# ================= CONFIGURATION =================
MONGO_URI = os.getenv("MONGO_URI") or os.getenv("intel_repo_url")
if not MONGO_URI:
    raise ValueError("MONGO_URI (or intel_repo_url) environment variable is required.")
DB_NAME = os.getenv("MONGO_DB_NAME") 
if not DB_NAME:
    raise ValueError("MONGO_DB_NAME environment variable is required.")

COLLECTION_ENDOFLIFE = "eol_endoflife_products"
COLLECTION_TERRAFORM = "eol_terraform_providers"

EOL_API_BASE = "https://endoflife.date/api/v1/products"
TF_REGISTRY_API_BASE = "https://registry.terraform.io/v1/providers"

EOL_PRODUCT_SLUGS: Dict[str, str] = {
    "java": "oracle-jdk",
    "go": "go",
    "gradle_wrapper": "gradle",
    "maven_wrapper": "apache-maven",
    "npm": "nodejs",
    "python": "python",
    "terraform": "terraform",
}

# Warm-cache Terraform providers (hashicorp/* + common third-party)
_DEFAULT_TF_SOURCES: Tuple[str, ...] = (
    "hashicorp/aws",
    "hashicorp/google",
    "hashicorp/google-beta",
    "hashicorp/azurerm",
    "hashicorp/azuread",
    "hashicorp/azurestack",
    "hashicorp/kubernetes",
    "hashicorp/helm",
    "hashicorp/vault",
    "hashicorp/consul",
    "hashicorp/nomad",
    "hashicorp/tfe",
    "hashicorp/random",
    "hashicorp/null",
    "hashicorp/local",
    "hashicorp/template",
    "hashicorp/time",
    "hashicorp/tls",
    "hashicorp/cloudinit",
    "hashicorp/external",
    "hashicorp/http",
    "hashicorp/archive",
    "hashicorp/dns",
    "cloudflare/cloudflare",
    "datadog/datadog",
    "grafana/grafana",
    "pagerduty/pagerduty",
    "newrelic/newrelic",
    "sumologic/sumologic",
    "splunk/splunk",
    "github/github",
    "integrations/github",
    "gitlabhq/gitlab",
    "mongodb/mongodbatlas",
    "snowflake-labs/snowflake",
    "confluentinc/confluent",
    "elastic/ec",
    "digitalocean/digitalocean",
    "linode/linode",
    "vultr/vultr",
    "hetznercloud/hcloud",
    "oracle/oci",
    "ibm-cloud/ibm",
    "aliyun/alicloud",
    "tencentcloudstack/tencentcloud",
    "huaweicloud/huaweicloud",
)

# ================= Concurrency =================
CONCURRENCY_LIMIT = int(os.getenv("EOL_CONCURRENCY_LIMIT", "10"))
DB_BATCH_SIZE = int(os.getenv("EOL_DB_BATCH_SIZE", "50"))

# ================= Retry / Timeout =================
MAX_RETRIES = 6
BASE_DELAY = 1.0
MAX_DELAY = 60.0
REQUEST_TIMEOUT = 60

RATE_LIMIT_PAUSE = 65.0
STARTUP_STAGGER_MAX = 5.0

USER_AGENT = "GeminiSec-EOL-Importer/1.0"

FetchStatus = Literal["ok", "missing", "failed"]
WorkKind = Literal["endoflife", "terraform"]

_rl_event: Optional[asyncio.Event] = None
_rl_lock: Optional[asyncio.Lock] = None


@dataclass(frozen=True)
class WorkItem:
    kind: WorkKind
    key: str
    slug: Optional[str] = None
    product_keys: Optional[Tuple[str, ...]] = None
    namespace: Optional[str] = None
    provider_type: Optional[str] = None


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
col_endoflife = db[COLLECTION_ENDOFLIFE]
col_terraform = db[COLLECTION_TERRAFORM]


def _ensure_indexes() -> None:
    for col, field in (
        (col_endoflife, "slug"),
        (col_terraform, "cache_key"),
    ):
        names = [i.get("name") for i in col.list_indexes()]
        idx = f"{field}_1"
        if idx not in names:
            print(f"Creating unique index on {col.name}.{field}...")
            col.create_index(field, unique=True)
        else:
            print(f"Index already exists on {col.name}.{field}.")


try:
    client.admin.command("ping")
    _ensure_indexes()
except ServerSelectionTimeoutError as e:
    print("\n[ERROR] Could not connect to MongoDB.")
    print(f"  MONGO_URI: {MONGO_URI!r}")
    print(f"  Database:  {DB_NAME!r}")
    print(f"  Details: {e}")
    raise SystemExit(2)
except pymongo.errors.OperationFailure as e:
    if e.code == 14031:
        print(f"[WARN] Not enough disk space for index: {e}")
    else:
        raise
print("MongoDB ready.\n")


# ================= SHA / skip unchanged =================
def _content_sha(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_sha_map(col: pymongo.collection.Collection, key_field: str) -> Dict[str, str]:
    sha_map: Dict[str, str] = {}
    try:
        for doc in col.find({}, {key_field: 1, "sha": 1, "_id": 0}):
            k = doc.get(key_field)
            if k and "sha" in doc:
                sha_map[str(k)] = doc["sha"]
    except Exception as e:
        print(f"[WARN] Could not load SHA map from {col.name}: {e}")
    return sha_map


def _compare_sha(new_sha: str, existing: Optional[str]) -> str:
    if existing is None:
        return "insert"
    if new_sha == existing:
        return "skip"
    return "update"


# ================= BACK-OFF / RATE LIMIT =================
def _backoff(attempt: int, base: float = BASE_DELAY, cap: float = MAX_DELAY) -> float:
    ceiling = min(cap, base * (2**attempt))
    return random.uniform(0.1, ceiling)


async def _pause_all_workers(who: str) -> None:
    async with _rl_lock:
        if _rl_event.is_set():
            return
        _rl_event.set()
        print(
            f"\n[429] '{who}' rate-limited — pausing ALL workers "
            f"for {RATE_LIMIT_PAUSE:.0f}s …"
        )
        await asyncio.sleep(RATE_LIMIT_PAUSE)
        _rl_event.clear()
        print("[429] Cooldown done — resuming.\n")


async def _wait_for_cooldown() -> None:
    if _rl_event.is_set():
        await asyncio.sleep(random.uniform(0.1, 3.0))
        while _rl_event.is_set():
            await asyncio.sleep(0.5)


# ================= PARSE API RESPONSES =================
def _parse_endoflife_json(data: Any) -> Optional[List[dict]]:
    if isinstance(data, dict) and "result" in data:
        releases = data.get("result", {}).get("releases")
        if isinstance(releases, list) and releases:
            return releases
    if isinstance(data, list) and data:
        return data
    return None


def _normalize_terraform_payload(
    namespace: str, provider_type: str, data: dict
) -> Optional[Dict[str, Any]]:
    versions_raw = data.get("versions", [])
    if not versions_raw or not isinstance(versions_raw, list):
        return None

    version_strings: List[str] = []
    for v in versions_raw:
        if isinstance(v, dict):
            ver = v.get("version")
        elif isinstance(v, str):
            ver = v
        else:
            continue
        if ver and isinstance(ver, str) and ver.strip():
            version_strings.append(ver.strip())

    if not version_strings:
        return None

    def _semver_key(v: str) -> Tuple[int, ...]:
        try:
            return tuple(int(x) for x in v.lstrip("v").split(".") if x.isdigit())
        except Exception:
            return (0,)

    sorted_versions = sorted(version_strings, key=_semver_key, reverse=True)
    latest_version = sorted_versions[0]
    published_at: Optional[str] = None
    latest_protocols: Optional[str] = None

    for v in versions_raw:
        if isinstance(v, dict) and v.get("version") == latest_version:
            raw_pub = v.get("published_at") or v.get("created_at")
            if raw_pub and isinstance(raw_pub, str):
                published_at = raw_pub
                try:
                    dt = datetime.fromisoformat(raw_pub.replace("Z", "+00:00"))
                    published_at = dt.strftime("%Y-%m-%d")
                except Exception:
                    published_at = raw_pub[:10]
            protos = v.get("protocols")
            if isinstance(protos, list) and protos:
                latest_protocols = ", ".join(str(p) for p in protos)
            break

    return {
        "latest_version": latest_version,
        "published_at": published_at,
        "versions": sorted_versions,
        "registry_address": f"{namespace}/{provider_type}",
        "indexed_version_count": len(version_strings),
        "latest_protocols": latest_protocols,
        "source": "terraform-registry",
    }


# ================= FETCH ONE WORK ITEM =================
async def _fetch_endoflife(
    session: aiohttp.ClientSession,
    slug: str,
    semaphore: asyncio.Semaphore,
    startup_delay: float,
) -> Tuple[str, FetchStatus, Optional[dict]]:
    urls = [
        f"{EOL_API_BASE}/{slug}/",
        f"{EOL_API_BASE}/{slug}.json",
        f"{EOL_API_BASE}/{slug}",
    ]
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

    async with semaphore:
        if startup_delay > 0:
            await asyncio.sleep(startup_delay)

        for attempt in range(MAX_RETRIES):
            await _wait_for_cooldown()
            last_status: Optional[int] = None

            for url in urls:
                try:
                    async with session.get(url, headers=headers, timeout=timeout) as resp:
                        last_status = resp.status
                        if resp.status == 404:
                            continue
                        if resp.status == 429:
                            asyncio.create_task(_pause_all_workers(slug))
                            await asyncio.sleep(_backoff(attempt, base=BASE_DELAY * 5))
                            break
                        if resp.status in (500, 502, 503, 504):
                            await asyncio.sleep(_backoff(attempt))
                            break
                        if resp.status != 200:
                            continue

                        ctype = (resp.headers.get("Content-Type") or "").lower()
                        if "json" not in ctype:
                            continue

                        data = await resp.json(content_type=None)
                        releases = _parse_endoflife_json(data)
                        if releases:
                            return slug, "ok", {
                                "releases": releases,
                                "source_url": url,
                            }
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

            if last_status in (404, 410):
                return slug, "missing", None

        return slug, "failed", None


async def _fetch_terraform(
    session: aiohttp.ClientSession,
    namespace: str,
    provider_type: str,
    cache_key: str,
    semaphore: asyncio.Semaphore,
    startup_delay: float,
) -> Tuple[str, FetchStatus, Optional[dict]]:
    url = f"{TF_REGISTRY_API_BASE}/{namespace}/{provider_type}/versions"
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

    async with semaphore:
        if startup_delay > 0:
            await asyncio.sleep(startup_delay)

        for attempt in range(MAX_RETRIES):
            await _wait_for_cooldown()
            try:
                async with session.get(url, headers=headers, timeout=timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        payload = _normalize_terraform_payload(
                            namespace, provider_type, data
                        )
                        if payload:
                            return cache_key, "ok", payload
                        return cache_key, "missing", None

                    if resp.status in (404, 410):
                        return cache_key, "missing", None

                    if resp.status == 429:
                        asyncio.create_task(_pause_all_workers(cache_key))
                        await asyncio.sleep(_backoff(attempt, base=BASE_DELAY * 5))
                        continue

                    if resp.status in (500, 502, 503, 504):
                        await asyncio.sleep(_backoff(attempt))
                        continue

                    return cache_key, "failed", None

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

        return cache_key, "failed", None


async def fetch_one(
    session: aiohttp.ClientSession,
    item: WorkItem,
    semaphore: asyncio.Semaphore,
    startup_delay: float = 0.0,
) -> Tuple[str, FetchStatus, Optional[dict], WorkItem]:
    if item.kind == "endoflife":
        key, status, data = await _fetch_endoflife(
            session, item.slug or item.key, semaphore, startup_delay
        )
    else:
        key, status, data = await _fetch_terraform(
            session,
            item.namespace or "",
            item.provider_type or "",
            item.key,
            semaphore,
            startup_delay,
        )
    return key, status, data, item


# ================= BUILD MONGO OPS =================
def build_endoflife_ops(
    records: List[Tuple[WorkItem, dict]],
    sha_map: Dict[str, str],
    current_time: datetime,
    counters: Dict[str, int],
) -> List[pymongo.UpdateOne]:
    ops: List[pymongo.UpdateOne] = []
    for item, payload in records:
        slug = item.slug or item.key
        releases = payload.get("releases")
        if not isinstance(releases, list) or not releases:
            continue

        body = {"releases": releases}
        new_sha = _content_sha(body)
        action = _compare_sha(new_sha, sha_map.get(slug))
        sha_map[slug] = new_sha
        counters["total"] += 1

        if action == "skip":
            counters["skipped"] += 1
            continue
        if action == "insert":
            counters["inserted"] += 1
        else:
            counters["updated"] += 1

        doc: Dict[str, Any] = {
            "slug": slug,
            "releases": releases,
            "fetched_at": current_time,
            "source": "endoflife.date",
            "sha": new_sha,
        }
        if payload.get("source_url"):
            doc["source_url"] = payload["source_url"]
        if item.product_keys:
            doc["product_keys"] = list(item.product_keys)

        ops.append(
            pymongo.UpdateOne({"slug": slug}, {"$set": doc}, upsert=True)
        )
    return ops


def build_terraform_ops(
    records: List[Tuple[WorkItem, dict]],
    sha_map: Dict[str, str],
    current_time: datetime,
    counters: Dict[str, int],
) -> List[pymongo.UpdateOne]:
    ops: List[pymongo.UpdateOne] = []
    for item, payload in records:
        cache_key = item.key
        new_sha = _content_sha(payload)
        action = _compare_sha(new_sha, sha_map.get(cache_key))
        sha_map[cache_key] = new_sha
        counters["total"] += 1

        if action == "skip":
            counters["skipped"] += 1
            continue
        if action == "insert":
            counters["inserted"] += 1
        else:
            counters["updated"] += 1

        doc = {
            "cache_key": cache_key.lower().strip(),
            "fetched_at": current_time,
            "sha": new_sha,
            **{k: v for k, v in payload.items() if k not in ("fetched_at", "cache_key", "sha")},
        }
        ops.append(
            pymongo.UpdateOne(
                {"cache_key": doc["cache_key"]}, {"$set": doc}, upsert=True
            )
        )
    return ops


async def db_write(
    loop: asyncio.AbstractEventLoop,
    col: pymongo.collection.Collection,
    ops: List[pymongo.UpdateOne],
) -> None:
    if not ops:
        return
    for attempt in range(4):
        try:
            fn = functools.partial(col.bulk_write, ops, ordered=False)
            await loop.run_in_executor(None, fn)
            return
        except pymongo.errors.BulkWriteError as bwe:
            non_dup = [
                e
                for e in bwe.details.get("writeErrors", [])
                if e.get("code") != 11000
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
            print(f"[DB] Connection error (attempt {attempt + 1}/4), retry in {wait}s: {e}")
            await asyncio.sleep(wait)
        except Exception as e:
            print(f"[DB] Unexpected error: {e}")
            return


# ================= WORK LIST =================
def _parse_tf_source(source: str) -> Tuple[Optional[str], Optional[str]]:
    s = source.strip().lower()
    if s.startswith("registry.terraform.io/"):
        s = s[len("registry.terraform.io/") :]
    parts = s.split("/")
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return None, None


def build_work_items(
    *,
    include_endoflife: bool,
    include_terraform: bool,
) -> List[WorkItem]:
    items: List[WorkItem] = []

    if include_endoflife:
        slug_to_keys: Dict[str, List[str]] = {}
        for key, slug in EOL_PRODUCT_SLUGS.items():
            slug_to_keys.setdefault(slug, []).append(key)
        for slug, keys in sorted(slug_to_keys.items()):
            items.append(
                WorkItem(
                    kind="endoflife",
                    key=slug,
                    slug=slug,
                    product_keys=tuple(keys),
                )
            )

    if include_terraform:
        seen: Set[str] = set()
        for source in _DEFAULT_TF_SOURCES:
            ns, ptype = _parse_tf_source(source)
            if not ns or not ptype:
                continue
            cache_key = f"{ns}/{ptype}".lower()
            if cache_key in seen:
                continue
            seen.add(cache_key)
            items.append(
                WorkItem(
                    kind="terraform",
                    key=cache_key,
                    namespace=ns,
                    provider_type=ptype,
                )
            )

        extra = os.getenv("EOL_TF_SYNC_PROVIDERS", "").strip()
        for part in extra.split(","):
            part = part.strip()
            if not part or "/" not in part:
                continue
            ns, ptype = part.split("/", 1)
            ns, ptype = ns.strip(), ptype.strip()
            if not ns or not ptype:
                continue
            cache_key = f"{ns}/{ptype}".lower()
            if cache_key in seen:
                continue
            seen.add(cache_key)
            items.append(
                WorkItem(
                    kind="terraform",
                    key=cache_key,
                    namespace=ns,
                    provider_type=ptype,
                )
            )

    return items


# ================= MAIN WORKER =================
async def worker(work_items: List[WorkItem]) -> Dict[str, int]:
    global _rl_event, _rl_lock
    _rl_event = asyncio.Event()
    _rl_lock = asyncio.Lock()

    loop = asyncio.get_running_loop()
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    current_time = datetime.now(timezone.utc)

    counters: Dict[str, int] = {
        "total": 0,
        "inserted": 0,
        "updated": 0,
        "skipped": 0,
        "fetch_failed": 0,
        "not_found": 0,
    }

    sha_endoflife = load_sha_map(col_endoflife, "slug")
    sha_terraform = load_sha_map(col_terraform, "cache_key")
    print(
        f"SHA maps loaded: endoflife={len(sha_endoflife):,}, "
        f"terraform={len(sha_terraform):,}"
    )

    connector = aiohttp.TCPConnector(
        limit=CONCURRENCY_LIMIT,
        limit_per_host=CONCURRENCY_LIMIT,
        force_close=False,
        enable_cleanup_closed=True,
        keepalive_timeout=60,
        ttl_dns_cache=300,
    )
    session_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Cache-Control": "no-cache",
    }

    pbar = tqdm(
        total=len(work_items),
        unit=" item",
        desc="Importing EOL",
        dynamic_ncols=True,
    )

    batch_endoflife: List[Tuple[WorkItem, dict]] = []
    batch_terraform: List[Tuple[WorkItem, dict]] = []

    async with aiohttp.ClientSession(
        connector=connector, headers=session_headers
    ) as session:
        pending: set[asyncio.Task] = set()
        next_idx = 0
        startup_slots_used = 0

        def _schedule(item: WorkItem, delay: float) -> None:
            pending.add(
                asyncio.create_task(fetch_one(session, item, semaphore, delay))
            )

        while next_idx < len(work_items) and len(pending) < CONCURRENCY_LIMIT:
            item = work_items[next_idx]
            next_idx += 1
            delay = 0.0
            if startup_slots_used < CONCURRENCY_LIMIT:
                delay = random.uniform(0, STARTUP_STAGGER_MAX)
                startup_slots_used += 1
            _schedule(item, delay)

        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )

            for task in done:
                _key, status, data, item = await task
                pbar.update(1)

                if status == "ok" and data is not None:
                    if item.kind == "endoflife":
                        batch_endoflife.append((item, data))
                    else:
                        batch_terraform.append((item, data))
                elif status == "missing":
                    counters["not_found"] += 1
                else:
                    counters["fetch_failed"] += 1

                if len(batch_endoflife) >= DB_BATCH_SIZE:
                    ops = build_endoflife_ops(
                        batch_endoflife, sha_endoflife, current_time, counters
                    )
                    await db_write(loop, col_endoflife, ops)
                    batch_endoflife.clear()

                if len(batch_terraform) >= DB_BATCH_SIZE:
                    ops = build_terraform_ops(
                        batch_terraform, sha_terraform, current_time, counters
                    )
                    await db_write(loop, col_terraform, ops)
                    batch_terraform.clear()

            while next_idx < len(work_items) and len(pending) < CONCURRENCY_LIMIT:
                _schedule(work_items[next_idx], 0.0)
                next_idx += 1

            pbar.set_postfix(
                {
                    "ins": counters["inserted"],
                    "upd": counters["updated"],
                    "skip": counters["skipped"],
                    "404": counters["not_found"],
                    "fail": counters["fetch_failed"],
                }
            )

        if batch_endoflife:
            ops = build_endoflife_ops(
                batch_endoflife, sha_endoflife, current_time, counters
            )
            await db_write(loop, col_endoflife, ops)
        if batch_terraform:
            ops = build_terraform_ops(
                batch_terraform, sha_terraform, current_time, counters
            )
            await db_write(loop, col_terraform, ops)

    pbar.close()
    return counters


def print_summary(label: str, counters: Dict[str, int]) -> None:
    print(f"\n{'=' * 60}")
    print(f" {label}")
    print(f"{'=' * 60}")
    print(f"Total processed  : {counters.get('total', 0):>10,}")
    print(f"Inserted : {counters.get('inserted', 0):>10,}")
    print(f"Updated  : {counters.get('updated', 0):>10,}")
    print(f"Skipped (no change): {counters.get('skipped', 0):>10,}")
    print(f"Not found (404/410): {counters.get('not_found', 0):>10,}")
    print(f"Fetch failed : {counters.get('fetch_failed', 0):>10,}")
    print(f"{'=' * 60}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="EOL IntelDB importer (async)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true")
    #--endoflife-only for eol data
    group.add_argument("--endoflife-only", action="store_true")
    #--terraform-only for terraform_providers data
    group.add_argument("--terraform-only", action="store_true")
    args = parser.parse_args()

    include_eol = args.all or args.endoflife_only
    include_tf = args.all or args.terraform_only
    work_items = build_work_items(
        include_endoflife=include_eol,
        include_terraform=include_tf,
    )

    if not work_items:
        print("No work items to process.")
        return 1
    print(
        f"Starting EOL import: {len(work_items)} items "
        f"(concurrency={CONCURRENCY_LIMIT}) …\n")

    try:
        counters = asyncio.run(worker(work_items))
    except KeyboardInterrupt:
        print("\nStopped by user.")
        return 0

    print_summary("EOL IMPORT SUMMARY", counters)
    if counters.get("fetch_failed", 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
