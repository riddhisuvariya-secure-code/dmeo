import asyncio
import aiohttp
import pymongo
import functools
import sys
import io
import os
import json
import random
import xml.etree.ElementTree as ET
from tqdm import tqdm
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Literal
from dotenv import load_dotenv

load_dotenv()

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from calculator_sha import PackageDocument, compare

# ================= CONFIGURATION =================
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("MONGO_URI environment variable is required.")
DB_NAME = os.getenv("MONGO_DB_NAME")
if not DB_NAME:
    raise ValueError("MONGO_DB_NAME environment variable is required.")
COLLECTION_NAME = "Updated_maven_metadata"

CONCURRENCY_LIMIT   = 3    
LICENSE_CONCURRENCY = 20   
ROWS_PER_PAGE       = 200

POM_BASE_URL           = "https://repo1.maven.org/maven2"
POM_TIMEOUT            = 20
LICENSE_MAX_RETRIES    = 2
POM_PARENT_MAX_DEPTH   = 5
LICENSE_CACHE_MAX_SIZE = 100_000
VERSION_FALLBACK_LIMIT = 2

MAX_RETRIES      = 6
BASE_DELAY       = 1.0
MAX_DELAY        = 60.0
REQUEST_TIMEOUT  = 60
RATE_LIMIT_PAUSE = 30.0


PAGE_PREFETCH = CONCURRENCY_LIMIT

SEARCH_ENDPOINTS = [
    "https://search.maven.org/solrsearch/select",
    "https://central.sonatype.com/solrsearch/select",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept":          "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer":         "https://search.maven.org/",
    "Origin":          "https://search.maven.org",
}

# ================= DATABASE SETUP =================
print("[*] Connecting to MongoDB...")
client = pymongo.MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=30000,
    connectTimeoutMS=30000,
    socketTimeoutMS=60000,
    maxPoolSize=50,
    minPoolSize=5,
    retryWrites=True,
    retryReads=True,
)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]
print(f"[*] Using Mongo collection: {DB_NAME}.{COLLECTION_NAME}")

if COLLECTION_NAME != "Updated_maven_metadata":
    alt_count = db["Updated_maven_metadata"].estimated_document_count()
    if alt_count > 0:
        print(
            "[!] Note: Updated_maven_metadata already has "
            f"{alt_count:,} docs. Ensure MONGO_COLLECTION_NAME is intended."
        )

try:
    idx_exists = any(i.get("name") == "package_name" for i in collection.list_indexes())
    if not idx_exists:
        print("[*] Creating unique index on 'package_name'...")
        collection.create_index("package_name", unique=True)
        print("[+] Index created.")
    else:
        print("[*] Index already exists.")
except pymongo.errors.OperationFailure as e:
    if e.code == 14031:
        print(f"[!] Disk space too low to create index: {e}")
    else:
        raise
print("[+] MongoDB ready.\n")


# ================= EXISTING SHA LOOKUP =================
def load_existing_sha_for_packages(package_names):
    if not package_names:
        return {}
    existing_sha_map = {}
    try:
        docs = collection.find(
            {"package_name": {"$in": package_names}},
            {"package_name": 1, "sha": 1, "_id": 0}
        )
        for doc in docs:
            pkg_name = doc.get("package_name")
            if pkg_name:
                existing_sha_map[pkg_name] = doc.get("sha")
    except Exception as e:
        print(f"[!] Error loading existing package SHA batch: {e}")
    return existing_sha_map


# ================= BACKOFF =================
def _backoff(attempt, base=BASE_DELAY, cap=MAX_DELAY):
    ceiling = min(cap, base * (2 ** attempt))
    return random.uniform(0.1, ceiling)


# ================= RATE-LIMIT GATE =================
_rl_event = None
_rl_lock  = None


async def _pause_all_workers(who):
    async with _rl_lock:
        if _rl_event.is_set():
            return
        _rl_event.set()
        print(f"\n[429] Rate-limited on '{who}' — pausing {RATE_LIMIT_PAUSE:.0f}s …")
        await asyncio.sleep(RATE_LIMIT_PAUSE)
        _rl_event.clear()
        print("[429] Cooldown done — resuming.\n")


async def _wait_for_cooldown():
    if _rl_event.is_set():
        await asyncio.sleep(random.uniform(0.1, 2.0))
        while _rl_event.is_set():
            await asyncio.sleep(0.5)


# ================= LICENSE CACHE =================
_license_cache: Dict[str, list] = {}


def _cache_license_result(key, licenses):
    _license_cache[key] = licenses
    if len(_license_cache) > LICENSE_CACHE_MAX_SIZE:
        evict = LICENSE_CACHE_MAX_SIZE // 10
        for k in list(_license_cache.keys())[:evict]:
            del _license_cache[k]


# ================= POM XML HELPERS =================
def _strip_ns(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def _child(el, name):
    for c in list(el):
        if _strip_ns(c.tag) == name:
            return c
    return None


def _resolve_prop(raw, props, project_ver):
    v = (raw or "").strip()
    if not v or "${" not in v:
        return v
    if v.startswith("${") and v.endswith("}"):
        key = v[2:-1].strip()
        if key in ("project.version", "pom.version", "version"):
            return project_ver or ""
        return props.get(key, "")
    return ""


def _pom_url(g, a, v):
    return f"{POM_BASE_URL}/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom"


def _metadata_url(g, a):
    return f"{POM_BASE_URL}/{g.replace('.', '/')}/{a}/maven-metadata.xml"


def _parse_pom(xml_text):
    licenses   = []
    parent_gav = None
    try:
        root = ET.fromstring(xml_text)

        lics_el = _child(root, "licenses")
        if lics_el is not None:
            for lic in list(lics_el):
                if _strip_ns(lic.tag) != "license":
                    continue
                entry = {}
                for c in list(lic):
                    tag = _strip_ns(c.tag)
                    val = (c.text or "").strip()
                    if not val:
                        continue
                    if tag == "name":
                        entry["name"] = val
                    elif tag == "url":
                        entry["url"] = val
                    elif tag in ("comments", "distribution"):
                        entry[tag] = val
                if entry:
                    licenses.append(entry)

        proj_ver = ""
        ver_el = _child(root, "version")
        if ver_el is not None and ver_el.text:
            proj_ver = ver_el.text.strip()

        props = {}
        props_el = _child(root, "properties")
        if props_el is not None:
            for p in list(props_el):
                k = _strip_ns(p.tag)
                v = (p.text or "").strip()
                if k and v:
                    props[k] = v

        parent_el = _child(root, "parent")
        if parent_el is not None:
            g = a = v = ""
            for c in list(parent_el):
                t = _strip_ns(c.tag)
                val = (c.text or "").strip()
                if t == "groupId":
                    g = val
                elif t == "artifactId":
                    a = val
                elif t == "version":
                    v = val
            v = _resolve_prop(v, props, proj_ver)
            if g and a and v:
                parent_gav = (g, a, v)

    except ET.ParseError:
        pass
    return licenses, parent_gav


async def _fetch_versions(session, g, a, semaphore):
    url = _metadata_url(g, a)
    try:
        async with semaphore:
            async with session.get(
                url, headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=POM_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    return []
                text = await resp.text(encoding="utf-8", errors="replace")

        root = ET.fromstring(text)
        versioning = _child(root, "versioning")
        if versioning is None:
            return []
        versions_el = _child(versioning, "versions")
        if versions_el is None:
            return []

        versions = []
        for v_el in list(versions_el):
            if _strip_ns(v_el.tag) == "version" and v_el.text:
                v = v_el.text.strip()
                if v:
                    versions.append(v)

        versions.reverse()
        return versions
    except Exception:
        return []


async def fetch_license_from_pom(session, g, a, version, semaphore, depth=0, visited=None):
    if not version:
        return []

    cache_key = f"{g}:{a}:{version}"
    cached = _license_cache.get(cache_key)
    if cached is not None:
        return cached

    if visited is None:
        visited = set()
    if cache_key in visited:
        return []
    visited.add(cache_key)

    url = _pom_url(g, a, version)

    for attempt in range(LICENSE_MAX_RETRIES):
        text       = None
        parent_gav = None
        try:
            async with semaphore:
                async with session.get(
                    url, headers=HEADERS,
                    timeout=aiohttp.ClientTimeout(total=POM_TIMEOUT),
                ) as resp:
                    if resp.status == 200:
                        text = await resp.text(encoding="utf-8", errors="replace")
                    elif resp.status in (404, 410):
                        _cache_license_result(cache_key, [])
                        return []
                    elif resp.status == 429:
                        await asyncio.sleep(_backoff(attempt, base=5.0))
                        continue
                    elif resp.status in (500, 502, 503, 504):
                        await asyncio.sleep(_backoff(attempt))
                        continue
                    else:
                        _cache_license_result(cache_key, [])
                        return []
        except (asyncio.TimeoutError, aiohttp.ClientError):
            await asyncio.sleep(_backoff(attempt))
            continue
        except Exception:
            _cache_license_result(cache_key, [])
            return []

        if text is None:
            continue

        licenses, parent_gav = _parse_pom(text)
        if licenses:
            _cache_license_result(cache_key, licenses)
            return licenses

        if depth < POM_PARENT_MAX_DEPTH and parent_gav:
            parent_licenses = await fetch_license_from_pom(
                session, parent_gav[0], parent_gav[1], parent_gav[2],
                semaphore, depth + 1, visited,
            )
            _cache_license_result(cache_key, parent_licenses)
            return parent_licenses

        _cache_license_result(cache_key, [])
        return []

    _cache_license_result(cache_key, [])
    return []


async def fetch_license_with_fallback(session, g, a, primary_version, semaphore):
    licenses = await fetch_license_from_pom(session, g, a, primary_version, semaphore)
    if licenses:
        return licenses

    if VERSION_FALLBACK_LIMIT <= 0:
        return []

    all_versions = await _fetch_versions(session, g, a, semaphore)
    tried = {primary_version}

    for version in all_versions[:VERSION_FALLBACK_LIMIT]:
        if version in tried:
            continue
        tried.add(version)
        licenses = await fetch_license_from_pom(session, g, a, version, semaphore)
        if licenses:
            return licenses

    return []


async def fetch_licenses_batch(session, docs, license_semaphore):
    tasks    = {}
    key_list = []

    for doc in docs:
        g = doc.get("g", "")
        a = doc.get("a", "")
        v = (doc.get("latestVersion") or doc.get("v") or "").strip()
        if not (g and a and v):
            continue
        key = f"{g}:{a}"
        if key not in tasks:
            tasks[key] = fetch_license_with_fallback(session, g, a, v, license_semaphore)
            key_list.append(key)

    if not key_list:
        return {}

    results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)

    results = {}
    for key, result in zip(key_list, results_list):
        results[key] = [] if isinstance(result, Exception) else result

    return results


# ================= HTTP HELPERS (Solr) =================
_active_ep = 0


async def fetch_page(session, query, start, semaphore, counter):
    global _active_ep
    params = {"q": query, "rows": ROWS_PER_PAGE, "start": start, "wt": "json"}
    order  = [_active_ep] + [i for i in range(len(SEARCH_ENDPOINTS)) if i != _active_ep]

    for ep_idx in order:
        url = SEARCH_ENDPOINTS[ep_idx]
        for attempt in range(MAX_RETRIES):
            await _wait_for_cooldown()
            async with semaphore:
                try:
                    async with session.get(
                        url, params=params, headers=HEADERS,
                        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                    ) as resp:
                        if resp.status == 200:
                            try:
                                data = await resp.json(content_type=None)
                            except Exception:
                                await asyncio.sleep(_backoff(attempt))
                                continue
                            _active_ep = ep_idx
                            return "ok", data
                        if resp.status in (404, 410):
                            counter["not_found"] = counter.get("not_found", 0) + 1
                            return "missing", None
                        if resp.status == 429:
                            counter["rate_limited"] = counter.get("rate_limited", 0) + 1
                            asyncio.create_task(_pause_all_workers(f"{query} start={start}"))
                            await asyncio.sleep(_backoff(attempt, base=BASE_DELAY * 5))
                            continue
                        if resp.status in (500, 502, 503, 504):
                            await asyncio.sleep(_backoff(attempt))
                            continue
                        if resp.status in (403, 406):
                            break
                        break
                except (asyncio.TimeoutError, aiohttp.ClientError):
                    await asyncio.sleep(_backoff(attempt))
                except Exception:
                    await asyncio.sleep(_backoff(attempt))

    counter["fetch_failed"] = counter.get("fetch_failed", 0) + 1
    return "failed", None


async def get_num_found(session, query, semaphore):
    global _active_ep
    params = {"q": query, "rows": 0, "wt": "json"}
    order  = [_active_ep] + [i for i in range(len(SEARCH_ENDPOINTS)) if i != _active_ep]

    for ep_idx in order:
        url = SEARCH_ENDPOINTS[ep_idx]
        async with semaphore:
            try:
                async with session.get(
                    url, params=params, headers=HEADERS,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        d = await resp.json(content_type=None)
                        _active_ep = ep_idx
                        return d.get("response", {}).get("numFound", 0)
                    if resp.status in (403, 406):
                        continue
            except Exception:
                continue
    return 0


# ================= DEBUG PROBE =================
async def debug_probe():
    connector = aiohttp.TCPConnector(limit=2)
    async with aiohttp.ClientSession(connector=connector) as session:
        for idx, url in enumerate(SEARCH_ENDPOINTS):
            params = {"q": "g:org.apache*", "rows": 3, "wt": "json"}
            try:
                async with session.get(
                    url, params=params, headers=HEADERS,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    body = await resp.text()
                    if resp.status == 200:
                        try:
                            parsed = json.loads(body)
                            nf = parsed.get("response", {}).get("numFound", 0)
                            if nf > 0:
                                global _active_ep
                                _active_ep = idx
                                return True
                        except json.JSONDecodeError:
                            continue
            except Exception:
                pass

    print("\n[DEBUG] Neither endpoint returned usable data.")
    return False


# ================= DB FLUSH =================
async def flush_ops(loop, ops):
    if not ops:
        return
    try:
        await loop.run_in_executor(None, functools.partial(collection.bulk_write, ops, ordered=False))
    except pymongo.errors.BulkWriteError as bwe:
        for err in bwe.details.get("writeErrors", []):
            if err.get("code") != 11000:
                print(f"\n[!] Write err: {err}")
    except Exception as e:
        print(f"\n[!] DB err: {e}")


# ================= PROCESS DOCS =================
async def process_docs(docs, session, license_semaphore, loop, current_time, counter, seen):
    ops              = []
    unique_processed = 0
    filtered_docs    = []
    package_names    = []
    batch_inserted = batch_updated = batch_skipped = 0

    for doc in docs:
        if "g" not in doc or "a" not in doc:
            continue
        pkg_key = f"{doc['g']}:{doc['a']}"
        if pkg_key in seen:
            counter["duplicates"] = counter.get("duplicates", 0) + 1
            continue
        seen.add(pkg_key)
        filtered_docs.append(doc)
        package_names.append(pkg_key)

    if not filtered_docs:
        return 0

    existing_sha_map = load_existing_sha_for_packages(package_names)

    action_map = {}
    sha_map    = {}
    for doc in filtered_docs:
        pkg_key      = f"{doc['g']}:{doc['a']}"
        existing_sha = existing_sha_map.get(pkg_key)
        new_sha, _, action = compare(doc, existing_sha, pkg_key, current_time)
        action_map[pkg_key] = action
        sha_map[pkg_key]    = new_sha

    license_map = await fetch_licenses_batch(session, filtered_docs, license_semaphore)

    for doc in filtered_docs:
        pkg_key = f"{doc['g']}:{doc['a']}"
        action  = action_map[pkg_key]
        new_sha = sha_map[pkg_key]

        counter["total"] += 1
        unique_processed += 1

        if action == "insert":
            counter["inserted"] += 1
            batch_inserted += 1
        elif action == "update":
            counter["updated"] += 1
            batch_updated += 1
        else:
            counter["skipped"] += 1
            batch_skipped += 1

        licenses          = license_map.get(pkg_key, [])
        doc_with_licenses = dict(doc)
        doc_with_licenses["licenses"] = licenses

        doc_data = {
            "package_name": pkg_key,
            "sha":          new_sha,
            "object":       doc_with_licenses,
        }
        if action == "update":
            doc_data["updated_time"] = current_time

        try:
            pd = PackageDocument(
                package_name=doc_data["package_name"],
                sha=doc_data["sha"],
                updated_time=doc_data.get("updated_time"),
                object=doc_data["object"],
            )
            payload = pd.model_dump(exclude_none=True)
            ops.append(pymongo.UpdateOne(
                {"package_name": pkg_key},
                {"$set": payload},
                upsert=True
            ))
        except Exception as e:
            print(f"\n[!] Pydantic err {pkg_key}: {e}")

    if unique_processed:
        lic_fetched = sum(1 for v in license_map.values() if v)
        print(
            f"[*] Solr batch: "
            f"insert={batch_inserted:,} update={batch_updated:,} skip={batch_skipped:,} "
            f"| licenses_found={lic_fetched:,}/{len(filtered_docs):,}"
        )

    await flush_ops(loop, ops)
    return unique_processed


# ================= BACKFILL EMPTY LICENSES =================
async def backfill_empty_licenses(session, license_semaphore, loop, batch_size=200):
    query = {
        "$or": [
            {"object.licenses": {"$exists": False}},
            {"object.licenses": {"$size": 0}},
        ]
    }
    projection = {
        "package_name":          1,
        "object.g":              1,
        "object.a":              1,
        "object.latestVersion":  1,
        "object.v":              1,
    }
    cursor = collection.find(query, projection=projection, no_cursor_timeout=True).batch_size(batch_size)

    stats         = {"candidates": 0, "processable": 0, "updated": 0, "resolved_non_empty": 0}
    pending_docs  = []
    pending_names = []

    async def flush_backfill():
        if not pending_docs:
            return
        license_map = await fetch_licenses_batch(session, pending_docs, license_semaphore)
        ops = []
        for item, pkg_name in zip(pending_docs, pending_names):
            key      = f"{item['g']}:{item['a']}"
            licenses = license_map.get(key, [])
            if licenses:
                stats["resolved_non_empty"] += 1
            ops.append(pymongo.UpdateOne(
                {"package_name": pkg_name},
                {"$set": {"object.licenses": licenses}},
                upsert=False,
            ))
        await flush_ops(loop, ops)
        stats["updated"] += len(ops)
        pending_docs.clear()
        pending_names.clear()

    try:
        for db_doc in cursor:
            stats["candidates"] += 1
            obj      = db_doc.get("object") or {}
            g        = obj.get("g")
            a        = obj.get("a")
            v        = (obj.get("latestVersion") or obj.get("v") or "").strip()
            pkg_name = db_doc.get("package_name")
            if not (g and a and v and pkg_name):
                continue
            stats["processable"] += 1
            pending_docs.append({"g": g, "a": a, "latestVersion": v})
            pending_names.append(pkg_name)
            if len(pending_docs) >= batch_size:
                await flush_backfill()
        await flush_backfill()
    finally:
        cursor.close()

    return stats


# ================= SOLR IMPORT =================
async def import_all_via_solr(current_time, counter):
    
    solr_semaphore    = asyncio.Semaphore(CONCURRENCY_LIMIT)
    license_semaphore = asyncio.Semaphore(LICENSE_CONCURRENCY)
    connector         = aiohttp.TCPConnector(
        limit=(CONCURRENCY_LIMIT + LICENSE_CONCURRENCY) * 3,
        limit_per_host=20,
        ttl_dns_cache=300,
    )
    loop = asyncio.get_running_loop()

    # seen must be protected — multiple page tasks run concurrently
    seen     = set()
    seen_lock = asyncio.Lock()

    async with aiohttp.ClientSession(connector=connector) as session:
        num_found = await get_num_found(session, "*:*", solr_semaphore)
        if num_found <= 0:
            print("[!] Solr *:* reported numFound=0 (or failed).")
            return 0

        print(f"[*] Solr *:* numFound = {num_found:,}")
        page_count = (num_found + ROWS_PER_PAGE - 1) // ROWS_PER_PAGE
        counter["pages_total"] = page_count

        bar        = tqdm(total=page_count, unit="page")
        total_lock = asyncio.Lock()
        total      = 0

        async def fetch_and_process_page(start: int) -> int:
            """Fetch one Solr page and process it. Returns number of docs processed."""
            nonlocal total

            # ---- fetch ----
            status, data = await fetch_page(session, "*:*", start, solr_semaphore, counter)

            if status == "failed":
                print(f"[!] Page start={start} failed after all retries — skipping.")
                return 0
            if status != "ok" or not data:
                return 0

            docs = data.get("response", {}).get("docs", [])
            if not docs:
                return 0

            # ---- deduplicate using shared seen set ----
            filtered = []
            async with seen_lock:
                for doc in docs:
                    if "g" not in doc or "a" not in doc:
                        continue
                    key = f"{doc['g']}:{doc['a']}"
                    if key in seen:
                        counter["duplicates"] = counter.get("duplicates", 0) + 1
                    else:
                        seen.add(key)
                        filtered.append(doc)

            if not filtered:
                return 0

            # ---- process (SHA compare + license fetch + DB write) ----
            n = await process_docs(
                filtered, session, license_semaphore,
                loop, current_time, counter, set(),  # pass empty set — dedup already done above
            )

            async with total_lock:
                total += n

            counter["pages_done"] = counter.get("pages_done", 0) + 1
            bar.update(1)
            bar.set_postfix(
                Pages=f"{counter.get('pages_done', 0)}/{page_count}",
                Total=total,
                Ins=counter["inserted"],
                Upd=counter["updated"],
                Skip=counter["skipped"],
            )
            return n

        
        offsets = list(range(0, num_found, ROWS_PER_PAGE))
        await asyncio.gather(
            *[fetch_and_process_page(s) for s in offsets],
            return_exceptions=True,
        )

        bar.close()
        return total


# ================= ENTRY POINT =================
async def worker():
    current_time = datetime.now(timezone.utc)
    global _rl_event, _rl_lock
    _rl_event = asyncio.Event()
    _rl_lock  = asyncio.Lock()

    print("[*] Reading current Maven collection size...")
    existing_before = collection.estimated_document_count()
    print(f"[+] Existing package docs in Mongo: {existing_before:,}\n")

    counter = {
        "total": 0, "inserted": 0, "updated": 0, "skipped": 0,
        "fetch_failed": 0, "not_found": 0, "rate_limited": 0, "duplicates": 0,
        "pages_done": 0, "pages_total": 0,
    }

    api_ok = await debug_probe()
    total  = 0
    if not api_ok:
        print("[!] Maven Solr API unavailable. Skipping Solr import for this run.")
    else:
        print("[*] Using Solr API only (global *:* scan).")
        total = await import_all_via_solr(current_time, counter)
        print(f"\n[+] Solr API import complete. Total processed: {total:,}")
        if total == 0:
            print("[!] Solr scan produced 0 packages (check API / rate limits).")

    print("\n[*] Backfilling missing/empty licenses in existing Mongo docs...")
    license_semaphore = asyncio.Semaphore(LICENSE_CONCURRENCY)
    connector = aiohttp.TCPConnector(
        limit=LICENSE_CONCURRENCY * 3,
        limit_per_host=20,
        ttl_dns_cache=300,
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        backfill_stats = await backfill_empty_licenses(
            session=session,
            license_semaphore=license_semaphore,
            loop=asyncio.get_running_loop(),
            batch_size=ROWS_PER_PAGE,
        )
    print(
        "[+] License backfill complete: "
        f"candidates={backfill_stats['candidates']:,} "
        f"processable={backfill_stats['processable']:,} "
        f"updated={backfill_stats['updated']:,} "
        f"resolved_non_empty={backfill_stats['resolved_non_empty']:,}"
    )

    print("\n" + "=" * 40)
    print("[+] MAVEN IMPORT SUMMARY")
    print(f" total    = {counter['total']:,}")
    print(f" inserted = {counter['inserted']:,}")
    print(f" updated  = {counter['updated']:,}")
    print(f" skipped  = {counter['skipped']:,}")
    print(f" dupes    = {counter.get('duplicates', 0):,}")
    print(f" pages    = {counter.get('pages_done', 0):,}/{counter.get('pages_total', 0):,}")
    print(f" 404/410  = {counter.get('not_found', 0):,}")
    print(f" fail     = {counter.get('fetch_failed', 0):,}")
    print(f" db_before= {existing_before:,}")
    db_after = collection.estimated_document_count()
    print(f" db_after = {db_after:,}")
    print(f" net_new  = {db_after - existing_before:,}")
    print("=" * 40)


if __name__ == "__main__":
    try:
        try:
            asyncio.run(worker())
        except AttributeError:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(worker())
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
