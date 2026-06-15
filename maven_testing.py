"""
Maven Central Lucene Index Parser — Production Grade
=====================================================
Downloads and parses the Maven Central binary Lucene index from:
  https://repo1.maven.org/maven2/.index/

Strategy
--------
First run  : downloads nexus-maven-repository-index.gz (full, ~500 MB compressed)
Subsequent : downloads only incremental chunks nexus-maven-repository-index.N.gz
             using the last chunk number stored in maven_lucene_state.json

Binary record format (Java DataOutput inside gzip):
  Per document:
    loop:
      1 byte  : field flags (0 = end-of-document, EOF = end-of-file)
      readUTF : field name  (2-byte big-endian length + modified UTF-8)
      readUTF : field value
  Key fields:
    u   = "groupId:artifactId:version:classifier:packaging"
    m   = lastModified (epoch ms as string)
    1   = sha1
    i   = "packaging|lastModified|size|..."
    n   = artifact display name
    d   = description
    del = present when the artifact was DELETED in an incremental chunk

Pipeline (mirrors maven_solr_import.py)
----------------------------------------
1. Parse Lucene index → raw records
2. SHA-compare each record against MongoDB (skip if unchanged)
3. Async-fetch POM licenses (with parent POM walk + version fallback)
4. Bulk-upsert to MongoDB
5. Backfill any existing docs still missing licenses
"""

from __future__ import annotations

import asyncio
import functools
import gzip
import io
import json
import os
import random
import struct
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp
import pymongo
from dotenv import load_dotenv

load_dotenv()

# ─── Config ──────────────────────────────────────────────────────────────────
MONGO_URI       = os.getenv("MONGO_URI")
DB_NAME         = os.getenv("MONGO_DB_NAME")
COLLECTION_NAME = "maven_metadata"

INDEX_BASE     = "https://repo1.maven.org/maven2/.index"
PROPS_URL      = f"{INDEX_BASE}/nexus-maven-repository-index.properties"
FULL_INDEX_URL = f"{INDEX_BASE}/nexus-maven-repository-index.gz"
CHUNK_URL_TPL  = f"{INDEX_BASE}/nexus-maven-repository-index.{{n}}.gz"

STATE_FILE  = Path(__file__).parent / "maven_lucene_state.json"
BATCH_SIZE  = 2_000   # docs to buffer before a MongoDB bulk_write

# Async concurrency knobs (mirror script 2)
LICENSE_CONCURRENCY    = 20
POM_BASE_URL           = "https://repo1.maven.org/maven2"
POM_TIMEOUT            = 20
LICENSE_MAX_RETRIES    = 2
POM_PARENT_MAX_DEPTH   = 5
LICENSE_CACHE_MAX_SIZE = 100_000
VERSION_FALLBACK_LIMIT = 2
BASE_DELAY             = 1.0
MAX_DELAY              = 60.0

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
}

# ─── Validate env ────────────────────────────────────────────────────────────
if not MONGO_URI:
    raise ValueError("MONGO_URI env var is required")
if not DB_NAME:
    raise ValueError("MONGO_DB_NAME env var is required")

# ─── MongoDB ─────────────────────────────────────────────────────────────────
client = pymongo.MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=30_000,
    maxPoolSize=50,
    minPoolSize=5,
    retryWrites=True,
    retryReads=True,
)
collection = client[DB_NAME][COLLECTION_NAME]
print(f"[*] Using Mongo collection: {DB_NAME}.{COLLECTION_NAME}")

# Ensure unique index on package_name
try:
    idx_exists = any(i.get("name") == "package_name" for i in collection.list_indexes())
    if not idx_exists:
        print("[*] Creating unique index on 'package_name'…")
        collection.create_index("package_name", unique=True)
        print("[+] Index created.")
    else:
        print("[*] Index already exists.")
except pymongo.errors.OperationFailure as e:
    if e.code == 14031:
        print(f"[!] Disk space too low to create index: {e}")
    else:
        raise

# ─── State helpers ───────────────────────────────────────────────────────────
def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ─── Download helpers ────────────────────────────────────────────────────────
def fetch_bytes(url: str) -> bytes:
    print(f"[*] Downloading {url} …")
    req = urllib.request.Request(url, headers={"User-Agent": "maven-index-fetcher/1.0"})
    with urllib.request.urlopen(req, timeout=300) as r:
        data = r.read()
    print(f"[+] Downloaded {len(data):,} bytes")
    return data


def parse_properties(raw: bytes) -> dict:
    props = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            props[k.strip()] = v.strip()
    return props


# ─── Binary index parser ─────────────────────────────────────────────────────
def _read_utf(stream: io.RawIOBase) -> str | None:
    """Read a Java-style UTF string: 2-byte big-endian length + UTF-8 bytes."""
    length_bytes = stream.read(2)
    if len(length_bytes) < 2:
        return None
    (length,) = struct.unpack(">H", length_bytes)
    data = stream.read(length)
    if len(data) < length:
        return None
    return data.decode("utf-8", errors="replace")


def parse_index_stream(stream: io.RawIOBase):
    """
    Generator — yields one dict per artifact document.

    Maven-indexer header layout (IndexDataWriter):
      1 byte  : index version (currently 1)
      readUTF : index ID
      8 bytes : timestamp (long, big-endian)
    Followed immediately by documents.
    """
    try:
        stream.read(1)          # version byte
        _read_utf(stream)       # index ID
        stream.read(8)          # timestamp
    except Exception:
        pass  # fall through and attempt doc reads anyway

    while True:
        flags_byte = stream.read(1)
        if not flags_byte:
            break

        flags = flags_byte[0]
        if flags == 0:
            continue  # end-of-doc sentinel between documents — skip

        doc: dict[str, str] = {}
        current_flags = flags

        while current_flags != 0:
            name  = _read_utf(stream)
            value = _read_utf(stream)
            if name is None or value is None:
                break
            doc[name] = value

            next_byte = stream.read(1)
            if not next_byte:
                break
            current_flags = next_byte[0]

        if doc:
            yield doc


# ─── SHA helpers (mirrors calculator_sha.compare) ────────────────────────────
import hashlib


def _compute_sha(obj: dict) -> str:
    """Stable SHA-256 of the serialised object dict."""
    canonical = json.dumps(obj, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _load_existing_sha(package_names: list[str]) -> dict[str, str | None]:
    if not package_names:
        return {}
    result = {}
    for doc in collection.find(
        {"package_name": {"$in": package_names}},
        {"package_name": 1, "sha": 1, "_id": 0},
    ):
        result[doc["package_name"]] = doc.get("sha")
    return result


# ─── Document transform ───────────────────────────────────────────────────────
def raw_to_object(raw: dict) -> dict | None:
    """
    Convert a raw Lucene record to the 'object' sub-document that matches
    the Updated_maven_metadata / Updated_maven2_metadata schema.
    """
    u = raw.get("u", "")
    parts = u.split(":")
    if len(parts) < 2:
        return None

    g = parts[0]
    a = parts[1]
    v = parts[2] if len(parts) > 2 else ""

    if not g or not a:
        return None

    # packaging: prefer the explicit field from 'i', fall back to parts[4]
    i_parts   = raw.get("i", "").split("|")
    packaging = i_parts[0] if i_parts[0] else (parts[4] if len(parts) > 4 else "jar")

    return {
        "g":             g,
        "a":             a,
        "latestVersion": v,
        "repositoryId":  "central",
        "p":             packaging,
        "timestamp":     int(raw.get("m", 0) or 0),
        # licenses filled in later by async POM fetcher
        "licenses":      [],
    }


# ─── Backoff ─────────────────────────────────────────────────────────────────
def _backoff(attempt: int, base: float = BASE_DELAY, cap: float = MAX_DELAY) -> float:
    ceiling = min(cap, base * (2 ** attempt))
    return random.uniform(0.1, ceiling)


# ─── License cache ───────────────────────────────────────────────────────────
_license_cache: Dict[str, list] = {}


def _cache_license(key: str, licenses: list):
    _license_cache[key] = licenses
    if len(_license_cache) > LICENSE_CACHE_MAX_SIZE:
        evict = LICENSE_CACHE_MAX_SIZE // 10
        for k in list(_license_cache.keys())[:evict]:
            del _license_cache[k]


# ─── POM XML helpers (identical to script 2) ─────────────────────────────────
def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def _child(el, name: str):
    for c in list(el):
        if _strip_ns(c.tag) == name:
            return c
    return None


def _resolve_prop(raw: str, props: dict, project_ver: str) -> str:
    v = (raw or "").strip()
    if not v or "${" not in v:
        return v
    if v.startswith("${") and v.endswith("}"):
        key = v[2:-1].strip()
        if key in ("project.version", "pom.version", "version"):
            return project_ver or ""
        return props.get(key, "")
    return ""


def _pom_url(g: str, a: str, v: str) -> str:
    return f"{POM_BASE_URL}/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom"


def _metadata_url(g: str, a: str) -> str:
    return f"{POM_BASE_URL}/{g.replace('.', '/')}/{a}/maven-metadata.xml"


def _parse_pom(xml_text: str) -> Tuple[list, Optional[Tuple[str, str, str]]]:
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
                    if tag in ("name", "url", "comments", "distribution"):
                        entry[tag] = val
                if entry:
                    licenses.append(entry)

        proj_ver = ""
        ver_el = _child(root, "version")
        if ver_el is not None and ver_el.text:
            proj_ver = ver_el.text.strip()

        props   = {}
        props_el = _child(root, "properties")
        if props_el is not None:
            for p in list(props_el):
                k = _strip_ns(p.tag)
                v = (p.text or "").strip()
                if k and v:
                    props[k] = v

        parent_el = _child(root, "parent")
        if parent_el is not None:
            pg = pa = pv = ""
            for c in list(parent_el):
                t   = _strip_ns(c.tag)
                val = (c.text or "").strip()
                if t == "groupId":    pg = val
                elif t == "artifactId": pa = val
                elif t == "version":    pv = val
            pv = _resolve_prop(pv, props, proj_ver)
            if pg and pa and pv:
                parent_gav = (pg, pa, pv)

    except ET.ParseError:
        pass
    return licenses, parent_gav


async def _fetch_versions(session: aiohttp.ClientSession, g: str, a: str, semaphore) -> list[str]:
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

        versions = [
            v_el.text.strip()
            for v_el in list(versions_el)
            if _strip_ns(v_el.tag) == "version" and v_el.text
        ]
        versions.reverse()
        return versions
    except Exception:
        return []


async def fetch_license_from_pom(
    session, g: str, a: str, version: str, semaphore,
    depth: int = 0, visited: set | None = None,
) -> list:
    if not version:
        return []

    cache_key = f"{g}:{a}:{version}"
    cached    = _license_cache.get(cache_key)
    if cached is not None:
        return cached

    if visited is None:
        visited = set()
    if cache_key in visited:
        return []
    visited.add(cache_key)

    url = _pom_url(g, a, version)

    for attempt in range(LICENSE_MAX_RETRIES):
        text = None
        try:
            async with semaphore:
                async with session.get(
                    url, headers=HEADERS,
                    timeout=aiohttp.ClientTimeout(total=POM_TIMEOUT),
                ) as resp:
                    if resp.status == 200:
                        text = await resp.text(encoding="utf-8", errors="replace")
                    elif resp.status in (404, 410):
                        _cache_license(cache_key, [])
                        return []
                    elif resp.status == 429:
                        await asyncio.sleep(_backoff(attempt, base=5.0))
                        continue
                    elif resp.status in (500, 502, 503, 504):
                        await asyncio.sleep(_backoff(attempt))
                        continue
                    else:
                        _cache_license(cache_key, [])
                        return []
        except (asyncio.TimeoutError, aiohttp.ClientError):
            await asyncio.sleep(_backoff(attempt))
            continue
        except Exception:
            _cache_license(cache_key, [])
            return []

        if text is None:
            continue

        licenses, parent_gav = _parse_pom(text)
        if licenses:
            _cache_license(cache_key, licenses)
            return licenses

        if depth < POM_PARENT_MAX_DEPTH and parent_gav:
            parent_licenses = await fetch_license_from_pom(
                session, parent_gav[0], parent_gav[1], parent_gav[2],
                semaphore, depth + 1, visited,
            )
            _cache_license(cache_key, parent_licenses)
            return parent_licenses

        _cache_license(cache_key, [])
        return []

    _cache_license(cache_key, [])
    return []


async def fetch_license_with_fallback(
    session, g: str, a: str, primary_version: str, semaphore,
) -> list:
    licenses = await fetch_license_from_pom(session, g, a, primary_version, semaphore)
    if licenses or VERSION_FALLBACK_LIMIT <= 0:
        return licenses

    all_versions = await _fetch_versions(session, g, a, semaphore)
    tried        = {primary_version}
    for version in all_versions[:VERSION_FALLBACK_LIMIT]:
        if version in tried:
            continue
        tried.add(version)
        licenses = await fetch_license_from_pom(session, g, a, version, semaphore)
        if licenses:
            return licenses

    return []


async def fetch_licenses_batch(session, items: list[dict], semaphore) -> dict[str, list]:
    """
    items: list of dicts with keys g, a, latestVersion
    Returns: {"{g}:{a}": [license, …]}
    """
    tasks    = {}
    key_list = []

    for item in items:
        g = item.get("g", "")
        a = item.get("a", "")
        v = (item.get("latestVersion") or "").strip()
        if not (g and a and v):
            continue
        key = f"{g}:{a}"
        if key not in tasks:
            tasks[key] = fetch_license_with_fallback(session, g, a, v, semaphore)
            key_list.append(key)

    if not key_list:
        return {}

    results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)
    return {
        key: ([] if isinstance(r, Exception) else r)
        for key, r in zip(key_list, results_list)
    }


# ─── MongoDB flush ────────────────────────────────────────────────────────────
async def flush_to_mongo_async(loop, ops: list):
    if not ops:
        return 0, 0
    try:
        result = await loop.run_in_executor(
            None,
            functools.partial(collection.bulk_write, ops, ordered=False),
        )
        return result.upserted_count, result.modified_count
    except pymongo.errors.BulkWriteError as bwe:
        for err in bwe.details.get("writeErrors", []):
            if err.get("code") != 11000:
                print(f"  [!] Write error: {err}")
        return bwe.details.get("nUpserted", 0), bwe.details.get("nModified", 0)
    except Exception as e:
        print(f"  [!] DB error: {e}")
        return 0, 0


# ─── Process a batch of raw Lucene records ────────────────────────────────────
async def process_batch(
    raw_batch: list[dict],
    session: aiohttp.ClientSession,
    license_semaphore,
    loop,
    current_time: datetime,
    counter: dict,
    is_incremental: bool,
) -> None:
    """
    1. Build object dicts
    2. SHA-compare against existing Mongo docs
    3. Fetch licenses async
    4. Bulk-upsert
    """
    # ── handle deletes (incremental only) ──────────────────────────────────
    if is_incremental:
        delete_keys = []
        surviving   = []
        for raw in raw_batch:
            if "del" in raw:
                pkg = raw.get("u", "").rsplit(":", 3)[0]
                if pkg:
                    delete_keys.append(pkg)
            else:
                surviving.append(raw)
        if delete_keys:
            collection.delete_many({"package_name": {"$in": delete_keys}})
            counter["deleted"] += len(delete_keys)
        raw_batch = surviving

    if not raw_batch:
        return

    # ── build object dicts ─────────────────────────────────────────────────
    items = []        # list of (package_name, object_dict)
    for raw in raw_batch:
        obj = raw_to_object(raw)
        if obj is None:
            continue
        pkg = f"{obj['g']}:{obj['a']}"
        items.append((pkg, obj))

    if not items:
        return

    # ── SHA compare ────────────────────────────────────────────────────────
    pkg_names    = [pkg for pkg, _ in items]
    existing_sha = await loop.run_in_executor(None, _load_existing_sha, pkg_names)

    to_insert  = []   # (pkg, obj) — new docs
    to_update  = []   # (pkg, obj) — changed docs
    # skipped ones just don't get appended

    for pkg, obj in items:
        new_sha  = _compute_sha(obj)
        old_sha  = existing_sha.get(pkg)
        if old_sha is None:
            to_insert.append((pkg, obj, new_sha))
        elif old_sha != new_sha:
            to_update.append((pkg, obj, new_sha))
        else:
            counter["skipped"] += 1

    counter["total"]    += len(to_insert) + len(to_update)
    counter["inserted"] += len(to_insert)
    counter["updated"]  += len(to_update)

    to_process = to_insert + to_update
    if not to_process:
        return

    # ── async license fetch ────────────────────────────────────────────────
    license_items = [obj for _, obj, _ in to_process]
    license_map   = await fetch_licenses_batch(session, license_items, license_semaphore)

    # ── build Mongo ops ────────────────────────────────────────────────────
    ops = []
    for pkg, obj, new_sha in to_process:
        obj_with_licenses         = dict(obj)
        obj_with_licenses["licenses"] = license_map.get(pkg, [])

        payload: dict = {
            "package_name": pkg,
            "sha":          new_sha,
            "object":       obj_with_licenses,
        }

        # only stamp updated_time on changes, not on first insert
        is_update = existing_sha.get(pkg) is not None
        if is_update:
            payload["updated_time"] = current_time

        ops.append(pymongo.UpdateOne(
            {"package_name": pkg},
            {"$set": payload},
            upsert=True,
        ))

    await flush_to_mongo_async(loop, ops)

    lic_found = sum(1 for v in license_map.values() if v)
    print(
        f"  [*] batch ins={len(to_insert):,} upd={len(to_update):,} "
        f"skip={counter['skipped']:,} "
        f"lic={lic_found:,}/{len(to_process):,}",
        end="\r",
    )


# ─── Process one gzipped index file ──────────────────────────────────────────
async def process_gz_data(
    gz_data: bytes,
    session: aiohttp.ClientSession,
    license_semaphore,
    loop,
    current_time: datetime,
    counter: dict,
    is_incremental: bool,
) -> None:
    decompressed = gzip.decompress(gz_data)
    stream       = io.BytesIO(decompressed)

    batch: list[dict] = []
    seen:  set[str]   = set()

    for raw in parse_index_stream(stream):
        # dedup within the same file (full index can have duplicate g:a entries)
        u     = raw.get("u", "")
        parts = u.split(":")
        if len(parts) < 2:
            continue
        key = f"{parts[0]}:{parts[1]}"
        if key in seen:
            counter["dupes"] = counter.get("dupes", 0) + 1
            continue
        seen.add(key)

        batch.append(raw)

        if len(batch) >= BATCH_SIZE:
            await process_batch(batch, session, license_semaphore, loop, current_time, counter, is_incremental)
            batch.clear()
            print(
                f"\n  [*] Progress — total={counter['total']:,} "
                f"ins={counter['inserted']:,} upd={counter['updated']:,} "
                f"skip={counter['skipped']:,} del={counter['deleted']:,}"
            )

    if batch:
        await process_batch(batch, session, license_semaphore, loop, current_time, counter, is_incremental)


# ─── License backfill (mirrors script 2) ─────────────────────────────────────
async def backfill_empty_licenses(
    session: aiohttp.ClientSession,
    license_semaphore,
    loop,
    batch_size: int = 200,
) -> dict:
    """Patch existing Mongo docs that still have no license data."""
    query = {
        "$or": [
            {"object.licenses": {"$exists": False}},
            {"object.licenses": {"$size": 0}},
        ]
    }
    projection = {
        "package_name":         1,
        "object.g":             1,
        "object.a":             1,
        "object.latestVersion": 1,
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
        await flush_to_mongo_async(loop, ops)
        stats["updated"] += len(ops)
        pending_docs.clear()
        pending_names.clear()

    try:
        for db_doc in cursor:
            stats["candidates"] += 1
            obj      = db_doc.get("object") or {}
            g        = obj.get("g")
            a        = obj.get("a")
            v        = (obj.get("latestVersion") or "").strip()
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


# ─── Main async worker ────────────────────────────────────────────────────────
async def worker():
    current_time = datetime.now(timezone.utc)
    loop         = asyncio.get_running_loop()
    counter      = {
        "total": 0, "inserted": 0, "updated": 0, "skipped": 0,
        "deleted": 0, "dupes": 0,
    }

    state = load_state()

    # ── fetch properties ────────────────────────────────────────────────────
    props        = parse_properties(fetch_bytes(PROPS_URL))
    latest_chunk = int(props.get("nexus.index.last-incremental", 0))
    chain_id     = props.get("nexus.index.chain-id", "")
    print(f"[+] Latest incremental chunk: {latest_chunk}, chain-id: {chain_id}")

    last_chunk    = state.get("last_chunk", 0)
    last_chain_id = state.get("chain_id", "")

    license_semaphore = asyncio.Semaphore(LICENSE_CONCURRENCY)
    connector = aiohttp.TCPConnector(
        limit=LICENSE_CONCURRENCY * 3,
        limit_per_host=20,
        ttl_dns_cache=300,
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        if last_chain_id != chain_id:
            print("[*] Chain ID changed — downloading FULL index (this may take a while)…")
            gz_data = fetch_bytes(FULL_INDEX_URL)
            await process_gz_data(gz_data, session, license_semaphore, loop, current_time, counter, is_incremental=False)
            save_state({"last_chunk": latest_chunk, "chain_id": chain_id})

        elif last_chunk >= latest_chunk:
            print("[+] Already up-to-date — nothing to do.")

        else:
            chunks = list(range(last_chunk + 1, latest_chunk + 1))
            print(f"[*] Fetching {len(chunks)} incremental chunk(s): {chunks}")
            for n in chunks:
                url     = CHUNK_URL_TPL.format(n=n)
                gz_data = fetch_bytes(url)
                print(f"[*] Processing chunk {n}…")
                await process_gz_data(gz_data, session, license_semaphore, loop, current_time, counter, is_incremental=True)
            save_state({"last_chunk": latest_chunk, "chain_id": chain_id})

        # ── backfill licenses for any pre-existing docs ─────────────────────
        print("\n[*] Backfilling missing/empty licenses in existing Mongo docs…")
        backfill_stats = await backfill_empty_licenses(session, license_semaphore, loop)
        print(
            "[+] License backfill complete: "
            f"candidates={backfill_stats['candidates']:,} "
            f"processable={backfill_stats['processable']:,} "
            f"updated={backfill_stats['updated']:,} "
            f"resolved_non_empty={backfill_stats['resolved_non_empty']:,}"
        )

    print("\n" + "=" * 40)
    print("[+] LUCENE INDEX IMPORT SUMMARY")
    print(f"  total    = {counter['total']:,}")
    print(f"  inserted = {counter['inserted']:,}")
    print(f"  updated  = {counter['updated']:,}")
    print(f"  skipped  = {counter['skipped']:,}")
    print(f"  deleted  = {counter['deleted']:,}")
    print(f"  dupes    = {counter['dupes']:,}")
    print("=" * 40)


# ─── Entry point ─────────────────────────────────────────────────────────────
def main():
    try:
        asyncio.run(worker())
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")


if __name__ == "__main__":
    main()