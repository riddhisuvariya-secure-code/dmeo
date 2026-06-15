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
COLLECTION_NAME = "Updated_maven_metadata"

INDEX_BASE     = "https://repo1.maven.org/maven2/.index"
PROPS_URL      = f"{INDEX_BASE}/nexus-maven-repository-index.properties"
FULL_INDEX_URL = f"{INDEX_BASE}/nexus-maven-repository-index.gz"
CHUNK_URL_TPL  = f"{INDEX_BASE}/nexus-maven-repository-index.{{n}}.gz"

STATE_FILE = Path(__file__).parent / "maven_lucene_state.json"


def _resolve_full_index_cache() -> Path:
    """Prefer an existing on-disk full index; otherwise download into project cache."""
    candidates = [
        Path(p) / "nexus-maven-repository-index.gz"
        for p in (
            os.getenv("MAVEN_INDEX_CACHE", ""),
            Path(__file__).parent / "maven_index",
            Path("C:/maven_index"),
        )
        if p
    ]
    for path in candidates:
        if path.exists():
            return path
    return Path(__file__).parent / "maven_index" / "nexus-maven-repository-index.gz"
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
    """Download small files (properties, incremental chunks) fully into memory."""
    print(f"[*] Downloading {url} …")
    req = urllib.request.Request(url, headers={"User-Agent": "maven-index-fetcher/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    print(f"[+] Downloaded {len(data):,} bytes")
    return data


def fetch_large_file(url: str, dest: Path, chunk_size: int = 1024 * 1024) -> Path:
    """
    Stream-download a large file to disk in 1 MB chunks.
    Shows progress and resumes automatically if the file already exists
    and the server supports Range requests.
    Returns the path to the downloaded file.
    """
    print(f"[*] Streaming download: {url}")
    print(f"[*] Saving to: {dest}")

    existing_size = dest.stat().st_size if dest.exists() else 0
    headers = {"User-Agent": "maven-index-fetcher/1.0"}
    if existing_size:
        headers["Range"] = f"bytes={existing_size}-"
        print(f"[*] Resuming from byte {existing_size:,}")

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            # 206 = partial content (resume), 200 = full download
            if existing_size and r.status == 200:
                # Server ignored Range — restart
                existing_size = 0
            dest.parent.mkdir(parents=True, exist_ok=True)
            mode        = "ab" if existing_size else "wb"
            total_read  = existing_size
            content_len = int(r.headers.get("Content-Length", 0) or 0)
            total_size  = existing_size + content_len

            with open(dest, mode) as f:
                while True:
                    chunk = r.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    total_read += len(chunk)
                    if total_size:
                        pct = total_read / total_size * 100
                        print(
                            f"  [*] {total_read / 1_048_576:.1f} MB / "
                            f"{total_size / 1_048_576:.1f} MB  ({pct:.1f}%)",
                            end="\r",
                        )
    except Exception as e:
        print(f"\n[!] Download interrupted: {e}")
        print(f"[*] Partial file kept at {dest} — re-run to resume.")
        raise

    print(f"\n[+] Download complete: {total_read / 1_048_576:.1f} MB → {dest}")
    return dest


def parse_properties(raw: bytes) -> dict:
    props = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            props[k.strip()] = v.strip()
    return props


# ─── Binary index parser ─────────────────────────────────────────────────────
def _read_java_utf(stream: io.RawIOBase) -> str | None:
    """Java DataInput.readUTF — 2-byte length + modified UTF-8."""
    length_bytes = stream.read(2)
    if len(length_bytes) < 2:
        return None
    (length,) = struct.unpack(">H", length_bytes)
    data = stream.read(length)
    if len(data) < length:
        return None
    return data.decode("utf-8", errors="replace")


def _read_index_utf(stream: io.RawIOBase) -> str | None:
    """Maven indexer value encoding — 4-byte big-endian length + UTF-8 bytes."""
    length_bytes = stream.read(4)
    if len(length_bytes) < 4:
        return None
    (length,) = struct.unpack(">i", length_bytes)
    if length < 0:
        return None
    data = stream.read(length)
    if len(data) < length:
        return None
    return data.decode("utf-8", errors="replace")


def parse_index_stream(stream: io.RawIOBase):
    
    if not stream.read(1):
        return
    if len(stream.read(8)) < 8:
        return

    while True:
        count_bytes = stream.read(4)
        if len(count_bytes) < 4:
            break

        (field_count,) = struct.unpack(">i", count_bytes)
        doc: dict[str, str] = {}

        for _ in range(field_count):
            if not stream.read(1):
                return

            name = _read_java_utf(stream)
            value = _read_index_utf(stream)
            if name is None or value is None:
                break
            doc[name] = value

        if doc:
            yield doc


def _split_u_field(u: str) -> list[str]:
    """Maven index stores coordinates pipe-delimited: g|a|v|classifier|packaging."""
    return u.replace(":", "|").split("|")


def _packaging_values(parts: list[str], raw: dict) -> tuple[str, str]:
    u_packaging = parts[4] if len(parts) > 4 else "jar"
    i_packaging = raw.get("i", "").split("|")[0] if raw.get("i") else u_packaging
    return u_packaging, i_packaging or u_packaging


def _is_checksum_packaging(packaging: str) -> bool:
    lowered = packaging.lower()
    return lowered.endswith((".sha256", ".sha512", ".md5")) or lowered in {
        "sha1", "sha256", "sha512", "md5",
    }


def _is_primary_artifact(parts: list[str], raw: dict) -> bool:
    if len(parts) < 2:
        return False

    classifier = parts[3] if len(parts) > 3 else ""
    if classifier not in ("", "NA"):
        return False

    u_packaging, i_packaging = _packaging_values(parts, raw)
    return not (_is_checksum_packaging(u_packaging) or _is_checksum_packaging(i_packaging))


def _artifact_rank(raw: dict) -> tuple[int, int]:
    """Prefer main artifacts (jar/pom) and newer timestamps when deduplicating."""
    parts = _split_u_field(raw.get("u", ""))
    _, packaging = _packaging_values(parts, raw)
    packaging = packaging.lower()
    is_main = 1 if packaging in ("jar", "pom", "war", "ear", "aar", "bundle") else 0
    return is_main, int(raw.get("m", 0) or 0)


def _artifact_package_key(raw: dict) -> tuple[str, tuple[int, int]] | None:
    parts = _split_u_field(raw.get("u", ""))
    if not _is_primary_artifact(parts, raw):
        return None

    g, a = parts[0], parts[1]
    if not g or not a:
        return None

    return f"{g}:{a}", _artifact_rank(raw)


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
    
    parts = _split_u_field(raw.get("u", ""))
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
        "g": g,
        "a":a,
        "latestVersion": v,
        "repositoryId":  "central",
        "p": packaging,
        "timestamp":     int(raw.get("m", 0) or 0),
        # licenses filled in later by async POM fetcher
        "licenses":  [],
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
    
    # ── handle deletes (incremental only) ──────────────────────────────────
    if is_incremental:
        delete_keys = []
        surviving   = []
        for raw in raw_batch:
            if "del" in raw:
                del_parts = _split_u_field(raw.get("u", ""))
                pkg = f"{del_parts[0]}:{del_parts[1]}" if len(del_parts) >= 2 else ""
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
    gz_source: "bytes | Path",
    session: aiohttp.ClientSession,
    license_semaphore,
    loop,
    current_time: datetime,
    counter: dict,
    is_incremental: bool,
) -> None:
    # Support both in-memory bytes (incremental chunks) and on-disk file (full index)
    if isinstance(gz_source, Path):
        stream = gzip.open(gz_source, "rb")          # streaming — no full decompress
    else:
        stream = gzip.open(io.BytesIO(gz_source))    # in-memory bytes

    # Keep the newest primary jar/pom record per group:artifact.
    best_by_pkg: dict[str, tuple[tuple[int, int], dict]] = {}
    parsed_records = 0

    try:
        for raw in parse_index_stream(stream):
            parsed_records += 1
            if parsed_records % 500_000 == 0:
                print(
                    f"\n  [*] Parsed {parsed_records:,} index records, "
                    f"unique packages {len(best_by_pkg):,}",
                    flush=True,
                )

            keyed = _artifact_package_key(raw)
            if keyed is None:
                continue

            pkg_key, rank = keyed
            prev = best_by_pkg.get(pkg_key)
            if prev is not None:
                counter["dupes"] = counter.get("dupes", 0) + 1
                if prev[0] >= rank:
                    continue

            best_by_pkg[pkg_key] = (rank, raw)

        print(
            f"\n  [*] Index parse complete: {parsed_records:,} records, "
            f"{len(best_by_pkg):,} unique packages to sync",
            flush=True,
        )

        batch: list[dict] = []
        for _, raw in best_by_pkg.values():
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
    finally:
        stream.close()


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

    full_index_cache = _resolve_full_index_cache()
    collection_count = collection.estimated_document_count()

    async with aiohttp.ClientSession(connector=connector) as session:
        if last_chain_id != chain_id:
            print("[*] Chain ID changed — downloading FULL index (this may take a while)…")
            gz_path = (
                full_index_cache
                if full_index_cache.exists()
                else fetch_large_file(FULL_INDEX_URL, full_index_cache)
            )
            await process_gz_data(gz_path, session, license_semaphore, loop, current_time, counter, is_incremental=False)
            save_state({"last_chunk": latest_chunk, "chain_id": chain_id})

        elif last_chunk >= latest_chunk and collection_count > 0:
            print("[+] Already up-to-date — nothing to do.")

        elif last_chunk >= latest_chunk and collection_count == 0:
            print("[!] Index state is current but MongoDB collection is empty — re-importing full index…")
            gz_path = (
                full_index_cache
                if full_index_cache.exists()
                else fetch_large_file(FULL_INDEX_URL, full_index_cache)
            )
            print(f"[*] Using full index file: {gz_path}")
            await process_gz_data(gz_path, session, license_semaphore, loop, current_time, counter, is_incremental=False)
            save_state({"last_chunk": latest_chunk, "chain_id": chain_id})

        else:
            chunks = list(range(last_chunk + 1, latest_chunk + 1))
            print(f"[*] Fetching {len(chunks)} incremental chunk(s): {chunks}")
            for n in chunks:
                url     = CHUNK_URL_TPL.format(n=n)
                gz_data = fetch_bytes(url)
                print(f"[*] Processing chunk {n}…")
                await process_gz_data(gz_data, session, license_semaphore, loop, current_time, counter, is_incremental=True)
            save_state({"last_chunk": latest_chunk, "chain_id": chain_id})

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
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(line_buffering=True)
        asyncio.run(worker())
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")


if __name__ == "__main__":
    main()