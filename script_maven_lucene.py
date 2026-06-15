"""
Maven Central Lucene Index Parser
===================================
Downloads and parses the Maven Central binary index from:
  https://repo1.maven.org/maven2/.index/

Files:
  nexus-maven-repository-index.properties  — metadata / latest chunk number
  nexus-maven-repository-index.gz          — full index (~500 MB compressed)
  nexus-maven-repository-index.N.gz        — incremental chunk N (delta only)

On first run: download the full index.
On subsequent runs: download only the incremental chunks since the last run,
using the chunk number stored in state.json.

Binary record format (Java DataOutput inside gzip):
  Per document:
    loop:
      1 byte  : field flags (0 = end-of-document, EOF = end-of-file)
      readUTF : field name  (2-byte big-endian length + modified UTF-8)
      readUTF : field value
  Key fields:
    u  = "groupId:artifactId:version:classifier:packaging"
    m  = lastModified (epoch ms as string)
    1  = sha1
    i  = "packaging|lastModified|size|..."
    n  = artifact display name
    d  = description
    del= present when the artifact was DELETED in an incremental chunk
"""

import gzip
import io
import json
import os
import struct
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pymongo
from dotenv import load_dotenv

load_dotenv()

# ─── Config ──────────────────────────────────────────────────────────────────
MONGO_URI       = os.getenv("MONGO_URI")
DB_NAME         = os.getenv("MONGO_DB_NAME")
COLLECTION_NAME = "Updated_maven_metadata"

INDEX_BASE      = "https://repo1.maven.org/maven2/.index"
PROPS_URL       = f"{INDEX_BASE}/nexus-maven-repository-index.properties"
FULL_INDEX_URL  = f"{INDEX_BASE}/nexus-maven-repository-index.gz"
CHUNK_URL_TPL   = f"{INDEX_BASE}/nexus-maven-repository-index.{{n}}.gz"

STATE_FILE      = Path(__file__).parent / "maven_lucene_state.json"
BATCH_SIZE      = 2_000   # docs to buffer before a MongoDB bulk_write

# ─── MongoDB ─────────────────────────────────────────────────────────────────
if not MONGO_URI:
    raise ValueError("MONGO_URI env var is required")
if not DB_NAME:
    raise ValueError("MONGO_DB_NAME env var is required")

client     = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=30_000)
collection = client[DB_NAME][COLLECTION_NAME]
print(f"[*] Using Mongo collection: {DB_NAME}.{COLLECTION_NAME}")


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
    # Java "modified UTF-8": null bytes encoded as 0xC0 0x80 — handle gracefully
    return data.decode("utf-8", errors="replace")


def parse_index_stream(stream: io.RawIOBase):
    """
    Generator that yields one dict per artifact document.
    Skips the Maven index file header automatically.
    """
    # The gzip payload starts with a header block ending at the first
    # full document boundary. We detect it by reading until we find the
    # first valid flags byte that starts a real document.
    #
    # Header structure (maven-indexer IndexDataWriter):
    #   - 1 byte  : index version (currently 1)
    #   - readUTF : index ID string
    #   - 8 bytes : timestamp (long, big-endian)
    # Then documents follow immediately.

    try:
        version = stream.read(1)
        if not version:
            return
        # index ID (UTF)
        _read_utf(stream)
        # timestamp (8 bytes)
        stream.read(8)
    except Exception:
        pass  # if header parsing fails, attempt to read docs anyway

    while True:
        flags_byte = stream.read(1)
        if not flags_byte:
            break  # EOF

        flags = flags_byte[0]
        if flags == 0:
            # end-of-document sentinel with no preceding fields — skip
            continue

        # Start reading fields for this document
        doc: dict[str, str] = {}
        current_flags = flags

        while current_flags != 0:
            name  = _read_utf(stream)
            value = _read_utf(stream)
            if name is None or value is None:
                break
            doc[name] = value

            # Read next flags byte
            next_byte = stream.read(1)
            if not next_byte:
                break
            current_flags = next_byte[0]

        if doc:
            yield doc


# ─── Document transform ───────────────────────────────────────────────────────
def doc_to_mongo(raw: dict, current_time: datetime) -> dict | None:
    """
    Convert a raw index record to a MongoDB document matching the
    existing Updated_maven_metadata schema.

    The 'u' field format: groupId:artifactId:version:classifier:packaging
    We only want the latest-version record per groupId:artifactId,
    which the index marks with a 'latestVersion' field or we derive from 'u'.
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

    package_name = f"{g}:{a}"

    obj = {
        "g":             g,
        "a":             a,
        "latestVersion": v,
        "repositoryId":  "central",
        "p":             parts[4] if len(parts) > 4 else raw.get("i", "").split("|")[0],
        "timestamp":     int(raw.get("m", 0) or 0),
        "licenses":      [],   # licenses still fetched via POM — not in the index
    }

    return {
        "package_name": package_name,
        "object":       obj,
        "updated_time": current_time,
    }


# ─── Flush to MongoDB ─────────────────────────────────────────────────────────
def flush_to_mongo(batch: list[dict], counter: dict):
    if not batch:
        return
    ops = [
        pymongo.UpdateOne(
            {"package_name": doc["package_name"]},
            {"$set": doc},
            upsert=True,
        )
        for doc in batch
    ]
    try:
        result = collection.bulk_write(ops, ordered=False)
        counter["inserted"] += result.upserted_count
        counter["updated"]  += result.modified_count
    except pymongo.errors.BulkWriteError as bwe:
        write_errors = bwe.details.get("writeErrors", [])
        for err in write_errors:
            if err.get("code") != 11000:  # ignore duplicate key
                print(f"  [!] Write error: {err}")
        counter["inserted"] += bwe.details.get("nUpserted", 0)
        counter["updated"]  += bwe.details.get("nModified", 0)


# ─── Process one gzipped index file ──────────────────────────────────────────
def process_gz_data(gz_data: bytes, current_time: datetime, counter: dict, is_incremental: bool):
    decompressed = gzip.decompress(gz_data)
    stream       = io.BytesIO(decompressed)

    batch:    list[dict] = []
    seen:     set[str]   = set()

    for raw in parse_index_stream(stream):
        # Incremental chunks mark deleted artifacts with a 'del' field
        if is_incremental and "del" in raw:
            pkg = raw.get("u", "").rsplit(":", 3)[0]   # g:a
            if pkg:
                collection.delete_one({"package_name": pkg})
                counter["deleted"] = counter.get("deleted", 0) + 1
            continue

        doc = doc_to_mongo(raw, current_time)
        if not doc:
            continue

        pkg = doc["package_name"]
        if pkg in seen:
            counter["dupes"] = counter.get("dupes", 0) + 1
            continue
        seen.add(pkg)

        batch.append(doc)
        counter["total"] += 1

        if len(batch) >= BATCH_SIZE:
            flush_to_mongo(batch, counter)
            batch.clear()
            print(
                f"  [*] Flushed batch — total={counter['total']:,} "
                f"ins={counter['inserted']:,} upd={counter['updated']:,}",
                end="\r",
            )

    flush_to_mongo(batch, counter)


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    current_time = datetime.now(timezone.utc)
    state        = load_state()
    counter      = {"total": 0, "inserted": 0, "updated": 0, "deleted": 0, "dupes": 0}

    # 1. Fetch properties to find latest incremental chunk number
    props       = parse_properties(fetch_bytes(PROPS_URL))
    latest_chunk = int(props.get("nexus.index.last-incremental", 0))
    chain_id     = props.get("nexus.index.chain-id", "")
    print(f"[+] Latest incremental chunk: {latest_chunk}, chain-id: {chain_id}")

    last_chunk    = state.get("last_chunk", 0)
    last_chain_id = state.get("chain_id", "")

    if last_chain_id != chain_id:
        # Chain ID changed means a new full index was published — must re-download
        print("[*] Chain ID changed — downloading FULL index (this may take a while)…")
        gz_data = fetch_bytes(FULL_INDEX_URL)
        process_gz_data(gz_data, current_time, counter, is_incremental=False)
        save_state({"last_chunk": latest_chunk, "chain_id": chain_id})

    elif last_chunk >= latest_chunk:
        print("[+] Already up-to-date — nothing to do.")

    else:
        # Download only the incremental chunks we're missing
        chunks_to_fetch = range(last_chunk + 1, latest_chunk + 1)
        print(f"[*] Fetching {len(chunks_to_fetch)} incremental chunk(s): {list(chunks_to_fetch)}")
        for n in chunks_to_fetch:
            url     = CHUNK_URL_TPL.format(n=n)
            gz_data = fetch_bytes(url)
            print(f"[*] Processing chunk {n}…")
            process_gz_data(gz_data, current_time, counter, is_incremental=True)
        save_state({"last_chunk": latest_chunk, "chain_id": chain_id})

    print("\n" + "=" * 40)
    print("[+] LUCENE INDEX IMPORT SUMMARY")
    print(f"  total    = {counter['total']:,}")
    print(f"  inserted = {counter['inserted']:,}")
    print(f"  updated  = {counter['updated']:,}")
    print(f"  deleted  = {counter['deleted']:,}")
    print(f"  dupes    = {counter['dupes']:,}")
    print("=" * 40)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
