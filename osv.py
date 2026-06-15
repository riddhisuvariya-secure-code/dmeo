import zipfile
import io
import json

OSV_DUMP_BASE = "https://osv-vulnerabilities.storage.googleapis.com"

def ingest_osv(coll: Collection, ecosystems: list[str]) -> None:
    """Download OSV bulk zips per ecosystem (no auth, no pagination issues)."""
    for eco in ecosystems:
        url = f"{OSV_DUMP_BASE}/{eco}/all.zip"
        log.info("OSV ← %s  (%s)", eco, url)
        
        try:
            resp = SESSION.get(url, timeout=120, stream=True)
            if resp.status_code == 404:
                log.warning("  No dump found for ecosystem %s, skipping", eco)
                continue
            resp.raise_for_status()
        except requests.RequestException as exc:
            log.warning("  Failed to download %s: %s", eco, exc)
            continue

        raw = io.BytesIO(resp.content)
        docs = []
        eco_total = 0

        with zipfile.ZipFile(raw) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                with zf.open(name) as f:
                    try:
                        v = json.load(f)
                    except json.JSONDecodeError:
                        continue
                docs.append(_map_osv(v))
                if len(docs) >= MONGO_BATCH:
                    bulk_upsert(coll, docs)
                    eco_total += len(docs)
                    docs = []

        if docs:
            bulk_upsert(coll, docs)
            eco_total += len(docs)

        log.info("  %s: %d records", eco, eco_total)