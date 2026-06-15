#!/usr/bin/env python3
"""
Vulnerability Lake Ingestion Script  —  NO API KEY REQUIRED
Sources:
  1. OSV.dev          — bulk zip download per ecosystem from GCS (no auth)
  2. NVD CVE 2.0 API  — keyless mode: 1 req/6s, max 2000 results/page
  3. FIRST.org EPSS   — no auth needed

Target: MongoDB `vulnerabilities` collection (sbom_scanner db)

Usage:
    pip install pymongo requests
    export MONGO_URI="mongodb://localhost:27017"

    python ingest_vulnerabilities.py --osv                        # OSV only (all default ecosystems)
    python ingest_vulnerabilities.py --nvd --nvd-days 30          # NVD last 30 days
    python ingest_vulnerabilities.py --nvd                        # NVD full (~250k, ~8 hrs keyless)
    python ingest_vulnerabilities.py --epss                       # enrich EPSS scores
    python ingest_vulnerabilities.py --all --nvd-days 30          # recommended first run
    python ingest_vulnerabilities.py --ecosystems Maven,PyPI,npm  # OSV subset
"""

import argparse
import io
import json
import logging
import os
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from pymongo import MongoClient, UpdateOne
from pymongo.collection import Collection

# ── config ────────────────────────────────────────────────────────────────────
MONGO_URI   = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME     = os.getenv("VULN_DB",   "sbom_scanner")
COLL_NAME   = "vulnerabilities"

NVD_BASE      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_DUMP_BASE = "https://osv-vulnerabilities.storage.googleapis.com"   # bulk zip per ecosystem
EPSS_BASE     = "https://api.first.org/data/v1/epss"

# NVD keyless: max 5 requests per 30 s window → safe at 6 s per request
NVD_DELAY     = 6.1
NVD_PAGE_SIZE = 2000   # max allowed
MONGO_BATCH   = 500
EPSS_BATCH    = 100    # FIRST.org accepts up to 100 CVE IDs per call

# Ecosystem names must match GCS bucket paths exactly (spaces are fine; requests URL-encodes them)
# Full list: https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
DEFAULT_ECOSYSTEMS = [
    "Maven", "PyPI", "npm", "Go", "crates.io", "NuGet", "RubyGems",
    "Packagist", "Hex", "Pub", "Alpine", "Debian", "Ubuntu",
    "AlmaLinux", "Rocky Linux", "Red Hat", "openSUSE",
    "GitHub Actions", "OSS-Fuzz", "GIT", "Linux",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "sbom-scanner-vuln-ingest/1.0"})


# ── MongoDB ───────────────────────────────────────────────────────────────────

def get_collection() -> Collection:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    coll = client[DB_NAME][COLL_NAME]
    _ensure_indexes(coll)
    return coll


def _ensure_indexes(coll: Collection) -> None:
    coll.create_index("vuln_id",        unique=True, background=True)
    coll.create_index("affected_purls", background=True)   # multikey
    coll.create_index("affected_cpes",  background=True)   # multikey
    coll.create_index("published_at",   background=True)
    coll.create_index("modified_at",    background=True)
    coll.create_index("epss.score",     background=True)
    log.info("Indexes ensured on %s", coll.full_name)


def bulk_upsert(coll: Collection, docs: list[dict]) -> None:
    if not docs:
        return
    ops = [
        UpdateOne({"vuln_id": d["vuln_id"]}, {"$set": d}, upsert=True)
        for d in docs
    ]
    r = coll.bulk_write(ops, ordered=False)
    log.info(
        "    ↳ upserted=%d  modified=%d  matched=%d",
        r.upserted_count, r.modified_count, r.matched_count,
    )


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _get(url: str, params: dict | None = None, retries: int = 5) -> dict:
    """GET with exponential back-off; respects NVD 429 Retry-After."""
    delay = 2.0
    for attempt in range(retries):
        try:
            resp = SESSION.get(url, params=params, timeout=60)
            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 30))
                log.warning("Rate-limited; sleeping %ds", wait)
                time.sleep(wait)
                continue
            if resp.status_code == 503:
                log.warning("503 from %s; retry in %ds", url, delay)
                time.sleep(delay)
                delay *= 2
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            log.warning("Request error (attempt %d/%d): %s", attempt + 1, retries, exc)
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to GET {url} after {retries} attempts")


def _get_raw(url: str, retries: int = 5, timeout: int = 300) -> bytes:
    """GET raw bytes (for zip downloads) with exponential back-off."""
    delay = 2.0
    for attempt in range(retries):
        try:
            resp = SESSION.get(url, timeout=timeout, stream=True)
            if resp.status_code == 404:
                return b""   # caller interprets empty as "not found"
            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 30))
                log.warning("Rate-limited; sleeping %ds", wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.content
        except requests.RequestException as exc:
            log.warning("Download error (attempt %d/%d): %s", attempt + 1, retries, exc)
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to download {url} after {retries} attempts")


def _post(url: str, payload: dict, retries: int = 5) -> dict:
    delay = 2.0
    for attempt in range(retries):
        try:
            resp = SESSION.post(url, json=payload, timeout=30)
            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 10))
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            log.warning("Request error (attempt %d/%d): %s", attempt + 1, retries, exc)
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to POST {url} after {retries} attempts")


# ── OSV ingestion (bulk zip from GCS) ─────────────────────────────────────────

def ingest_osv(coll: Collection, ecosystems: list[str]) -> None:
    """
    Download the all.zip bulk export for each ecosystem from OSV's GCS bucket.
    No authentication or pagination required — one download per ecosystem.
    Zip URL pattern: https://osv-vulnerabilities.storage.googleapis.com/{ECOSYSTEM}/all.zip
    Full ecosystem list: https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
    """
    for eco in ecosystems:
        url = f"{OSV_DUMP_BASE}/{eco}/all.zip"
        log.info("OSV ← %s  (%s)", eco, url)

        raw = _get_raw(url)
        if not raw:
            log.warning("  No dump found for ecosystem '%s' (404) — skipping", eco)
            continue

        eco_total = 0
        docs: list[dict] = []

        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                names = [n for n in zf.namelist() if n.endswith(".json")]
                log.info("  %s: %d JSON files in zip", eco, len(names))

                for name in names:
                    with zf.open(name) as f:
                        try:
                            v = json.load(f)
                        except json.JSONDecodeError as exc:
                            log.warning("  Skipping malformed JSON %s: %s", name, exc)
                            continue

                    docs.append(_map_osv(v))

                    if len(docs) >= MONGO_BATCH:
                        bulk_upsert(coll, docs)
                        eco_total += len(docs)
                        docs = []

        except zipfile.BadZipFile as exc:
            log.error("  Bad zip for ecosystem '%s': %s", eco, exc)
            continue

        # flush remainder
        if docs:
            bulk_upsert(coll, docs)
            eco_total += len(docs)

        log.info("  %s: %d records ingested", eco, eco_total)


def _map_osv(v: dict) -> dict:
    purls: list[str] = []
    cpes:  list[str] = []

    for affected in v.get("affected", []):
        pkg       = affected.get("package", {})
        ecosystem = pkg.get("ecosystem", "")
        name      = pkg.get("name", "")
        purl      = pkg.get("purl", "")

        if purl:
            purls.append(purl)
        elif ecosystem and name:
            purls.append(f"pkg:{ecosystem.lower()}/{name}")

        # some OSV records embed CPEs inside database_specific
        db_spec = affected.get("database_specific", {})
        for val in db_spec.values():
            if isinstance(val, str) and val.startswith("cpe:"):
                cpes.append(val)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item.startswith("cpe:"):
                        cpes.append(item)

    aliases = v.get("aliases", [])
    vuln_id = next((a for a in aliases if a.startswith("CVE-")), v["id"])

    return {
        "vuln_id":        vuln_id,
        "osv_id":         v["id"],
        "aliases":        aliases,
        "summary":        v.get("summary", ""),
        "details":        v.get("details", ""),
        "affected_purls": _dedup(purls),
        "affected_cpes":  _dedup(cpes),
        "published_at":   _parse_dt(v.get("published")),
        "modified_at":    _parse_dt(v.get("modified")),
        "cvss":           _osv_cvss(v),
        "cwes":           _osv_cwes(v),
        "epss":           {},
        "source":         "osv",
        "raw_osv":        v,
        "_ingested_at":   _now(),
    }


def _osv_cvss(v: dict) -> dict:
    cvss: dict[str, Any] = {}
    for sev in v.get("severity", []):
        vec   = sev.get("score", "")
        stype = sev.get("type", "")
        entry = {"vector": vec, "base_score": _parse_cvss_score(vec)}
        if "CVSS_V3" in stype:
            cvss["v3"] = entry
        elif "CVSS_V2" in stype:
            cvss["v2"] = entry
    return cvss


def _osv_cwes(v: dict) -> list[dict]:
    cwes = []
    seen: set[str] = set()
    for ref in v.get("references", []):
        url = ref.get("url", "")
        if "cwe" in url.lower():
            cwe_id = url.rstrip("/").split("/")[-1].upper()
            if cwe_id not in seen:
                seen.add(cwe_id)
                cwes.append({"id": cwe_id, "name": "", "source": "osv_ref"})
    return cwes


# ── NVD ingestion (keyless) ────────────────────────────────────────────────────

def ingest_nvd(coll: Collection, days_back: int | None = None) -> None:
    """
    Keyless NVD pull.  Rate limit: 5 req / 30 s → we sleep 6.1 s between pages.
    Full corpus (~250k CVEs, ~125 pages) takes roughly 13 minutes of wall time.
    Use --nvd-days to limit to a recent window for faster incremental runs.
    """
    params: dict[str, Any] = {
        "resultsPerPage": NVD_PAGE_SIZE,
        "startIndex":     0,
    }

    if days_back:
        now   = datetime.now(timezone.utc)
        start = now - timedelta(days=days_back)
        params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"]   = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        log.info("NVD ← last %d days (keyless, ~%.0fs/page)", days_back, NVD_DELAY)
    else:
        log.info("NVD ← full pull (keyless, ~%.0fs/page — this will take a while)", NVD_DELAY)

    total_fetched = 0
    while True:
        body  = _get(NVD_BASE, params)
        items = body.get("vulnerabilities", [])
        if not items:
            break

        docs = [_map_nvd(item["cve"]) for item in items]
        bulk_upsert(coll, docs)
        total_fetched += len(docs)

        total_results = body.get("totalResults", 0)
        log.info("  NVD progress: %d / %d", total_fetched, total_results)

        if total_fetched >= total_results:
            break

        params["startIndex"] += NVD_PAGE_SIZE
        time.sleep(NVD_DELAY)   # keyless rate-limit compliance

    log.info("NVD: %d records ingested", total_fetched)


def _map_nvd(cve: dict) -> dict:
    cve_id = cve.get("id", "")

    cpes: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpes.append(match["criteria"])

    desc_en = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )

    cwes: list[dict] = []
    seen_cwes: set[str] = set()
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-") and val not in seen_cwes:
                seen_cwes.add(val)
                cwes.append({"id": val, "name": "", "source": "nvd"})

    return {
        "vuln_id":        cve_id,
        "osv_id":         "",
        "aliases":        [cve_id],
        "summary":        desc_en[:300],
        "details":        desc_en,
        "affected_purls": [],          # NVD doesn't carry purls; OSV merge adds them
        "affected_cpes":  _dedup(cpes),
        "published_at":   _parse_dt(cve.get("published")),
        "modified_at":    _parse_dt(cve.get("lastModified")),
        "cvss":           _nvd_cvss(cve.get("metrics", {})),
        "cwes":           cwes,
        "epss":           {},
        "source":         "nvd",
        "raw_nvd":        cve,
        "_ingested_at":   _now(),
    }


def _nvd_cvss(metrics: dict) -> dict:
    cvss: dict[str, Any] = {}

    for key in ("cvssMetricV31", "cvssMetricV30"):
        items = metrics.get(key, [])
        if items:
            data = items[0].get("cvssData", {})
            cvss["v3"] = {
                "vector":         data.get("vectorString", ""),
                "base_score":     data.get("baseScore"),
                "base_severity":  data.get("baseSeverity", ""),
                "impact_score":   items[0].get("impactScore"),
                "exploitability": items[0].get("exploitabilityScore"),
            }
            break

    items = metrics.get("cvssMetricV2", [])
    if items:
        data = items[0].get("cvssData", {})
        cvss["v2"] = {
            "vector":         data.get("vectorString", ""),
            "base_score":     data.get("baseScore"),
            "base_severity":  items[0].get("baseSeverity", ""),
            "impact_score":   items[0].get("impactScore"),
            "exploitability": items[0].get("exploitabilityScore"),
        }

    return cvss


# ── EPSS enrichment ────────────────────────────────────────────────────────────

def enrich_epss(coll: Collection) -> None:
    """
    FIRST.org EPSS API — no key required.
    Accepts up to 100 CVE IDs per request via ?cve=CVE-X,CVE-Y,...
    """
    log.info("EPSS enrichment starting …")
    cve_ids: list[str] = coll.distinct("vuln_id", {"vuln_id": {"$regex": r"^CVE-"}})
    log.info("  %d CVE IDs to enrich", len(cve_ids))

    fetched_at = _now()
    ops: list[UpdateOne] = []

    for i in range(0, len(cve_ids), EPSS_BATCH):
        chunk  = cve_ids[i : i + EPSS_BATCH]
        params = {"cve": ",".join(chunk)}
        try:
            body = _get(EPSS_BASE, params)
            data = body.get("data", [])
        except Exception as exc:
            log.warning("EPSS batch %d skipped: %s", i // EPSS_BATCH, exc)
            time.sleep(5)
            continue

        for item in data:
            ops.append(UpdateOne(
                {"vuln_id": item["cve"]},
                {"$set": {"epss": {
                    "score":      float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                    "fetched_at": fetched_at,
                }}},
            ))

        if len(ops) >= MONGO_BATCH:
            coll.bulk_write(ops, ordered=False)
            log.info("  EPSS: %d / %d enriched", i + len(chunk), len(cve_ids))
            ops = []

        time.sleep(0.2)   # EPSS has no published rate limit; be polite

    if ops:
        coll.bulk_write(ops, ordered=False)

    log.info("EPSS enrichment complete")


# ── utilities ─────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dedup(lst: list[str]) -> list[str]:
    return list(dict.fromkeys(lst))


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def _parse_cvss_score(vector: str) -> float | None:
    """Some OSV records embed score as 'CVSS:3.1/AV:N/... (7.5)'."""
    if "(" in vector and ")" in vector:
        try:
            return float(vector[vector.rfind("(") + 1 : vector.rfind(")")])
        except ValueError:
            pass
    return None


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingest vulnerability data into MongoDB (no API key required)"
    )
    parser.add_argument("--osv",   action="store_true", help="Ingest from OSV.dev (bulk zip)")
    parser.add_argument("--nvd",   action="store_true", help="Ingest from NVD (keyless)")
    parser.add_argument("--epss",  action="store_true", help="Enrich with EPSS scores")
    parser.add_argument("--all",   action="store_true", help="Run OSV + NVD + EPSS")
    parser.add_argument(
        "--ecosystems",
        default=",".join(DEFAULT_ECOSYSTEMS),
        help="Comma-separated OSV ecosystems  [default: all major ones]",
    )
    parser.add_argument(
        "--nvd-days",
        type=int,
        default=None,
        metavar="N",
        help="Limit NVD pull to CVEs published in the last N days (faster incremental runs)",
    )
    args = parser.parse_args()

    if not (args.osv or args.nvd or args.epss or args.all):
        parser.print_help()
        return

    try:
        coll = get_collection()
    except Exception as exc:
        log.error("Cannot connect to MongoDB at %s: %s", MONGO_URI, exc)
        raise SystemExit(1)

    ecosystems = [e.strip() for e in args.ecosystems.split(",") if e.strip()]

    if args.all or args.osv:
        ingest_osv(coll, ecosystems)

    if args.all or args.nvd:
        ingest_nvd(coll, days_back=args.nvd_days)

    if args.all or args.epss:
        enrich_epss(coll)

    log.info("Done. Total docs: %d", coll.count_documents({}))


if __name__ == "__main__":
    main()