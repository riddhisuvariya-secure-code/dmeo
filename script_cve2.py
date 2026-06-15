"""
cve_fetch_to_db.py
==================
Fetches ALL CVE data from the NVD API v2.0 and stores everything in SQLite.

Just run:
    python cve_fetch_to_db.py

Optional flags:
    --db PATH          SQLite file path       (default: cve_data.db)
    --no-epss          Skip EPSS enrichment   (faster)
    --year YYYY        Only fetch a specific year (e.g. --year 2024)
    --debug            Verbose logging

Environment variable (optional, gives 10x higher NVD rate limit):
    NVD_API_KEY=your_key python cve_fetch_to_db.py

Database tables:
    cves            – core CVE record (id, description, severity, cvss, status …)
    cve_cwes        – CWE weakness IDs per CVE
    cve_references  – reference URLs per CVE
    cve_packages    – affected CPE vendor/product/version ranges per CVE
    cve_epss        – EPSS exploit probability score + percentile per CVE

NVD total CVE count is ~250 000+. Without an API key expect ~8-10 hours.
With a free NVD API key the same run takes ~30-45 minutes.
Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NVD_API_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE  = "https://api.first.org/data/v1/epss"
USER_AGENT     = "cve-fetch-to-db/2.0"
DEFAULT_DB     = "cve_data.db"

NVD_PAGE_SIZE      = 2000   # NVD maximum per request
NVD_THROTTLE_S     = 6.0    # without API key: ~10 req/min allowed
NVD_THROTTLE_KEY_S = 0.6    # with API key:    ~100 req/min allowed

EPSS_BATCH_SIZE = 100
EPSS_THROTTLE_S = 0.3

# NVD CVE database starts from 1999
NVD_START_YEAR = 1999

# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _get(url: str, *, timeout: int = 60, max_retries: int = 5) -> requests.Response:
    headers = {"User-Agent": USER_AGENT}
    wait = 6.0
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
        except requests.exceptions.RequestException as exc:
            if attempt == max_retries:
                raise
            logger.warning("Request error (%s). Retry %d/%d in %.0fs …", exc, attempt, max_retries, wait)
            time.sleep(wait)
            wait = min(wait * 2, 60)
            continue

        if r.status_code == 429:
            retry_after = float(r.headers.get("Retry-After", wait))
            logger.warning("Rate-limited (429). Sleeping %.0fs …", retry_after)
            time.sleep(retry_after)
            continue

        if r.status_code >= 500:
            logger.warning("Server error %d. Retry %d/%d in %.0fs …", r.status_code, attempt, max_retries, wait)
            time.sleep(wait)
            wait = min(wait * 2, 60)
            continue

        r.raise_for_status()
        return r

    r.raise_for_status()
    return r  # unreachable

# ---------------------------------------------------------------------------
# NVD data extractors
# ---------------------------------------------------------------------------

def _safe_float(v: Any) -> Optional[float]:
    try:
        return float(v) if v is not None else None
    except Exception:
        return None


def _extract_cvss(cve: Dict[str, Any]) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        m = entries[0] or {}
        cvss_data = m.get("cvssData") or {}
        score    = _safe_float(cvss_data.get("baseScore"))
        vector   = cvss_data.get("vectorString")
        severity = m.get("baseSeverity")
        if severity is None and score is not None:
            if score >= 9.0:   severity = "CRITICAL"
            elif score >= 7.0: severity = "HIGH"
            elif score >= 4.0: severity = "MEDIUM"
            elif score >= 0.1: severity = "LOW"
            else:              severity = "NONE"
        return severity, score, vector
    return None, None, None


def _extract_cwes(cve: Dict[str, Any]) -> List[str]:
    result: List[str] = []
    for item in (cve.get("problemtype") or {}).get("problemtype_data") or []:
        for desc in item.get("description") or []:
            text = (desc.get("value") or "").strip()
            if re.match(r"^CWE-\d+", text, re.IGNORECASE):
                cwe = text.upper()
                if cwe not in result:
                    result.append(cwe)
    return result


def _extract_references(cve: Dict[str, Any]) -> List[Dict[str, str]]:
    seen: set = set()
    refs = []
    for r in cve.get("references") or []:
        url = (r or {}).get("url", "")
        if url and url not in seen:
            seen.add(url)
            tags   = ",".join((r or {}).get("tags") or [])
            source = (r or {}).get("source", "")
            refs.append({"url": url, "tags": tags, "source": source})
    return refs


def _parse_version_range(cm: Dict[str, Any]) -> str:
    def n(v: Any) -> str:
        if v is None: return ""
        s = str(v).strip()
        return s[1:] if s.lower().startswith("v") else s

    si = n(cm.get("versionStartIncluding"))
    sx = n(cm.get("versionStartExcluding"))
    ei = n(cm.get("versionEndIncluding"))
    ex = n(cm.get("versionEndExcluding"))
    fv = n(cm.get("version"))

    if si and ex: return f">={si},<{ex}"
    if si and ei: return f">={si},<={ei}"
    if sx and ex: return f">{sx},<{ex}"
    if sx and ei: return f">{sx},<={ei}"
    if ex:        return f"<{ex}"
    if ei:        return f"<={ei}"
    if si:        return f">={si}"
    if sx:        return f">{sx}"
    if fv and fv not in ("*", "-"): return f"=={fv}"
    return "*"


def _extract_packages(cve: Dict[str, Any]) -> List[Dict[str, str]]:
    packages: List[Dict[str, str]] = []
    seen: set = set()
    configs = cve.get("configurations") or []
    if isinstance(configs, dict):
        configs = configs.get("nodes") or []

    def walk(nodes: Any) -> None:
        for node in nodes or []:
            if not isinstance(node, dict):
                continue
            for cm in node.get("cpeMatch") or []:
                uri   = cm.get("cpe23Uri") or ""
                parts = uri.split(":")
                if len(parts) < 6:
                    continue
                vendor        = parts[3]
                product       = parts[4]
                version_range = _parse_version_range(cm)
                vulnerable    = cm.get("vulnerable", True)
                key = (vendor, product, version_range)
                if key not in seen:
                    seen.add(key)
                    packages.append({
                        "vendor": vendor,
                        "product": product,
                        "version_range": version_range,
                        "cpe23uri": uri,
                        "vulnerable": "1" if vulnerable else "0",
                    })
            walk(node.get("nodes") or [])

    walk(configs)
    return packages

# ---------------------------------------------------------------------------
# NVD fetcher  (auto-paginated, year-by-year to stay within 120-day window)
# ---------------------------------------------------------------------------

def _nvd_throttle() -> float:
    return NVD_THROTTLE_KEY_S if os.environ.get("NVD_API_KEY", "").strip() else NVD_THROTTLE_S


def _build_nvd_url(params: Dict[str, str]) -> str:
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    qs = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    if api_key:
        qs += f"&apiKey={quote(api_key)}"
    return f"{NVD_API_BASE}?{qs}"


def fetch_nvd_year(year: int) -> List[Dict[str, Any]]:
    """Fetch all CVEs published in `year` by paginating through NVD."""
    throttle  = _nvd_throttle()
    all_cves: List[Dict[str, Any]] = []
    start = 0

    pub_start = f"{year}-01-01T00:00:00.000"
    pub_end   = f"{year}-12-31T23:59:59.999"

    while True:
        time.sleep(throttle)
        params = {
            "pubStartDate":   pub_start,
            "pubEndDate":     pub_end,
            "resultsPerPage": str(NVD_PAGE_SIZE),
            "startIndex":     str(start),
        }
        url = _build_nvd_url(params)
        logger.info("  NVD year=%d startIndex=%d …", year, start)

        data  = _get(url).json()
        total = int(data.get("totalResults") or 0)
        vulns = data.get("vulnerabilities") or []

        for v in vulns:
            cve = v.get("cve") if isinstance(v, dict) else None
            if isinstance(cve, dict):
                all_cves.append(cve)

        logger.info("    fetched %d  |  running total %d / %d", len(vulns), len(all_cves), total)
        start += NVD_PAGE_SIZE
        if start >= total or not vulns:
            break

    return all_cves


def fetch_all_nvd(year_filter: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Fetch every CVE from NVD.
    If year_filter is given, only that year is fetched.
    Otherwise fetches from NVD_START_YEAR up to the current year.
    """
    current_year = datetime.now(timezone.utc).year
    years = [year_filter] if year_filter else list(range(NVD_START_YEAR, current_year + 1))

    all_cves: List[Dict[str, Any]] = []
    for year in years:
        logger.info("Fetching CVEs for year %d …", year)
        cves = fetch_nvd_year(year)
        all_cves.extend(cves)
        logger.info("Year %d done — %d CVEs fetched so far", year, len(all_cves))

    return all_cves

# ---------------------------------------------------------------------------
# EPSS fetcher
# ---------------------------------------------------------------------------

def fetch_epss_batch(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    total = len(cve_ids)
    for i in range(0, total, EPSS_BATCH_SIZE):
        batch = cve_ids[i : i + EPSS_BATCH_SIZE]
        time.sleep(EPSS_THROTTLE_S)
        url = f"{EPSS_API_BASE}?cve={','.join(quote(c) for c in batch)}&envelope=true&pretty=false"
        try:
            data = _get(url).json()
            for item in data.get("data") or []:
                cid = item.get("cve", "")
                try:
                    results[cid] = {
                        "score":      float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                        "date":       item.get("date", ""),
                    }
                except Exception:
                    pass
        except Exception as exc:
            logger.warning("EPSS batch %d-%d failed: %s", i, i + len(batch), exc)

        if (i // EPSS_BATCH_SIZE) % 20 == 0:
            logger.info("  EPSS progress: %d / %d CVEs", min(i + EPSS_BATCH_SIZE, total), total)

    logger.info("EPSS fetched: %d scores", len(results))
    return results

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DDL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT,
    published       TEXT,
    last_modified   TEXT,
    severity        TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    source_id       TEXT,
    vuln_status     TEXT,
    fetched_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cve_cwes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id  TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    cwe_id  TEXT NOT NULL,
    UNIQUE(cve_id, cwe_id)
);

CREATE TABLE IF NOT EXISTS cve_references (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id  TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    url     TEXT NOT NULL,
    source  TEXT,
    tags    TEXT,
    UNIQUE(cve_id, url)
);

CREATE TABLE IF NOT EXISTS cve_packages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id        TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    vendor        TEXT,
    product       TEXT,
    version_range TEXT,
    cpe23uri      TEXT,
    vulnerable    TEXT,
    UNIQUE(cve_id, cpe23uri)
);

CREATE TABLE IF NOT EXISTS cve_epss (
    cve_id      TEXT PRIMARY KEY REFERENCES cves(cve_id) ON DELETE CASCADE,
    epss_score  REAL,
    percentile  REAL,
    epss_date   TEXT,
    updated_at  TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cves_severity   ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_published  ON cves(published);
CREATE INDEX IF NOT EXISTS idx_cves_score      ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_pkgs_product    ON cve_packages(product);
CREATE INDEX IF NOT EXISTS idx_pkgs_vendor     ON cve_packages(vendor);
"""


def init_db(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(path, check_same_thread=False)
    con.executescript(DDL)
    con.commit()
    logger.info("Database ready: %s", path)
    return con


def upsert_cve(con: sqlite3.Connection, cve: Dict[str, Any]) -> None:
    cve_id = str(cve.get("id") or cve.get("cveId") or "").strip()
    if not cve_id:
        return

    description = ""
    for d in cve.get("descriptions") or []:
        if (d.get("lang") or "").lower() == "en":
            description = (d.get("value") or "").strip()
            break

    published     = cve.get("published")
    last_modified = cve.get("lastModified")
    source_id     = cve.get("sourceIdentifier", "")
    vuln_status   = cve.get("vulnStatus", "")

    severity, score, vector = _extract_cvss(cve)
    cwes     = _extract_cwes(cve)
    refs     = _extract_references(cve)
    packages = _extract_packages(cve)

    with con:
        con.execute(
            """
            INSERT INTO cves
                (cve_id, description, published, last_modified,
                 severity, cvss_score, cvss_vector, source_id, vuln_status)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description   = excluded.description,
                published     = excluded.published,
                last_modified = excluded.last_modified,
                severity      = excluded.severity,
                cvss_score    = excluded.cvss_score,
                cvss_vector   = excluded.cvss_vector,
                source_id     = excluded.source_id,
                vuln_status   = excluded.vuln_status,
                fetched_at    = datetime('now')
            """,
            (cve_id, description, published, last_modified,
             severity, score, vector, source_id, vuln_status),
        )
        for cwe in cwes:
            con.execute(
                "INSERT OR IGNORE INTO cve_cwes (cve_id, cwe_id) VALUES (?,?)",
                (cve_id, cwe),
            )
        for ref in refs:
            con.execute(
                "INSERT OR IGNORE INTO cve_references (cve_id, url, source, tags) VALUES (?,?,?,?)",
                (cve_id, ref["url"], ref.get("source", ""), ref.get("tags", "")),
            )
        for pkg in packages:
            con.execute(
                """
                INSERT OR IGNORE INTO cve_packages
                    (cve_id, vendor, product, version_range, cpe23uri, vulnerable)
                VALUES (?,?,?,?,?,?)
                """,
                (cve_id, pkg["vendor"], pkg["product"],
                 pkg["version_range"], pkg["cpe23uri"], pkg["vulnerable"]),
            )


def upsert_epss(con: sqlite3.Connection, epss_map: Dict[str, Dict[str, Any]]) -> None:
    with con:
        for cve_id, data in epss_map.items():
            con.execute(
                """
                INSERT INTO cve_epss (cve_id, epss_score, percentile, epss_date)
                VALUES (?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    epss_score = excluded.epss_score,
                    percentile = excluded.percentile,
                    epss_date  = excluded.epss_date,
                    updated_at = datetime('now')
                """,
                (cve_id, data.get("score"), data.get("percentile"), data.get("date", "")),
            )

# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def print_summary(db_path: str) -> None:
    con = sqlite3.connect(db_path)
    rows = {
        "CVEs":               con.execute("SELECT COUNT(*) FROM cves").fetchone()[0],
        "CWE records":        con.execute("SELECT COUNT(*) FROM cve_cwes").fetchone()[0],
        "Reference URLs":     con.execute("SELECT COUNT(*) FROM cve_references").fetchone()[0],
        "Package/CPE rows":   con.execute("SELECT COUNT(*) FROM cve_packages").fetchone()[0],
        "EPSS records":       con.execute("SELECT COUNT(*) FROM cve_epss").fetchone()[0],
    }
    sev = con.execute(
        "SELECT severity, COUNT(*) FROM cves GROUP BY severity ORDER BY COUNT(*) DESC"
    ).fetchall()
    con.close()

    width = 44
    print("\n" + "=" * width)
    print("  NVD → SQLite  |  Summary")
    print("=" * width)
    for label, count in rows.items():
        print(f"  {label:<22} {count:>10,}")
    print("-" * width)
    print("  Severity breakdown:")
    for s, c in sev:
        print(f"    {(s or 'UNKNOWN'):<20} {c:>10,}")
    print("=" * width)
    print(f"  Database file: {db_path}")
    print("=" * width + "\n")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Fetch ALL NVD CVEs and store in SQLite. Just run: python cve_fetch_to_db.py",
    )
    p.add_argument("--db",      default=DEFAULT_DB, metavar="PATH",
                   help=f"SQLite database path (default: {DEFAULT_DB})")
    p.add_argument("--year",    type=int, metavar="YYYY",
                   help="Only fetch CVEs from this year (e.g. --year 2024)")
    p.add_argument("--no-epss", action="store_true",
                   help="Skip EPSS enrichment (faster run)")
    p.add_argument("--debug",   action="store_true",
                   help="Enable verbose debug logging")
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    has_key = bool(os.environ.get("NVD_API_KEY", "").strip())
    logger.info("=" * 50)
    logger.info("NVD CVE Fetcher")
    logger.info("  API key   : %s", "YES (fast mode)" if has_key else "NO  (slow mode ~8-10h)")
    logger.info("  Database  : %s", args.db)
    logger.info("  EPSS      : %s", "disabled" if args.no_epss else "enabled")
    logger.info("  Year      : %s", args.year or f"{NVD_START_YEAR}–{datetime.now().year} (all)")
    logger.info("=" * 50)

    # Step 1 – fetch all CVEs from NVD
    all_cves = fetch_all_nvd(year_filter=args.year)
    logger.info("Total CVEs fetched: %d", len(all_cves))

    # Step 2 – deduplicate
    seen: set = set()
    unique_cves: List[Dict[str, Any]] = []
    for c in all_cves:
        cid = str(c.get("id") or c.get("cveId") or "")
        if cid and cid not in seen:
            seen.add(cid)
            unique_cves.append(c)
    logger.info("Unique CVEs after dedup: %d", len(unique_cves))

    # Step 3 – store in DB
    con = init_db(args.db)
    for i, cve in enumerate(unique_cves, 1):
        upsert_cve(con, cve)
        if i % 1000 == 0:
            logger.info("  Stored %d / %d …", i, len(unique_cves))
    logger.info("All CVEs stored.")

    # Step 4 – EPSS enrichment
    if not args.no_epss:
        cve_ids = [str(c.get("id") or c.get("cveId") or "") for c in unique_cves]
        cve_ids = [x for x in cve_ids if x]
        logger.info("Fetching EPSS scores for %d CVEs …", len(cve_ids))
        epss_map = fetch_epss_batch(cve_ids)
        upsert_epss(con, epss_map)

    con.close()
    print_summary(args.db)


if __name__ == "__main__":
    main()