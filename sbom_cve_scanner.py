"""
SBOM CVE Scanner
----------------
Scans SBOM packages against your local MongoDB nvd_cves collection
and enriches each package with matching CVEs and CVSS scores.

MongoDB collection expected schema (from your screenshot):
  - cve_id       : "CVE-2000-0388"
  - fetched_at   : "2026-05-28T15:56:21.467+00:00"
  - lastModified : "2026-04-16T00:27:16.627"
  - published    : "1990-05-09T04:00:00.000"
  - raw          : Object  (full NVD raw data, contains cpe matches + CVSS)
  - sha          : "..."

Usage:
  pip install pymongo
  python sbom_cve_scanner.py

  # Or pass a custom SBOM JSON file and MongoDB URI:
  python sbom_cve_scanner.py --sbom my_sbom.json --mongo mongodb://localhost:27017 --out results.json
"""

import json
import argparse
import re
from datetime import datetime
from pymongo import MongoClient
from collections import defaultdict

# ─── Default config ───────────────────────────────────────────────────────────
DEFAULT_MONGO_URI = "mongodb://localhost:27017"
DEFAULT_DB        = "sbom_test"
DEFAULT_COLLECTION = "nvd_cves"

# ─── Sample SBOM (replace with your real data or pass --sbom flag) ────────────
SAMPLE_SBOM = [
    {
        "moduleName": "aiohttp",
        "versionInfo": "3.13.5",
        "sha": "02222e7e233295f40e011c1b00e3b0bd451f22cf853a0304c3595633ee47da4b",
        "sourceLocation": "requirements.txt",
        "packageURL": "https://pypi.org/project/aiohttp/",
        "packageManager": "pypi",
        "licenseConcluded": "Apache-2.0 AND MIT"
    },
    {
        "moduleName": "requests",
        "versionInfo": "2.28.0",
        "sha": "",
        "sourceLocation": "requirements.txt",
        "packageURL": "https://pypi.org/project/requests/",
        "packageManager": "pypi",
        "licenseConcluded": "Apache-2.0"
    },
    {
        "moduleName": "django",
        "versionInfo": "4.2.0",
        "sha": "",
        "sourceLocation": "requirements.txt",
        "packageURL": "https://pypi.org/project/django/",
        "packageManager": "pypi",
        "licenseConcluded": "BSD-3-Clause"
    },
]


# ─── Version comparison helpers ───────────────────────────────────────────────

def parse_version(v: str):
    """Parse a version string into a comparable tuple."""
    v = re.sub(r"[^0-9.]", "", v)  # strip non-numeric chars
    parts = v.split(".")
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    return tuple(result)


def version_in_range(pkg_version: str, version_start_including=None,
                     version_start_excluding=None, version_end_including=None,
                     version_end_excluding=None) -> bool:
    """Check if pkg_version falls within CPE version range."""
    try:
        pv = parse_version(pkg_version)

        if version_start_including:
            if pv < parse_version(version_start_including):
                return False
        if version_start_excluding:
            if pv <= parse_version(version_start_excluding):
                return False
        if version_end_including:
            if pv > parse_version(version_end_including):
                return False
        if version_end_excluding:
            if pv >= parse_version(version_end_excluding):
                return False
        return True
    except Exception:
        return False


# ─── CVSS extraction from raw NVD document ────────────────────────────────────

def extract_cvss(raw: dict) -> dict:
    """
    Extract CVSS v3.1 (preferred), v3.0, or v2.0 score and severity from
    the NVD raw object.
    """
    cvss_info = {"cvssVersion": None, "cvssScore": None, "cvssVector": None, "severity": None}

    metrics = raw.get("metrics", {})

    # Try CVSS v3.1 first
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            cvss_info["cvssVersion"]  = data.get("version")
            cvss_info["cvssScore"]    = data.get("baseScore")
            cvss_info["cvssVector"]   = data.get("vectorString")
            cvss_info["severity"]     = (
                entries[0].get("baseSeverity")          # v3.x
                or data.get("baseSeverity")              # v2
                or entries[0].get("cvssData", {}).get("baseSeverity")
            )
            break

    return cvss_info


# ─── CPE match check ──────────────────────────────────────────────────────────

def cpe_matches_package(cpe_uri: str, pkg_name: str) -> bool:
    try:
        parts = cpe_uri.lower().split(":")
        if len(parts) < 5:
            return False

        product = parts[4]
        pkg = pkg_name.lower()

        candidates = {
            pkg,
            pkg.replace("-", "_"),
            pkg.replace("_", "-"),
            pkg.split(":")[-1]
        }

        return any(c in product for c in candidates)
    except Exception:
        return False

def check_configurations(raw: dict, pkg_name: str, pkg_version: str) -> bool:
    """
    Walk the NVD 'configurations' block and check if the package+version
    matches any CPE node.
    Returns True if a match is found.
    """
    configurations = raw.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for cpe in cpe_matches:
                if not cpe.get("vulnerable", False):
                    continue
                cpe_uri = cpe.get("criteria", "")
                if not cpe_matches_package(cpe_uri, pkg_name):
                    continue

                # Check version range
                vsi = cpe.get("versionStartIncluding")
                vse = cpe.get("versionStartExcluding")
                vei = cpe.get("versionEndIncluding")
                vee = cpe.get("versionEndExcluding")

                # If no version range specified, match all versions
                if not any([vsi, vse, vei, vee]):
                    # Check exact version in CPE URI
                    cpe_parts = cpe_uri.split(":")
                    cpe_version = cpe_parts[5] if len(cpe_parts) > 5 else "*"
                    if cpe_version in ("*", "-", ""):
                        return True
                    if cpe_version.lower() == pkg_version.lower():
                        return True
                else:
                    if version_in_range(pkg_version, vsi, vse, vei, vee):
                        return True
    return False


# ─── Main scanner ─────────────────────────────────────────────────────────────

def scan_sbom(sbom_packages: list, mongo_uri: str, db_name: str, collection_name: str) -> list:
    """
    For each SBOM package, query MongoDB for CVEs that reference it,
    then return the enriched package list.
    """
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    db     = client[db_name]
    coll   = db[collection_name]

    print(f"[*] Connected to MongoDB: {mongo_uri} / {db_name}.{collection_name}")
    print(f"[*] Total CVE documents: {coll.count_documents({})}")
    print(f"[*] Scanning {len(sbom_packages)} packages...\n")

    enriched = []

    for pkg in sbom_packages:
        pkg_name    = pkg.get("moduleName", "")
        pkg_version = pkg.get("versionInfo", "")

        print(f"   Scanning: {pkg_name}@{pkg_version}")

        # ── Strategy 1: Text search on cve_id / raw description ──────────────
        # We query for documents where the raw JSON likely references the package.
        # MongoDB stores the full NVD raw object, so we use a regex on the
        # serialised CPE criteria field inside raw.configurations.
        #
        # This is a broad first pass; we then verify version ranges in Python.

        query = {
            "raw.cve.configurations.nodes.cpeMatch.criteria": {
                "$regex": re.escape(pkg_name),
                "$options": "i"
            }
        }

        cursor = coll.find(query, {
            "cve_id": 1,
            "published": 1,
            "lastModified": 1,
            "raw.cve.metrics": 1,
            "raw.cve.configurations": 1,
            "raw.cve.descriptions": 1,
            "_id": 0
        })

        matched_cves = []

        for doc in cursor:
            raw = doc.get("raw", {}).get("cve", {})

            # Verify version match
            if not check_configurations(raw, pkg_name, pkg_version):
                continue

            # Extract CVSS
            cvss = extract_cvss(raw)

            # Extract description (English)
            description = ""
            for desc in raw.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            matched_cves.append({
                "cveId":        doc.get("cve_id"),
                "published":    doc.get("published"),
                "lastModified": doc.get("lastModified"),
                "description":  description[:300] + ("..." if len(description) > 300 else ""),
                **cvss
            })

        # Sort by CVSS score descending
        matched_cves.sort(key=lambda x: x.get("cvssScore") or 0, reverse=True)

        # Compute package-level risk summary
        severities   = [c["severity"] for c in matched_cves if c.get("severity")]
        scores       = [c["cvssScore"] for c in matched_cves if c.get("cvssScore")]
        max_score    = max(scores) if scores else None
        max_severity = _highest_severity(severities)

        enriched_pkg = {
            **pkg,
            "cveCount":      len(matched_cves),
            "maxCvssScore":  max_score,
            "maxSeverity":   max_severity,
            "riskLevel":     _risk_label(max_score),
            "cves":          matched_cves
        }

        enriched.append(enriched_pkg)

        status = f"   {len(matched_cves)} CVE(s) found"
        if max_score:
            status += f"  |  Max CVSS: {max_score} ({max_severity})"
        print(status)

    client.close()
    return enriched


def _highest_severity(severities: list) -> str | None:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    ranked = sorted(severities, key=lambda s: order.get(s.upper(), -1), reverse=True)
    return ranked[0].upper() if ranked else None


def _risk_label(score) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


# ─── Report generation ────────────────────────────────────────────────────────

def print_summary(results: list):
    print("\n" + "=" * 70)
    print("  CVE SCAN SUMMARY — PER PACKAGE")
    print("=" * 70)

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}
    results_sorted = sorted(results, key=lambda p: risk_order.get(p.get("riskLevel", "UNKNOWN"), 5))

    for pkg in results_sorted:
        name     = pkg["moduleName"]
        version  = pkg["versionInfo"]
        count    = pkg["cveCount"]
        risk     = pkg.get("riskLevel", "UNKNOWN")
        score    = pkg.get("maxCvssScore")
        severity = pkg.get("maxSeverity", "")

        icon = {"CRITICAL": "-", "HIGH": "-", "MEDIUM": "-", "LOW": "-", "NONE": "-", "UNKNOWN": "-"}.get(risk, "-")

        print(f"\n{icon}  {name}@{version}  [{risk}]")
        if count == 0:
            print("     No CVEs found")
        else:
            print(f"     CVEs: {count}  |  Max CVSS: {score}  ({severity})")
            for cve in pkg["cves"][:5]:  # show top 5
                s = cve.get("cvssScore", "N/A")
                sev = cve.get("severity", "N/A")
                print(f"     • {cve['cveId']:20s}  CVSS: {s}  ({sev})")
            if count > 5:
                print(f"     ... and {count - 5} more")

    print("\n" + "=" * 70)
    total_cves = sum(p["cveCount"] for p in results)
    critical   = sum(1 for p in results if p.get("riskLevel") == "CRITICAL")
    high       = sum(1 for p in results if p.get("riskLevel") == "HIGH")
    print(f"  Total packages : {len(results)}")
    print(f"  Total CVEs     : {total_cves}")
    print(f"  Critical pkgs  : {critical}")
    print(f"  High pkgs      : {high}")
    print("=" * 70 + "\n")


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SBOM CVE Scanner using MongoDB NVD data")
    parser.add_argument("--sbom",  default=None,           help="Path to SBOM JSON file (list of package objects)")
    parser.add_argument("--mongo", default=DEFAULT_MONGO_URI, help=f"MongoDB URI (default: {DEFAULT_MONGO_URI})")
    parser.add_argument("--db",    default=DEFAULT_DB,     help=f"Database name (default: {DEFAULT_DB})")
    parser.add_argument("--col",   default=DEFAULT_COLLECTION, help=f"Collection name (default: {DEFAULT_COLLECTION})")
    parser.add_argument("--out",   default="sbom_cve_results.json", help="Output JSON file path")
    args = parser.parse_args()

    # Load SBOM
    if args.sbom:
        with open(args.sbom, "r", encoding="utf-8") as f:
            sbom = json.load(f)

        if isinstance(sbom, dict) and "packages" in sbom:
            sbom = sbom["packages"]
            print(f"[*] Loaded SBOM from: {args.sbom}")
    else:
        sbom = SAMPLE_SBOM
        print("[*] Using built-in sample SBOM (pass --sbom <file> to use your own)")

    # Run scan
    results = scan_sbom(sbom, args.mongo, args.db, args.col)

    # Print summary
    print_summary(results)

    # Save enriched results
    output = {
        "scanDate": datetime.utcnow().isoformat() + "Z",
        "packageCount": len(results),
        "totalCVEs": sum(p["cveCount"] for p in results),
        "packages": results
    }

    with open(args.out, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Full results saved to: {args.out}")


if __name__ == "__main__":
    main()