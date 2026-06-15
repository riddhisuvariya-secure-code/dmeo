"""
CVE checker helper for SBOM scanner.

Fetches CVE details from NVD (CVE v2.0 JSON API) using a best-effort
virtual CPE match string derived from SBOM dependency data.

Optionally enriches each CVE with EPSS score + percentile (FIRST EPSS API).
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

# NVD is heavily rate-limited without an API key; keep requests modest.
DEFAULT_USER_AGENT = "sbom-cve-checker/1.0"


def _sanitize_cpe_component(value: str) -> str:
    """
    Sanitize vendor/product/version components to reduce invalid CPE characters.
    This is best-effort only; NVD virtual matches are probabilistic anyway.
    """ 
    if value is None:
        return "*"
    vv = str(value).strip()
    if not vv:
        return "*"

    # Remove leading '@' for scoped npm packages (e.g. @angular/core).
    if vv.startswith("@"):
        vv = vv[1:]

    # Replace common delimiters that break the CPE tokenization.
    vv = vv.replace("/", "-").replace(":", "-").replace(" ", "-")

    # Convert remaining unsupported chars to '-'.
    vv = re.sub(r"[^a-zA-Z0-9._+\-]", "-", vv)
    vv = vv.strip("-")
    return vv or "*"


def build_virtual_match_string(dep: Dict[str, Any]) -> Optional[str]:
    """
    Build a best-effort CPE 2.3 URI for virtual matching in NVD.

    We derive CPE components from SBOM extracted dependency fields:
      - dep["packageManager"]: ecosystem key (pypi/npm/maven/gradle/go)
      - dep["moduleName"]: package name or group:artifact or go module path
      - dep["versionInfo"]: detected version
    """
    package_manager = str(dep.get("packageManager") or "").strip().lower()
    module_name = str(dep.get("moduleName") or "").strip()
    version = str(dep.get("versionInfo") or "").strip()

    if not package_manager or not module_name or not version:
        return None

    # Normalize some common "v1.2.3" patterns.
    if version.lower().startswith("v"):
        version = version[1:]
    version = version.strip()
    if not version:
        return None

    # Determine part: "a" (application) for most packages.
    part = "a"

    if package_manager in {"npm", "pypi"}:
        vendor = "*"
        product = _sanitize_cpe_component(module_name)
        cpe_version = _sanitize_cpe_component(version)
    elif package_manager in {"maven", "gradle"}:
        # SBOM encodes as "group:artifact"
        if ":" not in module_name:
            return None
        group, artifact = module_name.split(":", 1)
        vendor = _sanitize_cpe_component(group)
        product = _sanitize_cpe_component(artifact)
        cpe_version = _sanitize_cpe_component(version)
    elif package_manager in {"go", "golang"}:
        # go module import path: "github.com/org/repo/pkg"
        # We map product to the last path segment (vendor unknown).
        product = _sanitize_cpe_component(module_name.split("/")[-1])
        vendor = "*"
        cpe_version = _sanitize_cpe_component(version)
    else:
        return None

    return f"cpe:2.3:{part}:{vendor}:{product}:{cpe_version}:*:*:*:*:*:*:*"


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(str(value))
    except Exception:
        return None


def _extract_cve_dates(cve: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    published = cve.get("published")
    last_modified = cve.get("lastModified")
    return published, last_modified


def _extract_cvss(cve: Dict[str, Any]) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    """
    Returns (severity, score, vector).
    """
    metrics = cve.get("metrics") or {}
    # Prefer v3.1 then v3.0 then v2.
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key) or []
        if not entries:
            continue
        metric = entries[0] or {}
        cvss = metric.get("cvssData") or {}
        vector = cvss.get("vectorString")
        score = cvss.get("baseScore")
        severity = metric.get("baseSeverity")

        try:
            score_f = float(score) if score is not None else None
        except Exception:
            score_f = None

        if severity is None and score_f is not None:
            # Fallback severity mapping from CVSS base score.
            if score_f >= 9.0:
                severity = "CRITICAL"
            elif score_f >= 7.0:
                severity = "HIGH"
            elif score_f >= 4.0:
                severity = "MEDIUM"
            elif score_f >= 0.1:
                severity = "LOW"
            else:
                severity = "NONE"

        return severity, score_f, vector

    return None, None, None


def _extract_cwe(cve: Dict[str, Any]) -> List[str]:
    """
    Extract CWE IDs from NVD problemtype.
    """
    result: List[str] = []
    problemtype_data = (cve.get("problemtype") or {}).get("problemtype_data") or []
    for item in problemtype_data:
        for desc in item.get("description") or []:
            text = (desc.get("value") or "").strip()
            if text and re.match(r"^CWE-\d+", text, flags=re.IGNORECASE):
                cwe_id = text.upper()
                if cwe_id not in result:
                    result.append(cwe_id)
    return result


def _extract_references(cve: Dict[str, Any]) -> List[str]:
    refs = cve.get("references") or []
    urls: List[str] = []
    for r in refs:
        url = (r or {}).get("url")
        if url and url not in urls:
            urls.append(url)
    return urls


def _parse_cpe23_uri(cpe23_uri: str) -> Optional[Dict[str, str]]:
    """
    Parse a CPE 2.3 URI.
    Returns {'part','vendor','product','version'} or None.
    """
    if not cpe23_uri or not isinstance(cpe23_uri, str):
        return None
    parts = cpe23_uri.split(":")
    # Expected: cpe:2.3:<part>:<vendor>:<product>:<version>:...
    if len(parts) < 6:
        return None
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5],
    }


def _version_range_expression(cpe_match: Dict[str, Any], fallback_version: str) -> str:
    """
    Build a readable range expression from NVD configuration fields.
    Output is a string to match the desired `packages[].versions` shape.
    """
    start_incl = cpe_match.get("versionStartIncluding")
    start_excl = cpe_match.get("versionStartExcluding")
    end_incl = cpe_match.get("versionEndIncluding")
    end_excl = cpe_match.get("versionEndExcluding")

    # Some CVEs specify a fixed version in `version`.
    fixed_version = cpe_match.get("version")

    def _norm(v: Any) -> str:
        if v is None:
            return ""
        vv = str(v).strip()
        if vv.lower().startswith("v"):
            vv = vv[1:]
        return vv

    start_incl_s = _norm(start_incl)
    start_excl_s = _norm(start_excl)
    end_incl_s = _norm(end_incl)
    end_excl_s = _norm(end_excl)
    fixed_version_s = _norm(fixed_version)
    fallback_s = _norm(fallback_version)

    if start_incl_s and end_excl_s:
        return f">={start_incl_s},<{end_excl_s}"
    if start_incl_s and end_incl_s:
        return f">={start_incl_s},<={end_incl_s}"
    if start_excl_s and end_excl_s:
        return f">{start_excl_s},<{end_excl_s}"
    if start_excl_s and end_incl_s:
        return f">{start_excl_s},<={end_incl_s}"

    if end_excl_s and not start_incl_s and not start_excl_s:
        return f"<{end_excl_s}"
    if end_incl_s and not start_incl_s and not start_excl_s:
        return f"<={end_incl_s}"
    if start_incl_s and not end_incl_s and not end_excl_s:
        return f">={start_incl_s}"
    if start_excl_s and not end_incl_s and not end_excl_s:
        return f">{start_excl_s}"

    # Fixed version fallback.
    if fixed_version_s and fixed_version_s not in {"*", "-"}:
        return f"=={fixed_version_s}"
    if fallback_s and fallback_s not in {"*", "-"}:
        return fallback_s
    return "unknown"


def _build_expected_cpe_parts(dep: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Expected subset of CPE fields for matching NVD configuration cpeMatch entries.
    """
    package_manager = str(dep.get("packageManager") or "").strip().lower()
    module_name = str(dep.get("moduleName") or "").strip()

    if not package_manager or not module_name:
        return None

    if package_manager in {"npm", "pypi"}:
        return {"vendor": "*", "product": _sanitize_cpe_component(module_name)}
    if package_manager in {"maven", "gradle"}:
        if ":" not in module_name:
            return None
        group, artifact = module_name.split(":", 1)
        return {"vendor": _sanitize_cpe_component(group), "product": _sanitize_cpe_component(artifact)}
    if package_manager in {"go", "golang"}:
        return {"vendor": "*", "product": _sanitize_cpe_component(module_name.split("/")[-1])}

    return None


def _extract_package_versions_from_cve(cve: Dict[str, Any], dep: Dict[str, Any]) -> str:
    """
    Best-effort extraction of affected version range from NVD configuration blocks.
    """
    expected = _build_expected_cpe_parts(dep)
    if not expected:
        return str(dep.get("versionInfo") or "unknown")

    fallback_version = str(dep.get("versionInfo") or "unknown")
    configurations = cve.get("configurations") or {}

    # NVD may use `nodes` directly or wrap it differently.
    nodes: Sequence[Dict[str, Any]] = []
    if isinstance(configurations, dict):
        nodes = configurations.get("nodes") or []
    elif isinstance(configurations, list):
        nodes = configurations

    expressions: List[str] = []

    def walk(node_list: Sequence[Dict[str, Any]]) -> None:
        for node in node_list:
            if not isinstance(node, dict):
                continue

            for cpe_match in node.get("cpeMatch") or []:
                if not isinstance(cpe_match, dict):
                    continue
                cpe23_uri = cpe_match.get("cpe23Uri") or ""
                parsed = _parse_cpe23_uri(cpe23_uri)
                if not parsed:
                    continue
                parsed_product = _sanitize_cpe_component(parsed.get("product") or "")
                parsed_vendor = _sanitize_cpe_component(parsed.get("vendor") or "")

                exp_product = expected["product"]
                exp_vendor = expected["vendor"]

                if exp_vendor != "*" and parsed_vendor != exp_vendor:
                    continue
                if parsed_product != exp_product:
                    continue

                expr = _version_range_expression(cpe_match, fallback_version)
                if expr not in expressions:
                    expressions.append(expr)

            # Recurse
            walk(node.get("nodes") or [])

    walk(nodes)

    if not expressions:
        return fallback_version

    # Pick the most "specific-looking" expression (heuristic: shorter first).
    expressions_sorted = sorted(expressions, key=lambda s: (len(s), 0 if "<" in s or ">" in s else 1))
    return expressions_sorted[0]


@dataclass(frozen=True)
class _DepKey:
    ecosystem: str
    package: str
    version: str

    @staticmethod
    def from_dep(dep: Dict[str, Any]) -> Optional["_DepKey"]:
        ecosystem = str(dep.get("packageManager") or "").strip()
        package = str(dep.get("moduleName") or "").strip()
        version = str(dep.get("versionInfo") or "").strip()
        if not ecosystem or not package or not version:
            return None
        return _DepKey(ecosystem=ecosystem, package=package, version=version)


def _throttle_sleep(seconds: float) -> None:
    """
    Centralized sleep to keep the module testable and to adjust later.
    """
    if seconds > 0:
        time.sleep(seconds)


def fetch_nvd_cves_for_virtual_match(
    virtual_match_string: str,
    *,
    results_per_page: int = 50,
    max_pages: int = 1,
    timeout_s: int = 30,
    throttle_s: float = 0.25,
) -> List[Dict[str, Any]]:
    """
    Fetch NVD CVEs using `virtualMatchString`.
    Returns a list of NVD `vulnerability` objects (not yet normalized).
    """
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    vulns: List[Dict[str, Any]] = []

    for page in range(max_pages):
        _throttle_sleep(throttle_s)

        start_index = page * results_per_page
        query_parts = [
            f"virtualMatchString={quote(virtual_match_string)}",
            f"resultsPerPage={results_per_page}",
            f"startIndex={start_index}",
        ]
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        if api_key:
            query_parts.append(f"apiKey={quote(api_key)}")
        url = f"{NVD_API_BASE}?{'&'.join(query_parts)}"
        attempts = 0
        while True:
            attempts += 1
            r = requests.get(url, headers=headers, timeout=timeout_s)

            if r.status_code == 429:
                # Retry in place (same page/startIndex) rather than skipping.
                retry_after = r.headers.get("Retry-After")
                wait_s = float(retry_after) if retry_after and retry_after.isdigit() else 2.0
                logger.warning("NVD rate-limited (429). Backing off %.1fs", wait_s)
                _throttle_sleep(wait_s)
                if attempts >= 3:
                    r.raise_for_status()
                continue

            r.raise_for_status()
            data = r.json()
            page_vulns = data.get("vulnerabilities") or []
            if not isinstance(page_vulns, list):
                break
            vulns.extend(page_vulns)
            break

        # Stop if the API indicates no further pages.
        total = _safe_int(data.get("totalResults"))
        if total is not None and start_index + results_per_page >= total:
            break

        if not page_vulns:
            break

    return vulns


def _fetch_epss_for_cve(
    cve_id: str,
    *,
    timeout_s: int = 20,
    throttle_s: float = 0.15,
) -> Optional[Dict[str, Any]]:
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    _throttle_sleep(throttle_s)
    url = f"{EPSS_API_BASE}?cve={quote(cve_id)}"
    r = requests.get(url, headers=headers, timeout=timeout_s)
    if r.status_code == 429:
        _throttle_sleep(2.0)
        r = requests.get(url, headers=headers, timeout=timeout_s)
    r.raise_for_status()
    data = r.json()

    if data.get("status") != "ok":
        return None
    epss_data = data.get("data") or {}
    epss_score = epss_data.get("epss")
    percentile = epss_data.get("percentile")
    if epss_score is None or percentile is None:
        return None
    try:
        epss_score_f = float(epss_score)
        percentile_f = float(percentile)
    except Exception:
        return None
    return {"score": epss_score_f, "percentile": percentile_f}


def normalize_nvd_cve(nvd_item: Dict[str, Any], matching_deps: List[Dict[str, Any]], *, include_epss: bool) -> Dict[str, Any]:
    """
    Normalize an NVD CVE `cve` object into the output JSON schema.
    """
    cve_id = nvd_item.get("id") or nvd_item.get("cveId") or ""
    cve_id = str(cve_id).strip()

    # Description: pick English.
    description = ""
    descriptions = (nvd_item.get("descriptions") or []) if isinstance(nvd_item.get("descriptions"), list) else []
    for d in descriptions:
        if (d.get("lang") or "").lower() == "en":
            description = (d.get("value") or "").strip()
            break
    if not description and descriptions:
        description = (descriptions[0].get("value") or "").strip()

    published, last_modified = _extract_cve_dates(nvd_item)
    severity, score, vector = _extract_cvss(nvd_item)
    cwe = _extract_cwe(nvd_item)
    references = _extract_references(nvd_item)

    packages: List[Dict[str, Any]] = []
    seen_pkg_keys: set[Tuple[str, str, str]] = set()
    for dep in matching_deps:
        dep_key = _DepKey.from_dep(dep)
        if not dep_key:
            continue
        versions_expr = _extract_package_versions_from_cve(nvd_item, dep)
        pkg_key = (dep_key.ecosystem, dep_key.package, versions_expr)
        if pkg_key in seen_pkg_keys:
            continue
        seen_pkg_keys.add(pkg_key)
        packages.append(
            {
                "ecosystem": dep_key.ecosystem,
                "package": dep_key.package,
                "versions": versions_expr,
            }
        )

    result: Dict[str, Any] = {
        "cve_id": cve_id,
        "description": description,
        "published": published,
        "last_modified": last_modified,
        "severity": severity or "UNKNOWN",
        "cvss": {"score": score, "vector": vector},
        "cwe": cwe,
        "references": references,
        "packages": packages,
    }

    if include_epss and cve_id:
        epss = _fetch_epss_for_cve(cve_id)
        if epss:
            result["epss"] = epss
        else:
            result["epss"] = {"score": None, "percentile": None}

    return result


def check_cves_for_dependencies(
    dependencies: List[Dict[str, Any]],
    *,
    errors: Optional[List[Dict[str, Any]]] = None,
    include_epss: bool = True,
    max_virtual_matches: int = 20,
    max_cves_total: int = 100,
) -> List[Dict[str, Any]]:
    """
    Main entrypoint: given SBOM dependencies, fetch matching CVEs from NVD
    and return normalized CVE objects in the requested output schema.

    This function is intentionally defensive: it should not break the SBOM scan.
    """
    if errors is None:
        errors = []

    if not dependencies:
        return []

    # Build virtual match strings for dependencies.
    vms_to_deps: Dict[str, List[Dict[str, Any]]] = {}
    virtual_matches: List[str] = []
    for dep in dependencies:
        vms = build_virtual_match_string(dep)
        if not vms:
            continue
        if vms not in vms_to_deps:
            virtual_matches.append(vms)
            vms_to_deps[vms] = []
        vms_to_deps[vms].append(dep)

    # Limit to keep runtime bounded.
    virtual_matches = virtual_matches[:max_virtual_matches]

    cve_objects_cache: Dict[str, Dict[str, Any]] = {}
    cve_id_to_matching_deps: Dict[str, List[Dict[str, Any]]] = {}

    for vms in virtual_matches:
        try:
            logger.info("CVE: querying NVD for virtualMatchString=%s", vms)
            vulns = fetch_nvd_cves_for_virtual_match(vms)
        except Exception as e:
            logger.warning("CVE: NVD query failed: %s", e, exc_info=True)
            errors.append({"virtualMatchString": vms, "error": str(e)})
            continue

        for vuln in vulns:
            cve_obj = vuln.get("cve") if isinstance(vuln, dict) else None
            if not isinstance(cve_obj, dict):
                continue
            cve_id = str(cve_obj.get("id") or "").strip()
            if not cve_id:
                continue

            deps_for_vms = vms_to_deps.get(vms) or []

            if cve_id not in cve_objects_cache:
                cve_objects_cache[cve_id] = cve_obj
                cve_id_to_matching_deps[cve_id] = []

            cve_id_to_matching_deps[cve_id].extend(deps_for_vms)

            # Hard cap to avoid exploding metadata.
            if len(cve_objects_cache) >= max_cves_total:
                break

        if len(cve_objects_cache) >= max_cves_total:
            break

    # Normalize results (with optional EPSS).
    results: List[Dict[str, Any]] = []
    normalized_count = 0
    for cve_id, cve_obj in cve_objects_cache.items():
        matching_deps = cve_id_to_matching_deps.get(cve_id) or []
        if normalized_count >= max_cves_total:
            break

        # Deduplicate deps for package listing.
        dep_seen: set[_DepKey] = set()
        unique_deps: List[Dict[str, Any]] = []
        for dep in matching_deps:
            dk = _DepKey.from_dep(dep)
            if not dk or dk in dep_seen:
                continue
            dep_seen.add(dk)
            unique_deps.append(dep)

        try:
            result = normalize_nvd_cve(cve_obj, unique_deps, include_epss=include_epss)
            results.append(result)
            normalized_count += 1
        except Exception as e:
            logger.warning("CVE: normalization failed for %s: %s", cve_id, e, exc_info=True)
            errors.append({"cve_id": cve_id, "error": str(e)})

    return results

