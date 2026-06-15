"""Probe package totals using the same APIs as script_pypi.py, script_maven.py, script_go.py."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

import requests

# --- PyPI (script_pypi.py: SIMPLE_INDEX_URL + Accept) ---
PYPI_SIMPLE = "https://pypi.org/simple/"


def count_pypi() -> int:
    r = requests.get(
        PYPI_SIMPLE,
        headers={
            "Accept": "application/vnd.pypi.simple.v1+json",
            "User-Agent": "GeminiSec-Importer/3.0",
        },
        timeout=120,
    )
    r.raise_for_status()
    names = [p["name"] for p in r.json().get("projects", [])]
    return len(dict.fromkeys(names))


# --- Maven Solr (script_maven.py: SEARCH_ENDPOINTS + HEADERS + get_num_found params) ---
MAVEN_SOLR_URLS = [
    "https://search.maven.org/solrsearch/select",
    "https://central.sonatype.com/solrsearch/select",
]
MAVEN_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://search.maven.org/",
    "Origin": "https://search.maven.org",
}


def count_maven_solr_numfound() -> tuple[str, int]:
    params = urllib.parse.urlencode({"q": "*:*", "rows": "0", "wt": "json"})
    for base in MAVEN_SOLR_URLS:
        url = f"{base}?{params}"
        req = urllib.request.Request(url, headers=MAVEN_HEADERS)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
            n = int(data.get("response", {}).get("numFound", 0))
            if n:
                return base, n
        except Exception:
            continue
    return "(no endpoint)", 0


# --- Go index (script_go.py: INDEX_URL + INDEX_PAGE_SIZE) ---
GO_INDEX = "https://index.golang.org/index"
GO_LIMIT = 2000


def count_go_index_rows_and_unique_paths() -> tuple[int, int]:
    paths: set[str] = set()
    total_rows = 0
    since = ""

    while True:
        if since:
            q = urllib.parse.urlencode({"since": since, "limit": GO_LIMIT})
        else:
            q = urllib.parse.urlencode({"limit": GO_LIMIT})
        url = f"{GO_INDEX}?{q}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "GeminiSec-Importer/3.0",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        lines = [ln for ln in body.splitlines() if ln.strip()]
        if not lines:
            break

        for line in lines:
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            p, v, ts = o.get("Path"), o.get("Version"), o.get("Timestamp")
            if not p or not v or not ts:
                continue
            total_rows += 1
            paths.add(p)
            since = ts  # same ordering assumption as incremental crawl

        if len(lines) < GO_LIMIT:
            break

    return total_rows, len(paths)


if __name__ == "__main__":
    print("PyPI unique project names:", f"{count_pypi():,}")
    u, n = count_maven_solr_numfound()
    print("Maven Solr numFound (*:*) via", u, ":", f"{n:,}")
    rows, uniq = count_go_index_rows_and_unique_paths()
    print("Go index rows (valid Path/Version/Timestamp):", f"{rows:,}")
    print("Go unique module paths (seen in that scan):", f"{uniq:,}")