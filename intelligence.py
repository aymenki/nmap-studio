"""Optional, explicitly triggered public vulnerability intelligence enrichment."""
from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from typing import Any

USER_AGENT = "Nmap-Studio/0.4.1 (+https://github.com/aymenki/nmap-studio)"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESPONSE = 8 * 1024 * 1024


def fetch_json(url: str, timeout: int = 20) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        length = int(response.headers.get("Content-Length", "0") or 0)
        if length > MAX_RESPONSE:
            raise ValueError("Intelligence response exceeded the size limit")
        data = response.read(MAX_RESPONSE + 1)
    if len(data) > MAX_RESPONSE:
        raise ValueError("Intelligence response exceeded the size limit")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("Intelligence provider returned invalid JSON")
    return value


def _severity(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            return str(entries[0].get("cvssData", {}).get("baseSeverity") or entries[0].get("baseSeverity") or "unknown").lower()
    return "unknown"


def _description(cve: dict) -> str:
    descriptions = cve.get("descriptions") or []
    english = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
    return english[:4000]


def _keyword(service: dict) -> str:
    cpes = service.get("cpes") or []
    if cpes:
        pieces = str(cpes[0]).split(":")
        if len(pieces) >= 5:
            return " ".join(piece for piece in pieces[3:5] if piece and piece != "*")
    return " ".join(filter(None, [str(service.get("product", "")), str(service.get("version", ""))])).strip()


def refresh(workspace: Any, progress: dict) -> dict:
    """Enrich existing CVEs and create cautious NVD keyword candidates."""
    progress.update({"state": "running", "stage": "Downloading CISA KEV", "completed": 0, "total": 3, "error": ""})
    kev_payload = fetch_json(KEV_URL)
    kev_records = {}
    for item in kev_payload.get("vulnerabilities", []):
        cve = str(item.get("cveID", "")).upper()
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            kev_records[cve] = {
                "cve": cve, "kev": True,
                "description": str(item.get("shortDescription", "")),
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
    workspace.upsert_intelligence(list(kev_records.values()))
    progress.update({"stage": "Downloading FIRST EPSS", "completed": 1})

    cves = workspace.cves()
    epss_records = []
    for start in range(0, len(cves), 100):
        batch = cves[start:start + 100]
        if not batch:
            continue
        payload = fetch_json(EPSS_URL + "?" + urllib.parse.urlencode({"cve": ",".join(batch)}))
        for item in payload.get("data", []):
            try:
                epss = float(item.get("epss"))
            except (TypeError, ValueError):
                epss = None
            epss_records.append({"cve": item.get("cve", ""), "epss": epss})
    workspace.upsert_intelligence(epss_records)
    progress.update({"stage": "Finding possible CVE matches", "completed": 2})

    candidates = 0
    for service in workspace.services_for_enrichment()[:8]:
        keyword = _keyword(service)
        if len(keyword) < 3:
            continue
        url = NVD_URL + "?" + urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 5})
        try:
            payload = fetch_json(url)
        except Exception:
            continue
        for wrapper in payload.get("vulnerabilities", []):
            cve = wrapper.get("cve", {})
            cve_id = str(cve.get("id", "")).upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                continue
            workspace.add_candidate(
                int(service["id"]), cve_id, _severity(cve), _description(cve),
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
            candidates += 1
        time.sleep(0.7)
    # Re-apply KEV and EPSS after NVD candidates have created findings.
    workspace.upsert_intelligence(list(kev_records.values()) + epss_records)
    result = {"state": "completed", "stage": "Completed", "completed": 3, "total": 3, "candidates": candidates, "cves": len(cves)}
    progress.update(result)
    workspace.audit("intelligence.refresh", {"candidates": candidates, "existingCves": len(cves), "providers": ["CISA KEV", "FIRST EPSS", "NVD"]})
    return result
