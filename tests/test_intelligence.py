from __future__ import annotations

import pathlib
import tempfile
import time
import types
import unittest
from unittest import mock

import intelligence
from workspace import Workspace


ROOT = pathlib.Path(__file__).resolve().parents[1]


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.workspace = Workspace(pathlib.Path(self.temp.name) / "studio.db")
        report = {
            "hosts": [{
                "address": "10.0.0.4", "hostname": "web.lab", "state": "up",
                "ports": [{
                    "port": "443", "protocol": "tcp", "state": "open", "service": "https",
                    "product": "Example Server", "version": "1.0", "confidence": 10,
                    "cpes": ["cpe:/a:example:server:1.0"], "cves": ["CVE-2026-12345"],
                }],
            }],
            "hostCount": 1,
            "portCount": 1,
        }
        job = types.SimpleNamespace(id="intel-scan", schedule_id=None, name="Baseline", project="Lab", report=report, finished=time.time())
        self.workspace.persist_scan(job)

    def tearDown(self):
        self.temp.cleanup()

    def test_refresh_combines_kev_epss_and_possible_nvd_candidates(self):
        def provider(url):
            if url == intelligence.KEV_URL:
                return {"vulnerabilities": [{"cveID": "CVE-2026-12345", "shortDescription": "Known exploited"}]}
            if url.startswith(intelligence.EPSS_URL):
                return {"data": [{"cve": "CVE-2026-12345", "epss": "0.91"}]}
            return {"vulnerabilities": [{"cve": {
                "id": "CVE-2026-99999",
                "descriptions": [{"lang": "en", "value": "Possible keyword match"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
            }}]}

        progress = {}
        with mock.patch.object(intelligence, "fetch_json", side_effect=provider), mock.patch.object(intelligence.time, "sleep"):
            result = intelligence.refresh(self.workspace, progress)

        findings = {item["cve"]: item for item in self.workspace.findings()}
        self.assertEqual(result["state"], "completed")
        self.assertTrue(findings["CVE-2026-12345"]["kev"])
        self.assertAlmostEqual(findings["CVE-2026-12345"]["epss"], 0.91)
        self.assertEqual(findings["CVE-2026-99999"]["confidence"], "possible")
        self.assertEqual(findings["CVE-2026-99999"]["severity"], "critical")
        self.assertEqual(progress["candidates"], 1)


if __name__ == "__main__":
    unittest.main()
