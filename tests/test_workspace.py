from __future__ import annotations

import pathlib
import tempfile
import time
import types
import unittest

from workspace import Workspace

ROOT = pathlib.Path(__file__).resolve().parents[1]


def report(version="1.0", extra_port=False):
    ports = [{
        "port": "443", "protocol": "tcp", "state": "open", "service": "https",
        "product": "Example Server", "version": version, "confidence": 10,
        "cpes": [f"cpe:/a:example:server:{version}"], "cves": ["CVE-2026-12345"],
    }]
    if extra_port:
        ports.append({"port": "22", "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9", "cpes": [], "cves": []})
    return {"hosts": [{"address": "10.20.30.40", "hostname": "app.local", "mac": "00:11:22:33:44:55", "state": "up", "ports": ports}], "hostCount": 1, "portCount": len(ports), "summary": "done"}


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.workspace = Workspace(pathlib.Path(self.temp.name) / "studio.db")

    def tearDown(self):
        self.temp.cleanup()

    def job(self, job_id, value, finished=None):
        return types.SimpleNamespace(id=job_id, schedule_id=None, name="Baseline", project="Lab", report=value, finished=finished or time.time())

    def test_inventory_findings_and_drift_are_persistent(self):
        self.workspace.persist_scan(self.job("one", report()))
        self.workspace.persist_scan(self.job("two", report("2.0", True), time.time() + 1))
        self.workspace.persist_scan(self.job("three", report("2.0"), time.time() + 2))
        assets = self.workspace.assets()
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["open_ports"], 1)
        self.assertEqual(assets[0]["service_count"], 2)
        findings = self.workspace.findings()
        self.assertEqual(findings[0]["cve"], "CVE-2026-12345")
        kinds = {item["kind"] for item in self.workspace.alerts()}
        self.assertIn("new-service", kinds)
        self.assertIn("changed-service", kinds)

    def test_scope_allowlist_and_deny_precedence(self):
        self.workspace.add_scope_rule("Prod", "10.0.0.0/8", "allow", "CHG-42", "")
        self.workspace.add_scope_rule("Prod", "10.9.*", "deny", "Excluded segment", "")
        self.assertTrue(self.workspace.check_scope("Prod", ["10.1.2.3"])["allowed"])
        self.assertFalse(self.workspace.check_scope("Prod", ["192.168.1.2"])["allowed"])
        self.assertFalse(self.workspace.check_scope("Prod", ["10.9.1.2"])["allowed"])
        with self.assertRaises(ValueError):
            self.workspace.add_scope_rule("Prod", "10.0.0.0/8", "allow", "expired", "2000-01-01")

    def test_hash_chained_audit_detects_tampering(self):
        self.workspace.audit("first", {"value": 1})
        self.workspace.audit("second", {"value": 2})
        self.assertTrue(self.workspace.verify_audit()["valid"])
        with self.workspace._connect() as connection:
            connection.execute("UPDATE audit SET details_json='{}' WHERE id=1")
        self.assertFalse(self.workspace.verify_audit()["valid"])

    def test_schedule_and_exports(self):
        schedule = self.workspace.add_schedule("Daily", "Lab", "nmap", ["-sT", "10.0.0.1"], 60)
        self.assertEqual(self.workspace.schedules()[0]["args"], ["-sT", "10.0.0.1"])
        self.workspace.set_schedule(schedule["id"], False)
        self.assertEqual(self.workspace.schedules()[0]["enabled"], 0)
        self.workspace.persist_scan(self.job("export", report()))
        self.assertIn('"version": "2.1.0"', self.workspace.export("sarif")[1])
        self.assertIn("CVE-2026-12345", self.workspace.export("defectdojo")[1])
        self.assertIn('"type":"asset"', self.workspace.export("splunk")[1])

    def test_intelligence_preserves_provider_fields(self):
        self.workspace.upsert_intelligence([{"cve": "CVE-2026-12345", "severity": "high", "kev": True, "description": "Known exploited"}])
        self.workspace.upsert_intelligence([{"cve": "CVE-2026-12345", "epss": 0.82}])
        self.workspace.persist_scan(self.job("intel", report()))
        finding = self.workspace.findings()[0]
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["kev"], 1)
        self.assertAlmostEqual(finding["epss"], 0.82)


if __name__ == "__main__":
    unittest.main()
