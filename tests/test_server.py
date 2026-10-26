from __future__ import annotations

import json
import pathlib
import sys
import threading
import time
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import server  # noqa: E402


class RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake = str(ROOT / "tests" / "fake_tool.py")
        for tool in server.TOOLS:
            server.COMMAND_OVERRIDES[tool] = [sys.executable, fake, tool]
        server.JOBS = server.JobStore()
        cls.httpd = server.create_server(0)
        cls.port = cls.httpd.server_address[1]
        cls.url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.status = cls.request("GET", "/api/status")
        cls.token = cls.status["token"]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    @classmethod
    def request(cls, method, path, body=None, token=None, origin=True):
        data = json.dumps(body).encode() if body is not None else None
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["X-Nmap-Studio-Token"] = token
        if origin:
            headers["Origin"] = cls.url
        request = urllib.request.Request(cls.url + path, data=data, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def wait_for_job(self, job_id):
        deadline = time.time() + 5
        while time.time() < deadline:
            value = self.request("GET", f"/api/jobs/{job_id}", token=self.token)
            if value["done"]:
                return value
            time.sleep(0.05)
        self.fail("job did not finish")

    def test_status_reports_dynamic_tools_and_security_headers(self):
        request = urllib.request.Request(self.url + "/api/status")
        with urllib.request.urlopen(request, timeout=5) as response:
            value = json.load(response)
            self.assertEqual(value["version"], server.VERSION)
            self.assertTrue(value["tools"]["nmap"]["installed"])
            self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_run_captures_output_and_structured_report(self):
        created = self.request(
            "POST", "/api/run",
            {"tool": "nmap", "args": ["-sT", "-T3", "127.0.0.1"], "safeMode": True},
            self.token,
        )
        job = self.wait_for_job(created["id"])
        self.assertEqual(job["code"], 0)
        self.assertIn("tool=nmap", job["output"])
        self.assertEqual(job["report"]["hosts"][0]["ports"][0]["service"], "http")

    def test_advanced_mode_requires_explicit_confirmation(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request(
                "POST", "/api/run",
                {"tool": "nmap", "args": ["--script", "test"], "safeMode": False},
                self.token,
            )
        self.assertEqual(caught.exception.code, 400)
        caught.exception.close()

    def test_safe_mode_rejects_advanced_option(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request(
                "POST", "/api/run",
                {"tool": "nmap", "args": ["--script", "test", "127.0.0.1"], "safeMode": True},
                self.token,
            )
        self.assertEqual(caught.exception.code, 400)
        caught.exception.close()

    def test_bad_token_and_missing_origin_are_rejected(self):
        for token, origin in (("bad", True), (self.token, False)):
            with self.subTest(token=token, origin=origin):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    self.request(
                        "POST", "/api/run",
                        {"tool": "nmap", "args": ["127.0.0.1"], "safeMode": True},
                        token, origin,
                    )
                self.assertEqual(caught.exception.code, 403)
                caught.exception.close()

    def test_argument_limits_and_nul_rejection(self):
        with self.assertRaises(server.ValidationError):
            server.validate_args("nmap", ["x"] * (server.MAX_ARGS + 1), True, False)
        with self.assertRaises(server.ValidationError):
            server.validate_args("nmap", ["bad\x00value"], True, False)

    def test_output_and_completed_job_retention_are_bounded(self):
        job = server.Job("nmap", [], True)
        job.append(b"x" * (server.MAX_OUTPUT_BYTES + 100))
        self.assertLessEqual(len(job.snapshot()["output"].encode()), server.MAX_OUTPUT_BYTES)
        store = server.JobStore()
        for _ in range(server.MAX_COMPLETED_JOBS + 5):
            item = server.Job("nmap", [], True)
            item.finish(0)
            store.add(item)
        store._prune_locked()
        self.assertEqual(len(store._jobs), server.MAX_COMPLETED_JOBS)

    def test_xml_allows_nmap_doctype_and_rejects_custom_doctypes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "scan.xml"
            path.write_text(
                '<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>'
                '<runstats><finished summary="done"/></runstats></nmaprun>',
                encoding="utf-8",
            )
            self.assertEqual(server.parse_nmap_report(path)["summary"], "done")
            path.write_text(
                '<!DOCTYPE nmaprun [<!ENTITY x "unsafe">]><nmaprun/>',
                encoding="utf-8",
            )
            with self.assertRaises(server.ValidationError):
                server.parse_nmap_report(path)

    def test_job_store_queues_after_running_limit(self):
        store = server.JobStore()
        with mock.patch.object(server, "run_job", lambda job: None):
            jobs = [server.Job("nmap", ["127.0.0.1"], True, f"Scan {index}", "Lab") for index in range(3)]
            for item in jobs:
                store.add(item)
        self.assertEqual([item.state for item in jobs], ["running", "running", "queued"])
        listed = store.list()
        queued = next(item for item in listed if item["state"] == "queued")
        self.assertEqual(queued["queuePosition"], 1)

    def test_nse_risk_enforcement_in_safe_mode(self):
        scripts = [
            {"name": "http-title", "categories": ["safe", "discovery"], "risk": "safe"},
            {"name": "ftp-brute", "categories": ["intrusive", "brute"], "risk": "advanced"},
        ]
        with mock.patch.object(server, "discover_scripts", return_value=scripts):
            server.validate_args("nmap", ["--script", "http-title", "127.0.0.1"], True, False)
            with self.assertRaises(server.ValidationError):
                server.validate_args("nmap", ["--script", "ftp-brute", "127.0.0.1"], True, False)


if __name__ == "__main__":
    unittest.main()
