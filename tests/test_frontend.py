import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FrontendTests(unittest.TestCase):
    def test_csp_compatible_markup(self):
        html = (ROOT / "dist" / "index.html").read_text(encoding="utf-8")
        app = (ROOT / "dist" / "app.js").read_text(encoding="utf-8")
        css = (ROOT / "dist" / "style.css").read_text(encoding="utf-8")
        self.assertNotIn("onclick=", html)
        self.assertNotIn("@import", css)

    def test_security_controls_are_exposed(self):
        app = (ROOT / "dist" / "app.js").read_text(encoding="utf-8")
        for value in ("safeMode", "persistHistory", "/api/shutdown", "/api/diagnostics", "/api/jobs", "compareReports", "rowsToCSV", "riskLabel",
                      "/api/workspace/assets", "/api/workspace/findings", "/api/workspace/schedule", "/api/workspace/scope", "/api/enrichment/refresh", "sarif"):
            self.assertIn(value, app)


if __name__ == "__main__":
    unittest.main()
