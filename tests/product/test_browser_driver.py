"""Acceptance tests for Headless Chromium / DOM XSS Driver and SPA Route Discovery (I3)."""

import os
import unittest
from unittest.mock import MagicMock, patch

from packages.scanner_adapters.integrations.browser import (
    BrowserWorkflowError,
    DOMSinkTracker,
    HeadlessBrowserDriver,
    SPARouteExtractor,
    find_browser_binary,
    validate_workflow,
)


class BrowserDriverAcceptanceTests(unittest.TestCase):
    def test_legacy_workflow_validation_preserved(self):
        valid_steps = [
            {"verb": "goto", "url": "https://example.com/login"},
            {"verb": "wait", "ms": 500},
            {"verb": "read_text", "label": "Welcome"},
            {"verb": "screenshot"},
        ]
        plan = validate_workflow(valid_steps)
        self.assertEqual(len(plan), 4)
        self.assertEqual(plan[0]["verb"], "goto")

        with self.assertRaises(BrowserWorkflowError):
            validate_workflow([{"verb": "evaluate", "script": "alert(1)"}])

    def test_dom_sink_tracker_detects_hash_to_innerhtml(self):
        vulnerable_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Vulnerable SPA</title></head>
        <body>
            <div id="content"></div>
            <script>
                var hashVal = decodeURIComponent(window.location.hash.substring(1));
                document.getElementById('content').innerHTML = hashVal;
            </script>
        </body>
        </html>
        """
        tracker = DOMSinkTracker()
        findings = tracker.analyze(vulnerable_html, base_url="https://example.com/app")

        self.assertGreater(len(findings), 0)
        top = findings[0]
        self.assertEqual(top["category"], "dom_xss")
        self.assertEqual(top["source"], "location.hash")
        self.assertEqual(top["sink"], "innerHTML")
        self.assertEqual(top["confidence"], "high")

    def test_dom_sink_tracker_detects_search_to_eval(self):
        vulnerable_html = """
        <script>
            var params = new URLSearchParams(window.location.search);
            var callback = params.get("cb");
            if (callback) {
                eval(callback + "()");
            }
        </script>
        """
        tracker = DOMSinkTracker()
        findings = tracker.analyze(vulnerable_html, base_url="https://example.com/api")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source"], "location.search")
        self.assertEqual(findings[0]["sink"], "eval")

    def test_dom_sink_tracker_detects_dvwa_location_href_to_document_write(self):
        # DVWA's DOM XSS module: document.location.href -> document.write unencoded.
        vulnerable_html = """
        <script>
        if (document.location.href.indexOf("default=") >= 0) {
            var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
            document.write("<option value='" + decodeURI(lang) + "'>" + decodeURI(lang) + "</option>");
        }
        </script>
        """
        findings = DOMSinkTracker().analyze(vulnerable_html, base_url="http://127.0.0.1/vulnerabilities/xss_d/")
        self.assertTrue(any(f["source"] == "location.href" and f["sink"] == "document.write" for f in findings))

    def test_dom_sink_tracker_benign_code_produces_no_findings(self):
        safe_html = """
        <script>
            var now = new Date();
            console.log("Current time: " + now.toISOString());
            document.getElementById('footer').textContent = "Copyright 2026";
        </script>
        """
        tracker = DOMSinkTracker()
        findings = tracker.analyze(safe_html, base_url="https://example.com/safe")
        self.assertEqual(len(findings), 0)

    def test_spa_route_extractor_discovers_routes(self):
        spa_bundle_js = """
        const AppRoutes = () => (
            <Switch>
                <Route path="/overview" component={Overview} />
                <Route exact path="/users/:userId/details" component={UserDetails} />
                <Route path="/admin/security-settings" component={SecuritySettings} />
            </Switch>
        );
        const vueRoutes = [
            { path: '/billing/invoices', component: Invoices },
            { path: '/api-keys', component: ApiKeys }
        ];
        """
        extractor = SPARouteExtractor()
        routes = extractor.extract_routes(spa_bundle_js, base_url="https://app.example.com")

        self.assertIn("/overview", routes)
        self.assertIn("/users/:userId/details", routes)
        self.assertIn("/admin/security-settings", routes)
        self.assertIn("/billing/invoices", routes)
        self.assertIn("/api-keys", routes)

    def test_find_browser_binary(self):
        binary = find_browser_binary()
        # On this macOS system, Google Chrome exists; in CI or other platforms it may return None or a path
        if binary:
            self.assertTrue(os.path.exists(binary))

    @patch("subprocess.run")
    def test_headless_browser_driver_execution_mocked(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="<html><body><div id='spa-rendered'>Dynamic Client Content</div></body></html>",
            stderr="",
        )
        driver = HeadlessBrowserDriver(browser_binary="/usr/bin/mock-chrome")
        result = driver.render_dom("https://app.example.com/spa", timeout_seconds=5)

        self.assertEqual(result["status"], "success")
        self.assertIn("Dynamic Client Content", result["dom"])
        self.assertEqual(mock_run.call_count, 1)

    @patch("subprocess.run")
    def test_headless_browser_driver_xss_validation_confirms_unescaped_element(self, mock_run):
        # The canary survives as a real element -> the sink wrote it unescaped -> confirmed.
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="<html><body><div id='target'><sharay_dom_probe_999></sharay_dom_probe_999></div></body></html>",
            stderr="",
        )
        driver = HeadlessBrowserDriver(browser_binary="/usr/bin/mock-chrome")
        validation = driver.verify_dom_xss(
            target_url="https://app.example.com/spa", canary="sharay_dom_probe_999",
        )
        self.assertEqual(validation["status"], "verified")
        self.assertTrue(validation["canary_reflected"])

    @patch("subprocess.run")
    def test_headless_browser_driver_xss_not_confirmed_when_escaped(self, mock_run):
        # The canary is HTML-escaped (safe output) -> not confirmed.
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="<html><body>&lt;sharay_dom_probe_999&gt;</body></html>",
            stderr="",
        )
        driver = HeadlessBrowserDriver(browser_binary="/usr/bin/mock-chrome")
        validation = driver.verify_dom_xss(
            target_url="https://app.example.com/spa", canary="sharay_dom_probe_999",
        )
        self.assertEqual(validation["status"], "not_reproduced")
        self.assertFalse(validation["canary_reflected"])


if __name__ == "__main__":
    unittest.main()
