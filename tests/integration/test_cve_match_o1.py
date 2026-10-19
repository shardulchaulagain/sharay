"""Sector O1: grounded version->CVE matching, and its wiring into the live scan pipeline.

Every CVE must be grounded in an observed version that falls in an affected range. A bare banner
(product with no version) and a patched version must flag nothing.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import unittest

from packages.scanner_adapters import scan_comprehensive
from packages.scanner_adapters.integrations import cve_match as cm
from packages.security_policies import Destination


class CveMatchUnitTest(unittest.TestCase):
    def test_fingerprint_extracts_concrete_versions(self):
        fv = cm.fingerprint_versions(
            [("Server", "Apache/2.4.49 (Unix) OpenSSL/3.0.1"), ("X-Powered-By", "PHP/8.1.2")]
        )
        pairs = {(x["product"], x["version"]) for x in fv}
        self.assertIn(("apache_http_server", "2.4.49"), pairs)
        self.assertIn(("openssl", "3.0.1"), pairs)
        self.assertIn(("php", "8.1.2"), pairs)

    def test_vulnerable_versions_flag_grounded_cves(self):
        fv = cm.fingerprint_versions([("Server", "Apache/2.4.49 (Unix) OpenSSL/3.0.1")])
        cves = {f["cve_id"] for f in cm.scan_known_cves(fv)}
        self.assertIn("CVE-2021-41773", cves)
        self.assertIn("CVE-2022-3786", cves)
        for f in cm.scan_known_cves(fv):
            self.assertEqual(f["status"], "suspected")  # version match, not exploit-verified
            self.assertEqual(f["category"], "known_vulnerable_component")

    def test_patched_versions_and_bare_banner_flag_nothing(self):
        # Patched releases are out of range.
        self.assertEqual(cm.match_product("apache_http_server", "2.4.51"), [])
        self.assertEqual([a.cve for a in cm.match_product("php", "8.1.29")], [])
        # A product with no version (bare banner) must never become a finding.
        self.assertEqual(cm.scan_known_cves(cm.fingerprint_versions([("Server", "nginx")])), [])

    def test_version_range_boundaries(self):
        self.assertTrue(cm.version_in_range("2.4.49", "2.4.49", "2.4.50"))  # inclusive lower
        self.assertFalse(cm.version_in_range("2.4.50", "2.4.49", "2.4.50"))  # exclusive upper
        self.assertFalse(cm.version_in_range("2.4.48", "2.4.49", "2.4.50"))  # below range


class _VulnServerHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def version_string(self):  # this is what BaseHTTPRequestHandler puts in the Server header
        return "Apache/2.4.49 (Unix)"

    def do_GET(self):
        body = b"home"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class CveMatchPipelineWiringTest(unittest.TestCase):
    def setUp(self):
        self.srv = socketserver.TCPServer(("127.0.0.1", 0), _VulnServerHandler)
        self.srv.allow_reuse_address = True
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_pipeline_flags_cve_from_observed_server_version(self):
        base = f"http://127.0.0.1:{self.port}/"
        dest = Destination(base, "http", "127.0.0.1", self.port, "/", f"http://127.0.0.1:{self.port}", "127.0.0.1")
        res = scan_comprehensive(dest, "127.0.0.1", mode="standard", tools=["crawler"], max_seconds=30)

        checks = [c for c in res["checks"] if c.get("category") == "known_cve"]
        self.assertTrue(checks, "known_cve stage did not run")

        cve = [f for f in res["findings"] if f.get("category") == "known_vulnerable_component"]
        self.assertTrue(cve, "no CVE finding from the observed Apache/2.4.49 Server header")
        cves = {f["cve_id"] for f in cve}
        self.assertIn("CVE-2021-41773", cves)
        self.assertEqual(cve[0]["attributes"]["version"], "2.4.49")


if __name__ == "__main__":
    unittest.main()
