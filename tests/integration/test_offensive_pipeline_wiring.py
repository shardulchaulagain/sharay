"""Regression: the compositional payload engine (Sector O3) is wired into the live
scan_comprehensive pipeline and fire-and-confirms against an authorized loopback lab.

Guards against the engine silently reverting to unwired/cosmetic behavior.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import unittest

from packages.scanner_adapters import scan_comprehensive
from packages.security_policies import Destination


class _VulnHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        q = self.path
        body = b"normal product page"
        # Simulated injectable 'id' parameter: SQL error signature on quote/UNION/SLEEP.
        if "id=" in q and ("'" in q or "%27" in q or "UNION" in q.upper() or "SLEEP" in q.upper()):
            body = b"SQL error: You have an error in your SQL syntax near '1'"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OffensivePipelineWiringTest(unittest.TestCase):
    def setUp(self):
        self.srv = socketserver.TCPServer(("127.0.0.1", 0), _VulnHandler)
        self.srv.allow_reuse_address = True
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def _dest(self) -> Destination:
        base = f"http://127.0.0.1:{self.port}/"
        return Destination(
            base, "http", "127.0.0.1", self.port, "/", f"http://127.0.0.1:{self.port}", "127.0.0.1"
        )

    def test_engine_wired_fires_and_confirms_with_mitre(self):
        res = scan_comprehensive(
            self._dest(), "127.0.0.1", mode="adaptive", tools=["payload_forge"], max_seconds=40
        )

        # The new engine's stage ran and reports generation + firing (not the old cosmetic summary).
        checks = [c for c in res["checks"] if c.get("category") == "payload_forge"]
        self.assertTrue(checks, "payload_forge stage did not run")
        self.assertIn("Compositional grammar", checks[0]["detail"])

        obs = [o for o in res["observations"] if o.get("kind") == "payload_grammar_summary"]
        self.assertTrue(obs, "payload_grammar_summary observation missing")
        summary = obs[0]
        self.assertGreater(summary["generated_payloads"], 0)
        self.assertGreater(summary["fired"], 0, "engine did not fire against the serving lab")
        # Negative control must keep this honest: not every fired payload confirms.
        self.assertLess(summary["confirmed"], summary["fired"])

        # The injectable 'id' parameter yields a reproducer-confirmed finding with ATT&CK mapping.
        sqli = [f for f in res["findings"] if f.get("category") == "sql_injection"]
        self.assertTrue(sqli, "no confirmed SQLi finding from the grammar engine")
        f = sqli[0]
        self.assertEqual(f["status"], "confirmed")
        self.assertEqual(f.get("lifecycle_state"), "REPRODUCED")
        self.assertEqual(f["attributes"]["mitre"]["technique_id"], "T1190")
        self.assertTrue(f["attributes"]["payload"])


if __name__ == "__main__":
    unittest.main()
