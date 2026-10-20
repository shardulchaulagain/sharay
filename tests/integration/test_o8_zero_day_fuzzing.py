"""Sector O8: target-side 0-day research via anomaly/differential fuzzing.

Novel target behaviour (unhandled 5xx, surfaced stack traces) becomes a `needs_triage` research
candidate -- never an auto-confirmed vulnerability. A stable target produces no candidates.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import unittest
import urllib.parse

from packages.offensive_capability import TargetAnomalyFuzzer
from packages.scanner_adapters import scan_comprehensive
from packages.security_policies import Destination


class _AnomalyLab(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        val = (qs.get("id", [""]) or [""])[0]
        if len(val) > 5000:  # unhandled code path on oversized input
            body = b"Internal Server Error: Traceback (most recent call last): boom"
            self.send_response(500)
        else:
            body = b"normal catalog page"
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _StableLab(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"normal catalog page"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(handler):
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class TargetAnomalyFuzzerTest(unittest.TestCase):
    def test_anomaly_becomes_research_candidate_never_confirmed(self):
        srv, port = _serve(_AnomalyLab)
        try:
            cands = TargetAnomalyFuzzer().fuzz_parameter(f"http://127.0.0.1:{port}/", "id")
            self.assertTrue(cands, "oversized input that 500s should produce a research candidate")
            for c in cands:
                self.assertEqual(c["status"], "needs_triage")
                self.assertNotEqual(c["status"], "confirmed")
                self.assertEqual(c["category"], "anomaly_research_candidate")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_stable_target_produces_no_candidates(self):
        srv, port = _serve(_StableLab)
        try:
            self.assertEqual(TargetAnomalyFuzzer().fuzz_parameter(f"http://127.0.0.1:{port}/", "id"), [])
        finally:
            srv.shutdown()
            srv.server_close()


class ZeroDayPipelineTest(unittest.TestCase):
    def test_pipeline_surfaces_research_candidate_unverified(self):
        srv, port = _serve(_AnomalyLab)
        try:
            dest = Destination(
                f"http://127.0.0.1:{port}/",
                "http",
                "127.0.0.1",
                port,
                "/",
                f"http://127.0.0.1:{port}",
                "127.0.0.1",
            )
            res = scan_comprehensive(dest, "127.0.0.1", mode="adaptive", tools=["crawler"], max_seconds=40)
            self.assertTrue([c for c in res["checks"] if c.get("category") == "zero_day_research"])
            cands = [f for f in res["findings"] if f.get("category") == "anomaly_research_candidate"]
            self.assertTrue(cands, "pipeline did not surface a 0-day research candidate")
            self.assertTrue(all(f["status"] == "needs_triage" for f in cands))
            self.assertFalse(any(f["status"] == "confirmed" for f in cands))
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
