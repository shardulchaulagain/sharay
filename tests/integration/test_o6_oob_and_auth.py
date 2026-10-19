"""Sector O6: live out-of-band blind confirmation + authenticated reproduction.

- The OOB listener confirms blind SSRF only when a real callback arrives (no callback -> no finding).
- scan_comprehensive wires OOB blind-SSRF against a serving loopback lab.
- Authenticated reproduction logs in and reaches an auth-gated injectable that an unauthenticated
  probe cannot.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
import unittest
import urllib.parse
import urllib.request

from packages.offensive_capability import AuthenticatedReproducer, OOBBlindVerifier
from packages.scanner_adapters import scan_comprehensive
from packages.scanner_adapters.integrations.authorization import AuthConfig, IdentitySession
from packages.scanner_adapters.reproducer import DeterministicReproducer
from packages.security_policies import Destination


def _serve(handler) -> tuple[socketserver.TCPServer, int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class OOBBlindVerifierUnitTest(unittest.TestCase):
    def test_callback_confirms_only_when_received(self):
        with OOBBlindVerifier() as oob:
            def ssrf_fetch(base, param, payload):  # simulate a server-side fetch of the OOB URL
                try:
                    urllib.request.urlopen(payload, timeout=2.0).read()
                except Exception:
                    pass

            confirmed = oob.probe_param("http://target/", "url", "ssrf", fire_fn=ssrf_fetch)
            self.assertIsNotNone(confirmed)
            self.assertEqual(confirmed["status"], "confirmed")
            self.assertIn("Out-of-Band", confirmed["title"])

            # No fetch -> no callback -> no finding (zero false positives).
            nothing = oob.probe_param("http://target/", "url", "ssrf", fire_fn=lambda b, p, pl: None, wait_seconds=0.4)
            self.assertIsNone(nothing)


class _SSRFLab(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        for v in qs.get("url", []):  # the SSRF: fetch whatever is in ?url=
            try:
                urllib.request.urlopen(v, timeout=2.0).read()
            except Exception:
                pass
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class _NoSSRFLab(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class OOBPipelineTest(unittest.TestCase):
    def _run(self, handler):
        srv, port = _serve(handler)
        try:
            dest = Destination(
                f"http://127.0.0.1:{port}/", "http", "127.0.0.1", port, "/", f"http://127.0.0.1:{port}", "127.0.0.1"
            )
            return scan_comprehensive(dest, "127.0.0.1", mode="standard", tools=["crawler"], max_seconds=30)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_pipeline_confirms_blind_ssrf_via_real_callback(self):
        res = self._run(_SSRFLab)
        self.assertTrue([c for c in res["checks"] if c.get("category") == "oob_blind"])
        oob = [f for f in res["findings"] if "Out-of-Band" in f.get("title", "")]
        self.assertTrue(oob, "blind SSRF was not confirmed via OOB callback")
        self.assertEqual(oob[0]["status"], "confirmed")

    def test_pipeline_no_false_positive_without_ssrf(self):
        res = self._run(_NoSSRFLab)
        oob = [f for f in res["findings"] if "Out-of-Band" in f.get("title", "")]
        self.assertEqual(oob, [])


class _AuthLab(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        if self.path == "/login":
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode("utf-8", "replace")
            try:
                data = json.loads(raw)
            except ValueError:
                data = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
            if data.get("username") == "admin" and data.get("password") == "secret":
                self.send_response(200)
                self.send_header("Set-Cookie", "session=valid; Path=/")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
                return
            self.send_response(401)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"no")
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        authed = "session=valid" in self.headers.get("Cookie", "")
        q = urllib.parse.unquote_plus(urllib.parse.urlparse(self.path).query)
        if not authed:
            self.send_response(401)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"no")
            return
        injected = "'" in q or "SLEEP" in q.upper() or "UNION" in q.upper()
        body = b"You have an error in your SQL syntax; check the manual" if injected else b"catalog listing ok here"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AuthenticatedReproductionTest(unittest.TestCase):
    def test_login_lets_reproducer_reach_auth_gated_injectable(self):
        srv, port = _serve(_AuthLab)
        try:
            dest = Destination(
                f"http://127.0.0.1:{port}/", "http", "127.0.0.1", port, "/", f"http://127.0.0.1:{port}", "127.0.0.1"
            )
            identity = IdentitySession(
                name="admin",
                role="admin",
                auth_config=AuthConfig(
                    login_url="/login",
                    login_method="POST",
                    login_payload={"username": "admin", "password": "secret"},
                ),
            )
            item_url = f"http://127.0.0.1:{port}/item"

            # Authenticated: logs in, carries the session, reaches the injectable -> confirmed.
            res_auth = AuthenticatedReproducer().reproduce_authenticated(
                dest, "127.0.0.1", identity, base_url=item_url, fuzz_param="id", active_payload="' OR '1'='1"
            )
            self.assertTrue(res_auth.confirmed, "authenticated reproduction should confirm the auth-gated SQLi")

            # Unauthenticated: the endpoint 401s everything -> no confirmation.
            res_plain = DeterministicReproducer().verify_finding(
                base_url=item_url, fuzz_param="id", active_payload="' OR '1'='1"
            )
            self.assertFalse(res_plain.confirmed, "unauthenticated reproduction must not confirm behind auth")
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
