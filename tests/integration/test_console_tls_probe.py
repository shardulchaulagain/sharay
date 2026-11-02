"""The operator console must probe and verify an authorized HTTPS target whose certificate is
self-signed/invalid, without aborting on an SSL error (roadmap X3; reported console defect).

Certificate validity is an observation, not a connection precondition for an assessment target.
"""

import http.server
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packages.scanner_adapters.reproducer import DeterministicReproducer
from packages.scanner_adapters.workspace import InteractiveWorkspace
from packages.security_policies import ScopePolicy


def _self_signed(folder: Path) -> tuple[str, str] | None:
    if shutil.which("openssl") is None:
        return None
    cert, key = folder / "c.pem", folder / "k.pem"
    proc = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
        ],
        capture_output=True,
    )
    return (str(cert), str(key)) if proc.returncode == 0 else None


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "nginx/1.18.0")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class ConsoleTlsProbeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        pair = _self_signed(Path(self._tmp.name))
        if pair is None:
            self.skipTest("openssl is not available to generate a self-signed certificate.")
        cert, key = pair
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.shutdown)
        self.url = f"https://127.0.0.1:{self.port}/"

    def _scope(self) -> ScopePolicy:
        now = datetime.now(UTC)
        return ScopePolicy(
            hosts=["127.0.0.1"],
            allowed_origins=[f"https://127.0.0.1:{self.port}"],
            allowed_paths=["/"],
            allowed_cidrs=["127.0.0.1/32"],
            request_rate=5,
            max_concurrency=1,
            starts_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(hours=1),
        )

    def test_workspace_probe_succeeds_against_self_signed_tls(self):
        result = InteractiveWorkspace().execute_probe(self._scope(), self.url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.metadata.get("tls_verified"), False)

    def test_reproducer_verifies_over_self_signed_tls(self):
        status, body, _elapsed = DeterministicReproducer._default_http_request(self.url, timeout=5.0)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")


if __name__ == "__main__":
    unittest.main()
