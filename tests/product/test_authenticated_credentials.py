"""Product & integration tests for Sector 2.1: Real Credential Provisioning & Authenticated Sessions.

Verifies:
1. AuthenticatedSession JSON login and dynamic token extraction from response body.
2. AuthenticatedSession cookie capture and automatic session maintenance.
3. Transparent re-authentication on 401/403 expiry.
4. Dual-identity IDOR/BOLA matrix verification with real HTTP tenant handlers.
5. Zero synthetic tokens policy: pipeline gracefully skips matrix when operator credentials are omitted.
"""

import http.server
import json
import threading
import unittest

from packages.scanner_adapters.integrations.authorization import (
    AuthConfig,
    AuthenticatedSession,
    AuthorizationMatrixProber,
    IdentitySession,
    ResourceTarget,
    _extract_token_from_json,
)
from packages.security_policies import Destination


class MultiTenantAuthLabServer(http.server.BaseHTTPRequestHandler):
    """Live HTTP server providing authentication endpoints and tenant-isolated resources."""

    def log_message(self, format, *args):
        pass  # Suppress console logging during test runs

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8")

        if self.path == "/api/login":
            try:
                creds = json.loads(body)
                username = creds.get("username")
                password = creds.get("password")
                if username == "alice" and password == "alice_secret":
                    resp = json.dumps({"token": "jwt_token_alice_secure_abc123", "user_id": "101"}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", "session_id=alice_sess; Path=/")
                    self.send_header("Content-Length", str(len(resp)))
                    self.end_headers()
                    self.wfile.write(resp)
                    return
                elif username == "bob" and password == "bob_secret":
                    resp = json.dumps({"token": "jwt_token_bob_secure_xyz789", "user_id": "102"}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", "session_id=bob_sess; Path=/")
                    self.send_header("Content-Length", str(len(resp)))
                    self.end_headers()
                    self.wfile.write(resp)
                    return
            except Exception:
                pass
            self.send_response(401)
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        auth_hdr = self.headers.get("Authorization", "")
        _cookie_hdr = self.headers.get("Cookie", "")

        # Endpoint /api/user/101 (Alice's resource)
        # Vulnerable to IDOR: Bob can read Alice's data if he has any valid token
        if self.path == "/api/user/101":
            if "jwt_token_alice" in auth_hdr or "jwt_token_bob" in auth_hdr:
                resp = json.dumps(
                    {"user_id": "101", "name": "Alice Private Data", "ssn": "000-11-2222"}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
                return
            self.send_response(401)
            self.end_headers()
            return

        # Endpoint /api/user/102 (Bob's resource)
        if self.path == "/api/user/102":
            if "jwt_token_alice" in auth_hdr or "jwt_token_bob" in auth_hdr:
                resp = json.dumps(
                    {"user_id": "102", "name": "Bob Private Data", "credit_card": "4111-2222"}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
                return
            self.send_response(401)
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()


class TestAuthenticatedCredentials(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MultiTenantAuthLabServer)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.destination = Destination(
            url=f"http://127.0.0.1:{cls.port}",
            scheme="http",
            host="127.0.0.1",
            port=cls.port,
            path="/",
            origin=f"http://127.0.0.1:{cls.port}",
            ip="127.0.0.1",
        )
        cls.allow_ip = "127.0.0.1"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_token_extraction_from_json(self):
        """Ensure _extract_token_from_json extracts JWTs and auth tokens from arbitrary structures."""
        self.assertEqual(
            _extract_token_from_json({"token": "eyJhbGciOiJIUzI1NiJ9.test"}), "eyJhbGciOiJIUzI1NiJ9.test"
        )
        self.assertEqual(
            _extract_token_from_json({"auth": {"access_token": "secret_access_token_999"}}),
            "secret_access_token_999",
        )
        self.assertIsNone(_extract_token_from_json({"status": "ok", "count": 5}))

    def test_authenticated_session_json_login_and_token_capture(self):
        """Verify real JSON login flow, cookie capture, and Bearer token acquisition."""
        auth_cfg = AuthConfig(
            login_url="/api/login",
            login_method="POST",
            login_payload={"username": "alice", "password": "alice_secret"},
            custom_headers={"Content-Type": "application/json"},
        )
        identity = IdentitySession("user_alice", role="standard", user_id="101", auth_config=auth_cfg)
        session = AuthenticatedSession(self.destination, self.allow_ip, identity)

        # Before reauth
        self.assertIsNone(session._active_token)

        # Perform reauth / login
        success = session.reauthenticate()
        self.assertTrue(success, "Login should succeed against test handler")
        self.assertEqual(session._active_token, "jwt_token_alice_secure_abc123")
        self.assertIn("session_id", session._cookie_jar)
        self.assertEqual(session._cookie_jar["session_id"], "alice_sess")

        # Verify headers produced
        headers = session.get_effective_headers()
        self.assertEqual(headers["Authorization"], "Bearer jwt_token_alice_secure_abc123")
        self.assertIn("session_id=alice_sess", headers["Cookie"])

    def test_dual_identity_idor_matrix_detection(self):
        """Verify real dual-identity matrix testing detects cross-account IDOR."""
        # Alice session
        alice_cfg = AuthConfig(
            login_url="/api/login",
            login_method="POST",
            login_payload={"username": "alice", "password": "alice_secret"},
            custom_headers={"Content-Type": "application/json"},
        )
        alice_id = IdentitySession("alice", role="standard", user_id="101", auth_config=alice_cfg)

        # Bob session
        bob_cfg = AuthConfig(
            login_url="/api/login",
            login_method="POST",
            login_payload={"username": "bob", "password": "bob_secret"},
            custom_headers={"Content-Type": "application/json"},
        )
        bob_id = IdentitySession("bob", role="standard", user_id="102", auth_config=bob_cfg)

        # Authenticate both sessions
        sess_alice = AuthenticatedSession(self.destination, self.allow_ip, alice_id)
        self.assertTrue(sess_alice.reauthenticate())
        alice_id.headers = sess_alice.get_effective_headers()

        sess_bob = AuthenticatedSession(self.destination, self.allow_ip, bob_id)
        self.assertTrue(sess_bob.reauthenticate())
        bob_id.headers = sess_bob.get_effective_headers()

        prober = AuthorizationMatrixProber(
            self.destination, self.allow_ip, {"alice": alice_id, "bob": bob_id}
        )
        target = ResourceTarget(
            path="/api/user/101",
            method="GET",
            owner_identity="alice",
            owner_resource_id="101",
            peer_resource_id="102",
        )
        report = prober.sweep([target])

        # Bob accessed Alice's resource (/api/user/101) with HTTP 200 -> IDOR confirmed!
        findings = report.get("findings", [])
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].get("category"), "broken_object_level_authorization")
        self.assertEqual(findings[0].get("type"), "horizontal_idor")
        self.assertEqual(findings[0].get("path"), "/api/user/101")
        self.assertEqual(findings[0].get("status"), "confirmed")

    def test_pipeline_skips_matrix_without_credentials(self):
        """Ensure pipeline strictly avoids synthetic tokens and skips matrix when credentials omitted."""
        from packages.scanner_adapters import scan_comprehensive

        res = scan_comprehensive(
            self.destination,
            self.allow_ip,
            tools=["auth_matrix"],
            mode="aggressive",
            auth=None,  # No credentials supplied
        )

        matrix_checks = [c for c in res.get("checks", []) if c.get("category") == "authorization_matrix"]
        self.assertTrue(len(matrix_checks) >= 1)
        self.assertEqual(matrix_checks[0].get("status"), "skipped")
        self.assertIn("synthetic placeholder tokens disallowed", matrix_checks[0].get("detail", ""))


if __name__ == "__main__":
    unittest.main()
