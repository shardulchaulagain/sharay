"""Hermetic tests for AuthenticatedSession, AuthConfig, and transparent re-authentication."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from packages.scanner_adapters.integrations.authorization import (
    AuthConfig,
    AuthenticatedSession,
    IdentitySession,
)
from packages.security_policies import Destination


class AuthenticatedSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.destination = Destination(
            url="http://127.0.0.1:8080/api",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            path="/api",
            origin="http://127.0.0.1:8080",
            ip="127.0.0.1",
        )

    def test_token_rotation_cycles_through_token_pool(self) -> None:
        auth_config = AuthConfig(
            bearer_token="initial-token",
            rotating_tokens=["token-alpha", "token-beta", "token-gamma"],
        )
        ident = IdentitySession(name="service_agent", auth_config=auth_config)
        session = AuthenticatedSession(self.destination, "127.0.0.1", ident)

        # Initial header has initial-token
        self.assertEqual(session.get_effective_headers()["Authorization"], "Bearer initial-token")

        # First reauth -> token-alpha
        session.reauthenticate()
        self.assertEqual(session.get_effective_headers()["Authorization"], "Bearer token-alpha")

        # Second reauth -> token-beta
        session.reauthenticate()
        self.assertEqual(session.get_effective_headers()["Authorization"], "Bearer token-beta")

        # Third reauth -> token-gamma
        session.reauthenticate()
        self.assertEqual(session.get_effective_headers()["Authorization"], "Bearer token-gamma")

        # Cycles back to token-alpha
        session.reauthenticate()
        self.assertEqual(session.get_effective_headers()["Authorization"], "Bearer token-alpha")

    def test_transparent_reauth_on_401_unauthorized(self) -> None:
        auth_config = AuthConfig(
            bearer_token="expired-token",
            rotating_tokens=["valid-token-123"],
        )
        ident = IdentitySession(name="api_user", auth_config=auth_config)
        session = AuthenticatedSession(self.destination, "127.0.0.1", ident)

        call_count = {"n": 0}

        def mock_probe(dest, allow_ip, method, path, headers, timeout=4.0, body=None):
            call_count["n"] += 1
            auth = headers.get("Authorization", "")
            if auth == "Bearer valid-token-123":
                return 200, {}, '{"user": "alice", "status": "authenticated"}', 15.0
            return 401, {}, '{"error": "Token expired"}', 15.0

        with patch(
            "packages.scanner_adapters.integrations.authorization._send_auth_probe", side_effect=mock_probe
        ):
            status, _, body, _ = session.execute_with_reauth("GET", "/api/profile")
            self.assertEqual(status, 200)
            self.assertIn("alice", body)
            # Must have issued initial request (401), triggered reauth, and retried (200)
            self.assertEqual(call_count["n"], 2)

    def test_transparent_reauth_on_redirect_to_login(self) -> None:
        auth_config = AuthConfig(
            cookies={"session": "stale_session_cookie"},
            login_url="/auth/login",
            login_payload={"username": "alice", "password": "correct_password"},
            success_indicator="Login successful",
        )
        ident = IdentitySession(name="web_user", auth_config=auth_config)
        session = AuthenticatedSession(self.destination, "127.0.0.1", ident)

        def mock_probe(dest, allow_ip, method, path, headers, timeout=4.0, body=None):
            cookie = headers.get("Cookie", "")
            if path == "/auth/login":
                return (
                    200,
                    {"set-cookie": "session=fresh_cookie_999; Path=/; HttpOnly"},
                    "Login successful. Welcome back alice.",
                    20.0,
                )
            if path == "/dashboard":
                if "fresh_cookie_999" in cookie:
                    return 200, {}, "<h1>Executive Dashboard</h1>", 15.0
                return 302, {"location": "/auth/login"}, "Redirecting to login...", 15.0
            return 404, {}, "", 10.0

        with patch(
            "packages.scanner_adapters.integrations.authorization._send_auth_probe", side_effect=mock_probe
        ):
            status, _, body, _ = session.execute_with_reauth("GET", "/dashboard")
            self.assertEqual(status, 200)
            self.assertIn("Executive Dashboard", body)
            self.assertEqual(session._cookie_jar.get("session"), "fresh_cookie_999")

    def test_check_health_validates_session_status(self) -> None:
        auth_config = AuthConfig(
            cookies={"session": "live_valid_cookie"},
            health_check_endpoint="/api/health",
            success_indicator="UP",
        )
        ident = IdentitySession(name="agent", auth_config=auth_config)
        session = AuthenticatedSession(self.destination, "127.0.0.1", ident)

        def mock_probe(dest, allow_ip, method, path, headers, timeout=4.0, body=None):
            if path == "/api/health":
                return 200, {}, '{"status": "UP"}', 10.0
            return 404, {}, "", 10.0

        with patch(
            "packages.scanner_adapters.integrations.authorization._send_auth_probe", side_effect=mock_probe
        ):
            self.assertTrue(session.check_health())


if __name__ == "__main__":
    unittest.main()
