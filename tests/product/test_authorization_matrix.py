"""Acceptance tests for Dual-Identity Session Switching and IDOR Matrix Probes (B5)."""

import unittest
from unittest.mock import patch

from packages.scanner_adapters.integrations.authorization import (
    AuthorizationMatrixProber,
    IdentitySession,
    ResourceTarget,
)
from packages.security_policies import Destination


class AuthorizationMatrixAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.destination = Destination(
            url="http://example.com/",
            scheme="http",
            host="example.com",
            port=80,
            path="/",
            origin="http://example.com",
            ip="93.184.216.34",
        )
        self.user_a = IdentitySession(
            name="user_a",
            role="standard",
            headers={"Cookie": "session_id=user_a_secret_cookie_token_111"},
            user_id="1001",
            canaries=["user_a_private_profile_data", "1001"],
        )
        self.user_b = IdentitySession(
            name="user_b",
            role="standard",
            headers={"Cookie": "session_id=user_b_secret_cookie_token_222"},
            user_id="1002",
            canaries=["user_b_private_profile_data", "1002"],
        )
        self.admin = IdentitySession(
            name="admin_user",
            role="admin",
            headers={"Cookie": "session_id=admin_super_secret_cookie_999"},
            user_id="9999",
            canaries=["admin_confidential_metrics"],
        )

    @patch("packages.scanner_adapters.integrations.authorization._send_auth_probe")
    def test_detects_horizontal_idor_when_user_b_reads_user_a(self, mock_probe):
        # Mock probe responses:
        # User A requests /api/users/1001 -> 200 with user_a_private_profile_data
        # User B requests /api/users/1001 -> 200 with user_a_private_profile_data (VULNERABILITY!)
        def probe_handler(dest, allow_ip, method, path, headers, timeout):
            cookie = headers.get("Cookie", "")
            if path == "/api/users/1001":
                if "user_a" in cookie or "user_b" in cookie:
                    return (
                        200,
                        {"content-type": "application/json"},
                        '{"id": "1001", "data": "user_a_private_profile_data"}',
                        10.0,
                    )
            return (404, {}, "", 10.0)

        mock_probe.side_effect = probe_handler

        prober = AuthorizationMatrixProber(
            destination=self.destination,
            allow_ip="93.184.216.34",
            identities={"user_a": self.user_a, "user_b": self.user_b},
        )
        resources = [
            ResourceTarget(
                path="/api/users/1001",
                owner_identity="user_a",
                owner_resource_id="1001",
                peer_resource_id="1002",
            )
        ]
        results = prober.sweep(resources)

        self.assertEqual(len(results["findings"]), 1)
        finding = results["findings"][0]
        self.assertEqual(finding["type"], "horizontal_idor")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["victim_identity"], "user_a")
        self.assertEqual(finding["attacker_identity"], "user_b")
        self.assertIn("user_a_private_profile_data", finding["evidence"])

    @patch("packages.scanner_adapters.integrations.authorization._send_auth_probe")
    def test_properly_authorized_endpoint_produces_no_idor(self, mock_probe):
        # Mock probe responses:
        # User A requests /api/users/1001 -> 200 OK
        # User B requests /api/users/1001 -> 403 Forbidden (SAFE)
        def probe_handler(dest, allow_ip, method, path, headers, timeout):
            cookie = headers.get("Cookie", "")
            if path == "/api/users/1001":
                if "user_a" in cookie:
                    return (200, {}, '{"id": "1001", "data": "user_a_private_profile_data"}', 10.0)
                return (403, {}, '{"error": "Forbidden"}', 10.0)
            return (404, {}, "", 10.0)

        mock_probe.side_effect = probe_handler

        prober = AuthorizationMatrixProber(
            destination=self.destination,
            allow_ip="93.184.216.34",
            identities={"user_a": self.user_a, "user_b": self.user_b},
        )
        resources = [
            ResourceTarget(
                path="/api/users/1001",
                owner_identity="user_a",
                owner_resource_id="1001",
                peer_resource_id="1002",
            )
        ]
        results = prober.sweep(resources)
        self.assertEqual(len(results["findings"]), 0)

    @patch("packages.scanner_adapters.integrations.authorization._send_auth_probe")
    def test_detects_vertical_privilege_escalation(self, mock_probe):
        # Mock probe responses:
        # Admin requests /admin/system/metrics -> 200 OK
        # Standard user_a requests /admin/system/metrics -> 200 OK (VULNERABILITY!)
        def probe_handler(dest, allow_ip, method, path, headers, timeout):
            if path == "/admin/system/metrics":
                return (200, {}, '{"metrics": "admin_confidential_metrics"}', 10.0)
            return (404, {}, "", 10.0)

        mock_probe.side_effect = probe_handler

        prober = AuthorizationMatrixProber(
            destination=self.destination,
            allow_ip="93.184.216.34",
            identities={"admin": self.admin, "user_a": self.user_a},
        )
        resources = [
            ResourceTarget(
                path="/admin/system/metrics",
                owner_identity="admin",
                is_admin_only=True,
            )
        ]
        results = prober.sweep(resources)

        self.assertEqual(len(results["findings"]), 1)
        finding = results["findings"][0]
        self.assertEqual(finding["type"], "vertical_privilege_escalation")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["attacker_identity"], "user_a")


if __name__ == "__main__":
    unittest.main()
