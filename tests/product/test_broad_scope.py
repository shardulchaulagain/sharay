"""Broad inventory must not silently expand the runnable assessment boundary."""

import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from pydantic import ValidationError

from packages.scanner_adapters import preflight, scan
from packages.security_policies import PolicyError, ScopePolicy, check_url, normalize_url, validate_scope


def broad_scope(host="example.com", cidrs=None):
    now = datetime.now(UTC)
    authority = f"[{host}]" if ":" in host else host
    return {
        "hosts": [host],
        "allowed_origins": [f"https://{authority}"],
        "allowed_cidrs": [] if cidrs is None else cidrs,
        "starts_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "request_rate": 10.0,
        "max_concurrency": 5,
    }


class BroadScopeTests(unittest.TestCase):
    def test_canonical_domains_and_ipv6_are_registration_only_without_resolution(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("Registration must not resolve")):
            for host in ("example.com", "localhost", "192.168.1.50", "2001:db8::1"):
                with self.subTest(host=host):
                    scope = broad_scope(host)
                    url = scope["allowed_origins"][0] + "/"
                    self.assertEqual(normalize_url(url), url)
                    policy = validate_scope(scope, url)
                    self.assertEqual(check_url(policy, url).host, host)

    def test_ambiguous_hosts_remain_rejected(self):
        for host in (
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f000001",
            "example.0xabc",
            "example.com.",
            "-bad.example",
            "bad-.example",
            "bad..example",
            "*.example.com",
            "bad_host.example",
            "[fe80::1%25en0]",
            "[::ffff:127.0.0.1]",
        ):
            with self.subTest(host=host), self.assertRaises(PolicyError):
                normalize_url(f"https://{host}/")

    def test_broad_scope_retains_strict_types_limits_and_address_membership(self):
        for change in (
            {"request_rate": True},
            {"request_rate": "10"},
            {"request_rate": 5000.1},
            {"request_rate": float("nan")},
            {"request_rate": float("inf")},
            {"max_concurrency": True},
            {"max_concurrency": "5"},
            {"max_concurrency": 6},
            {"allowed_cidrs": ["10.0.0.1/24"]},
            {"allowed_cidrs": ["not-a-network"]},
            {"allowed_cidrs": ["10.0.0.0/24", "10.0.0.0/24"]},
            {"hosts": ["example.com", "example.com"]},
            {"unknown": True},
        ):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                ScopePolicy.model_validate(broad_scope() | change)
        with self.assertRaises(ValidationError):
            ScopePolicy.model_validate(broad_scope("192.168.1.50", ["10.0.0.0/24"]))
        validate_scope(broad_scope("192.168.1.50", ["192.168.1.0/24"]), "https://192.168.1.50/")

    def test_broad_direct_scan_fails_before_resolution_persistence_or_connection(self):
        for host in ("example.com", "localhost", "10.0.0.1", "169.254.169.254", "::ffff:7f00:1"):
            with (
                self.subTest(host=host),
                patch("socket.getaddrinfo") as resolver,
                patch("packages.scanner_adapters._connection") as connect,
            ):
                scope = broad_scope(host)
                pacing = {}
                result = scan(
                    scope,
                    scope["allowed_origins"][0],
                    lambda: False,
                    lambda event: None,
                    request_starts=pacing,
                )
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["requests_performed"], 0)
                self.assertEqual(pacing, {})
                resolver.assert_not_called()
                connect.assert_not_called()
                self.assertFalse(result["observations"])

    def test_preflight_has_actionable_guidance_without_false_execution_readiness(self):
        for installed in (None, "/synthetic/bin/tool"):
            with patch("packages.scanner_adapters.shutil.which", return_value=installed):
                tools = preflight()
                for tool in tools[1:]:
                    self.assertEqual(tool["available"], bool(installed))
                    self.assertFalse(tool["runnable"])
                    self.assertTrue(tool["guidance"])

    def test_registered_broad_redirect_stops_before_a_second_connection(self):
        scope = broad_scope("127.0.0.1", ["127.0.0.1/32"])
        scope["hosts"].append("example.com")
        scope["allowed_origins"].append("https://example.com")
        response = MagicMock()
        response.status = 302
        response.headers.defects = []
        response.getheaders.return_value = [("Location", "https://example.com/")]
        response.getheader.return_value = "https://example.com/"
        connection = MagicMock()
        connection.getresponse.return_value = response
        with (
            patch("socket.getaddrinfo") as resolver,
            patch("packages.scanner_adapters._connection", return_value=connection) as connect,
        ):
            result = scan(scope, "https://127.0.0.1/", lambda: False, lambda event: None)
            self.assertEqual(result["outcome"], "completed_with_errors")
            self.assertEqual(result["requests_performed"], 1)
            self.assertEqual(connect.call_count, 1)
            resolver.assert_not_called()
            self.assertIn("execution requires", result["checks"][-1]["detail"])

    def test_preflight_samples_each_executable_once(self):
        with patch(
            "packages.scanner_adapters.shutil.which", side_effect=["/synthetic/nmap"] + [None] * 5
        ) as which:
            tools = preflight()
            self.assertEqual(which.call_count, 6)
            self.assertTrue(tools[1]["available"])
            self.assertEqual(tools[1]["status"], "integration_not_implemented")


if __name__ == "__main__":
    unittest.main()
