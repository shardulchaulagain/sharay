"""Unit tests for typed ResolverService & Error Taxonomy (Requirement A2)."""

from __future__ import annotations

import socket
import unittest
from unittest.mock import MagicMock

from packages.security_policies.resolver import (
    ResolutionError,
    ResolutionErrorCode,
    ResolverService,
)


class TestResolverService(unittest.TestCase):
    """Test suite for typed resolver error taxonomy, caching, SSRF guards, and pinning."""

    def test_01_literal_ip_bypasses_dns(self):
        resolver = ResolverService()
        res = resolver.resolve("1.1.1.1")
        self.assertEqual(res.host, "1.1.1.1")
        self.assertEqual(res.pinned_ip, "1.1.1.1")
        self.assertEqual(res.resolver_used, "literal")
        self.assertFalse(res.cached)

    def test_02_literal_private_ip_refused_ssrf(self):
        resolver = ResolverService(allow_internal=False)
        with self.assertRaises(ResolutionError) as ctx:
            resolver.resolve("192.168.1.50")
        self.assertEqual(ctx.exception.code, ResolutionErrorCode.SSRF_REFUSED)

    def test_03_loopback_refused_ssrf(self):
        resolver = ResolverService(allow_internal=False)
        with self.assertRaises(ResolutionError) as ctx:
            resolver.resolve("127.0.0.1")
        self.assertEqual(ctx.exception.code, ResolutionErrorCode.SSRF_REFUSED)

    def test_04_system_resolver_success(self):
        mock_sys = MagicMock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            ]
        )
        resolver = ResolverService(system_resolver=mock_sys, enable_doh_fallback=False)
        res = resolver.resolve("example.com")
        self.assertEqual(res.host, "example.com")
        self.assertEqual(res.pinned_ip, "93.184.216.34")
        self.assertEqual(res.resolver_used, "system")
        self.assertFalse(res.cached)
        mock_sys.assert_called_once()

    def test_05_caching_returns_lkg(self):
        mock_sys = MagicMock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            ]
        )
        resolver = ResolverService(system_resolver=mock_sys, enable_doh_fallback=False)
        res1 = resolver.resolve("cached-domain.com")
        self.assertFalse(res1.cached)

        # Second lookup should hit cache without calling system_resolver again
        res2 = resolver.resolve("cached-domain.com")
        self.assertTrue(res2.cached)
        self.assertEqual(res2.resolver_used, "cache")
        self.assertEqual(res2.pinned_ip, "93.184.216.34")
        self.assertEqual(mock_sys.call_count, 1)

    def test_06_nxdomain_error_mapping(self):
        mock_sys = MagicMock(side_effect=socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided"))
        resolver = ResolverService(system_resolver=mock_sys, enable_doh_fallback=False)
        with self.assertRaises(ResolutionError) as ctx:
            resolver.resolve("nonexistent-domain-xyz-123.org")
        self.assertEqual(ctx.exception.code, ResolutionErrorCode.NXDOMAIN)
        self.assertFalse(ctx.exception.policy.retryable)

    def test_07_servfail_error_mapping(self):
        mock_sys = MagicMock(
            side_effect=socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
        )
        resolver = ResolverService(system_resolver=mock_sys, enable_doh_fallback=False)
        with self.assertRaises(ResolutionError) as ctx:
            resolver.resolve("transient-timeout.com")
        self.assertEqual(ctx.exception.code, ResolutionErrorCode.SERVFAIL)
        self.assertTrue(ctx.exception.policy.retryable)

    def test_08_ssrf_guard_on_resolved_private_ip(self):
        # Even if domain name looks public, resolving to 10.0.0.1 must be refused
        mock_sys = MagicMock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
            ]
        )
        resolver = ResolverService(system_resolver=mock_sys, allow_internal=False)
        with self.assertRaises(ResolutionError) as ctx:
            resolver.resolve("internal-spoof.company.com")
        self.assertEqual(ctx.exception.code, ResolutionErrorCode.SSRF_REFUSED)

    def test_09_deterministic_pinning_prefers_ipv4(self):
        # When both IPv4 and IPv6 exist, prefer IPv4 for egress runner compatibility
        mock_sys = MagicMock(
            return_value=[
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            ]
        )
        resolver = ResolverService(system_resolver=mock_sys)
        res = resolver.resolve("dual-stack.com")
        self.assertEqual(res.pinned_ip, "93.184.216.34")
        self.assertIn("93.184.216.34", res.ipv4_addresses)
        self.assertIn("2606:2800:220:1:248:1893:25c8:1946", res.ipv6_addresses)


if __name__ == "__main__":
    unittest.main()
