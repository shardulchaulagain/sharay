"""Comprehensive 30-case verification test suite for TargetNormaliser (Requirement A1)."""

from __future__ import annotations

import unittest

from packages.security_policies.normalizer import (
    NormalizationError,
    TargetNormaliser,
)


class TestTargetNormaliser(unittest.TestCase):
    """30-case fixture suite verifying 100% pass on dirty, malicious, and edge-case inputs."""

    # 1. Full URL with scheme, port, path, query, and fragment
    def test_01_full_url_parsing(self):
        res = TargetNormaliser.normalize_single("https://host.example.com:8443/api/v1/scan?depth=2#heading")
        self.assertEqual(res.host, "host.example.com")
        self.assertEqual(res.port, 8443)
        self.assertEqual(res.scheme, "https")
        self.assertEqual(res.path, "/api/v1/scan?depth=2")
        self.assertFalse(res.is_literal_ip)
        self.assertEqual(res.origin, "https://host.example.com:8443")

    # 2. User credentials stripped from URL
    def test_02_credentials_stripped(self):
        res = TargetNormaliser.normalize_single("http://admin:SecretPass123!@target.corp:8080/dashboard")
        self.assertEqual(res.host, "target.corp")
        self.assertEqual(res.port, 8080)
        self.assertEqual(res.scheme, "http")
        self.assertNotIn("admin", res.url)
        self.assertNotIn("SecretPass123", res.url)

    # 3. Trailing CRLF and spaces scrubbed
    def test_03_crlf_and_whitespace_scrubbing(self):
        res = TargetNormaliser.normalize_single("  api.target.com\r\n")
        self.assertEqual(res.host, "api.target.com")
        self.assertIsNone(res.port)

    # 4. Zero-width spaces scrubbed
    def test_04_zero_width_spaces(self):
        # \u200b is zero-width space, \ufeff is BOM
        res = TargetNormaliser.normalize_single("sub\u200b.\ufefftarget\u200e.com")
        self.assertEqual(res.host, "sub.target.com")

    # 5. Non-breaking spaces scrubbed
    def test_05_non_breaking_spaces(self):
        res = TargetNormaliser.normalize_single("\u00a0target.org\u00a0")
        self.assertEqual(res.host, "target.org")

    # 6. Typographic en-dash and em-dash normalized to ASCII hyphen
    def test_06_dashes_normalized(self):
        # \u2013 is en-dash, \u2014 is em-dash
        res = TargetNormaliser.normalize_single("my\u2013secure\u2014site.com")
        self.assertEqual(res.host, "my-secure-site.com")

    # 7. Internationalized Domain Name (IDN) punycoded
    def test_07_idn_punycode(self):
        res = TargetNormaliser.normalize_single("münchen.de")
        self.assertEqual(res.host, "xn--mnchen-3ya.de")

    # 8. Another IDN punycode test
    def test_08_idn_punycode_cyrillic(self):
        res = TargetNormaliser.normalize_single("россия.рф")
        self.assertTrue(res.host.startswith("xn--"))

    # 9. Bare IPv4 literal short-circuited (skip DNS)
    def test_09_bare_ipv4_literal(self):
        res = TargetNormaliser.normalize_single("192.168.1.100")
        self.assertEqual(res.host, "192.168.1.100")
        self.assertTrue(res.is_literal_ip)
        self.assertFalse(res.is_ipv6)

    # 10. IPv4 literal with port
    def test_10_ipv4_with_port(self):
        res = TargetNormaliser.normalize_single("10.0.0.1:4280")
        self.assertEqual(res.host, "10.0.0.1")
        self.assertEqual(res.port, 4280)
        self.assertTrue(res.is_literal_ip)

    # 11. URL with IPv4 literal
    def test_11_url_with_ipv4(self):
        res = TargetNormaliser.normalize_single("https://178.79.134.182:4280/vulnerabilities/sqli/")
        self.assertEqual(res.host, "178.79.134.182")
        self.assertEqual(res.port, 4280)
        self.assertEqual(res.path, "/vulnerabilities/sqli/")
        self.assertTrue(res.is_literal_ip)

    # 12. Bare IPv6 loopback
    def test_12_bare_ipv6_loopback(self):
        res = TargetNormaliser.normalize_single("::1")
        self.assertEqual(res.host, "::1")
        self.assertTrue(res.is_literal_ip)
        self.assertTrue(res.is_ipv6)
        self.assertEqual(res.origin, "https://[::1]")

    # 13. Bracketed IPv6 with port
    def test_13_bracketed_ipv6_with_port(self):
        res = TargetNormaliser.normalize_single("[2001:db8::1]:8443")
        self.assertEqual(res.host, "2001:db8::1")
        self.assertEqual(res.port, 8443)
        self.assertTrue(res.is_literal_ip)
        self.assertTrue(res.is_ipv6)
        self.assertEqual(res.origin, "https://[2001:db8::1]:8443")

    # 14. URL with bracketed IPv6
    def test_14_url_with_ipv6(self):
        res = TargetNormaliser.normalize_single("http://[fe80::1ff:fe23:4567:890a]:80/status")
        self.assertEqual(res.host, "fe80::1ff:fe23:4567:890a")
        self.assertEqual(res.port, 80)
        self.assertEqual(res.scheme, "http")

    # 15. Hostname uppercase to lowercase
    def test_15_uppercase_lowercasing(self):
        res = TargetNormaliser.normalize_single("SCANNER-TARGET.EXAMPLE.COM")
        self.assertEqual(res.host, "scanner-target.example.com")

    # 16. Trailing dot stripped from FQDN
    def test_16_trailing_dot_fqdn(self):
        res = TargetNormaliser.normalize_single("defense.pentest.local.")
        self.assertEqual(res.host, "defense.pentest.local")

    # 17. CIDR /30 expansion into 4 hosts
    def test_17_cidr_expansion_slash_30(self):
        targets = TargetNormaliser.normalize("192.168.1.0/30")
        self.assertEqual(len(targets), 4)
        hosts = [t.host for t in targets]
        self.assertEqual(hosts, ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"])
        for t in targets:
            self.assertTrue(t.is_literal_ip)

    # 18. CIDR /32 single host
    def test_18_cidr_slash_32(self):
        targets = TargetNormaliser.normalize("10.5.5.5/32")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].host, "10.5.5.5")

    # 19. Hyphenated IPv4 range expansion
    def test_19_hyphenated_ip_range(self):
        targets = TargetNormaliser.normalize("10.0.0.1-4")
        self.assertEqual(len(targets), 4)
        hosts = [t.host for t in targets]
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])

    # 20. Hyphenated range inverted bounds (4-1) handled safely
    def test_20_hyphenated_range_inverted(self):
        targets = TargetNormaliser.normalize("10.0.0.4-1")
        self.assertEqual(len(targets), 4)
        hosts = [t.host for t in targets]
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])

    # 21. Idempotency test (normalizing already normalized URL is byte-identical)
    def test_21_idempotency(self):
        raw = "https://pentest-ground.com:4280/vulnerabilities/sqli/"
        res1 = TargetNormaliser.normalize_single(raw)
        res2 = TargetNormaliser.normalize_single(res1.url)
        self.assertEqual(res1.host, res2.host)
        self.assertEqual(res1.port, res2.port)
        self.assertEqual(res1.origin, res2.origin)
        self.assertEqual(res1.url, res2.url)

    # 22. Bare host with custom subpath (no scheme)
    def test_22_host_with_path_no_scheme(self):
        res = TargetNormaliser.normalize_single("target.io/admin/login")
        self.assertEqual(res.host, "target.io")
        self.assertEqual(res.path, "/admin/login")
        self.assertEqual(res.scheme, "https")

    # 23. Host with port and path (no scheme)
    def test_23_host_port_path_no_scheme(self):
        res = TargetNormaliser.normalize_single("target.io:9000/metrics")
        self.assertEqual(res.host, "target.io")
        self.assertEqual(res.port, 9000)
        self.assertEqual(res.path, "/metrics")

    # 24. Invalid port > 65535 raises NormalizationError
    def test_24_port_out_of_range(self):
        with self.assertRaises(NormalizationError) as ctx:
            TargetNormaliser.normalize_single("target.com:70000")
        self.assertEqual(ctx.exception.code, "PORT_OUT_OF_RANGE")

    # 25. Port 0 raises NormalizationError
    def test_25_port_zero_invalid(self):
        with self.assertRaises(NormalizationError) as ctx:
            TargetNormaliser.normalize_single("target.com:0")
        self.assertEqual(ctx.exception.code, "PORT_OUT_OF_RANGE")

    # 26. Unsupported scheme (ftp://) raises NormalizationError
    def test_26_unsupported_scheme(self):
        with self.assertRaises(NormalizationError) as ctx:
            TargetNormaliser.normalize_single("ftp://ftp.example.com/files")
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_SCHEME")

    # 27. Empty target raises NormalizationError
    def test_27_empty_target(self):
        with self.assertRaises(NormalizationError) as ctx:
            TargetNormaliser.normalize_single("   \r\n\t  ")
        self.assertEqual(ctx.exception.code, "EMPTY_TARGET")

    # 28. Malformed IPv6 brackets raises NormalizationError
    def test_28_malformed_ipv6_brackets(self):
        with self.assertRaises(NormalizationError) as ctx:
            TargetNormaliser.normalize_single("[2001:db8::1")
        self.assertEqual(ctx.exception.code, "MALFORMED_IPV6")

    # 29. CIDR block exceeding safe expansion ceiling raises NormalizationError
    def test_29_cidr_expansion_limit(self):
        with self.assertRaises(NormalizationError) as ctx:
            TargetNormaliser.normalize("10.0.0.0/16", max_expansion=256)
        self.assertEqual(ctx.exception.code, "CIDR_TOO_LARGE")

    # 30. Invalid characters in hostname
    def test_30_invalid_hostname_chars(self):
        with self.assertRaises(NormalizationError) as ctx:
            TargetNormaliser.normalize_single("bad_target;rm -rf /")
        self.assertEqual(ctx.exception.code, "INVALID_HOSTNAME")


if __name__ == "__main__":
    unittest.main()
