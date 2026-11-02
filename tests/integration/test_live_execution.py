"""Live-target execution path: ownership gate, DNS-pin SSRF guard, and egress-locked header scan."""

import unittest
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from packages.scanner_adapters import _parse_http_headers, scan_live
from packages.security_policies import (
    Destination,
    PolicyError,
    ScopePolicy,
    check_execution_url,
    resolve_pinned,
)


def _scope(host, origin):
    return ScopePolicy.model_validate(
        {
            "hosts": [host],
            "allowed_origins": [origin],
            "allowed_paths": ["/"],
            "allowed_cidrs": ["127.0.0.1/32"] if host == "127.0.0.1" else [],
            "categories": ["http_headers"],
            "starts_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        }
    )


class ExecutionGateTests(unittest.TestCase):
    def test_loopback_allowed_without_ownership(self):
        d = check_execution_url(_scope("127.0.0.1", "https://127.0.0.1"), "https://127.0.0.1/")
        self.assertEqual(d.host, "127.0.0.1")

    def test_live_requires_ownership(self):
        scope = _scope("example.com", "https://example.com")
        with self.assertRaisesRegex(PolicyError, "verified target ownership"):
            check_execution_url(scope, "https://example.com/", owned=False)
        self.assertEqual(check_execution_url(scope, "https://example.com/", owned=True).host, "example.com")

    def test_private_literal_refused_even_when_owned(self):
        scope = _scope("192.168.1.50", "https://192.168.1.50")
        with self.assertRaisesRegex(PolicyError, "public addresses"):
            check_execution_url(scope, "https://192.168.1.50/", owned=True)


class ResolvePinnedTests(unittest.TestCase):
    @staticmethod
    def _res(*ips):
        return lambda host, port: [(2, 1, 6, "", (ip, 0)) for ip in ips]

    def test_public_is_pinned(self):
        self.assertEqual(resolve_pinned("example.com", resolver=self._res("93.184.216.34")), "93.184.216.34")

    def test_private_loopback_and_split_are_refused(self):
        for ips in (("127.0.0.1",), ("10.0.0.5",), ("93.184.216.34", "169.254.1.1")):
            with self.assertRaises(PolicyError):
                resolve_pinned("example.com", resolver=self._res(*ips))

    def test_literal_private_refused(self):
        with self.assertRaises(PolicyError):
            resolve_pinned("192.168.1.1")


class ScanLiveTests(unittest.TestCase):
    _dest = Destination(
        "https://example.com/", "https", "example.com", 443, "/", "https://example.com", "example.com"
    )

    def test_headers_become_findings_over_pinned_egress(self):
        raw = b"HTTP/2 200 \r\ncontent-type: text/html\r\nserver: nginx\r\n\r\n"
        seen = {}

        def run(image, argv, *, allow_ip, allow_port, max_seconds):
            seen.update(argv=argv, allow_ip=allow_ip, allow_port=allow_port)
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=raw, output_truncated=False)

        result = scan_live(self._dest, "93.184.216.34", run=run)
        self.assertEqual(result["outcome"], "completed")
        self.assertTrue(result["findings"])  # missing security headers detected
        self.assertIn("example.com:443:93.184.216.34", seen["argv"])  # connection pinned to the IP
        self.assertEqual((seen["allow_ip"], seen["allow_port"]), ("93.184.216.34", 443))
        self.assertEqual(result["checks"][0]["url"], "https://example.com/")

    def test_failed_fetch_reports_failed(self):
        def run(*a, **k):
            return SimpleNamespace(outcome="failed", exit_code=1, stdout=b"", output_truncated=False)

        res = scan_live(self._dest, "93.184.216.34", run=run)
        self.assertEqual(res["outcome"], "failed")
        self.assertEqual(res["checks"][0]["url"], "https://example.com/")

    def test_oversized_header_output_is_rejected(self):
        huge_raw = b"HTTP/1.1 200 OK\r\nX-Custom: " + (b"A" * 70000) + b"\r\n\r\n"

        def run(*a, **k):
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=huge_raw, output_truncated=False)

        res = scan_live(self._dest, "93.184.216.34", run=run)
        self.assertEqual(res["outcome"], "failed")
        self.assertEqual(res["checks"][0]["status"], "failed")
        self.assertIn("exceeds maximum", res["checks"][0]["detail"])

    def test_status_zero_response_is_rejected_honestly(self):
        def run(*a, **k):
            return SimpleNamespace(
                outcome="completed",
                exit_code=0,
                stdout=b"Garbage without HTTP status\r\n\r\n",
                output_truncated=False,
            )

        res = scan_live(self._dest, "93.184.216.34", run=run)
        self.assertEqual(res["outcome"], "failed")
        self.assertEqual(res["checks"][0]["status"], "failed")
        self.assertIn("No valid HTTP response status", res["checks"][0]["detail"])

    def test_cgnat_rfc6598_and_loopback_refused_by_execution_scope(self):
        from packages.security_policies import PolicyError, check_execution_url
        from tests.product.test_broad_scope import broad_scope

        scope = broad_scope("100.64.0.1")
        with self.assertRaises(PolicyError) as ctx:
            check_execution_url(scope, "https://100.64.0.1/", owned=True)
        self.assertIn("Live targets must be public addresses", str(ctx.exception))

        scope_lb = broad_scope("127.0.0.2")
        with self.assertRaises(PolicyError) as ctx2:
            check_execution_url(scope_lb, "https://127.0.0.2/", owned=True)
        self.assertIn("Live targets must be public addresses", str(ctx2.exception))

    def test_header_parser_takes_final_block(self):
        status, headers = _parse_http_headers("HTTP/1.1 301\r\nlocation: /x\r\n\r\nHTTP/2 200\r\nx-y: z\r\n")
        self.assertEqual(status, 200)
        self.assertEqual(headers, [("x-y", "z")])


class ScanLiveNucleiTests(unittest.TestCase):
    _dest = Destination(
        "https://example.com/", "https", "example.com", 443, "/", "https://example.com", "example.com"
    )

    def test_jsonl_becomes_findings_and_logs_are_filtered(self):
        from packages.scanner_adapters import scan_live_nuclei

        raw = (
            b"[INF] Templates loaded: 14036\n"  # a 2>&1-merged log line must not break strict parsing
            b'{"template-id":"tls-version","info":{"name":"TLS Version","severity":"info"},"matched-at":"example.com:443"}\n'
            b'{"template-id":"CVE-2023-1","info":{"name":"Example RCE","severity":"critical"},"matched-at":"https://example.com/x"}\n'
        )
        seen = {}

        def run(image, argv, *, allow_ip, allow_port, add_host, mount_volume, max_seconds, memory_mb):
            seen.update(add_host=add_host, mount_volume=mount_volume, duc="-duc" in argv)
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=raw, output_truncated=False)

        r = scan_live_nuclei(self._dest, "93.184.216.34", run=run, severities="info,critical")
        self.assertEqual(r["outcome"], "completed")
        self.assertEqual(len(r["findings"]), 2)  # the [INF] line was filtered, both JSONL rows parsed
        self.assertTrue(all(f["fingerprint"].startswith("nuclei:") for f in r["findings"]))
        self.assertEqual(seen["add_host"], "example.com:93.184.216.34")  # pinned, no DNS
        self.assertEqual(seen["mount_volume"], "sharay-nuclei-templates:/tpl:ro")  # offline templates
        self.assertTrue(seen["duc"])  # no update fetch

    def test_runner_failure_is_reported(self):
        from packages.scanner_adapters import scan_live_nuclei

        def run(*a, **k):
            raise RuntimeError("no runtime")

        self.assertEqual(scan_live_nuclei(self._dest, "93.184.216.34", run=run)["outcome"], "failed")


if __name__ == "__main__":
    unittest.main()
