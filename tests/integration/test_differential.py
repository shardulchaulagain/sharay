"""Unit tests for active differential response testing."""

import unittest
from unittest.mock import patch

from packages.scanner_adapters.integrations.differential import run_differential_tests
from packages.security_policies import Destination


class DifferentialTestingTests(unittest.TestCase):
    _dest = Destination(
        "https://example.com/", "https", "example.com", 443, "/", "https://example.com", "example.com"
    )

    def test_differential_detects_trace_xst(self):
        def fake_probe(dest, allow_ip, method, path, headers, timeout=4.0):
            if method == "TRACE":
                return 200, {}, "TRACE / HTTP/1.1\r\nUser-Agent: SHARAY-DiffTester/1.0", 12.0
            return 200, {}, "<html>Normal Page</html>", 10.0

        with patch("packages.scanner_adapters.integrations.differential._send_probe", side_effect=fake_probe):
            res = run_differential_tests(self._dest, "93.184.216.34")

        findings = res["findings"]
        self.assertTrue(any(f["cwe_id"] == "CWE-205" for f in findings))
        self.assertTrue(any("TRACE" in f["title"] for f in findings))

    def test_differential_detects_dynamic_cors_reflection(self):
        def fake_probe(dest, allow_ip, method, path, headers, timeout=4.0):
            if headers.get("Origin") == "https://sharay-attacker.invalid":
                return (
                    200,
                    {
                        "access-control-allow-origin": "https://sharay-attacker.invalid",
                        "access-control-allow-credentials": "true",
                    },
                    "ok",
                    15.0,
                )
            return 200, {}, "<html>Normal Page</html>", 10.0

        with patch("packages.scanner_adapters.integrations.differential._send_probe", side_effect=fake_probe):
            res = run_differential_tests(self._dest, "93.184.216.34")

        findings = res["findings"]
        self.assertTrue(any(f["cwe_id"] == "CWE-942" for f in findings))
        cors_f = next(f for f in findings if f["cwe_id"] == "CWE-942")
        self.assertEqual(cors_f["severity"], "high")

    def test_differential_detects_parameter_reflection(self):
        import hashlib

        canary = f"sharay{hashlib.md5(self._dest.host.encode()).hexdigest()[:8]}"

        def fake_probe(dest, allow_ip, method, path, headers, timeout=4.0):
            if "sharay" in path:
                # Return unencoded reflection inside tag
                return 200, {}, f"<div>Input: <span>{canary}</span></div>", 10.0
            return 200, {}, "<div>Normal Baseline</div>", 10.0

        with patch("packages.scanner_adapters.integrations.differential._send_probe", side_effect=fake_probe):
            res = run_differential_tests(self._dest, "93.184.216.34", parameters=["q"])

        findings = res["findings"]
        self.assertTrue(any(f["cwe_id"] == "CWE-79" for f in findings))

    def test_differential_detects_verb_tampering_bypass(self):
        def fake_probe(dest, allow_ip, method, path, headers, timeout=4.0):
            if path == "/admin":
                if method == "GET":
                    return 403, {}, "Forbidden", 10.0
                if method == "HEAD":
                    return 200, {}, "", 10.0
            return 200, {}, "Normal", 10.0

        with patch("packages.scanner_adapters.integrations.differential._send_probe", side_effect=fake_probe):
            res = run_differential_tests(self._dest, "93.184.216.34", endpoints=["/admin"])

        findings = res["findings"]
        self.assertTrue(any(f["cwe_id"] == "CWE-288" for f in findings))
        bypass_f = next(f for f in findings if f["cwe_id"] == "CWE-288")
        self.assertEqual(bypass_f["severity"], "high")
        self.assertIn("HEAD", bypass_f["title"])


if __name__ == "__main__":
    unittest.main()
