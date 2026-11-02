"""Time-based blind injection oracle: statistical delay gate, reproduced across trials."""

import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from packages.scanner_adapters.integrations import vuln_scanner
from packages.security_policies import Destination


class TimeBasedBlindOracleTests(unittest.TestCase):
    _dest = Destination(
        "https://example.com/", "https", "example.com", 443, "/", "https://example.com", "93.184.216.34"
    )

    @staticmethod
    def _payload_value(path):
        qs = parse_qs(urlsplit(path).query)
        for key in ("id", "q", "search", "cmd", "ip"):
            if key in qs:
                return qs[key][0]
        return ""

    def _run(self, sleep_ms, baseline_ms=100.0):
        """sleep_ms: elapsed returned for any sleep/delay payload; baseline for everything else."""

        def fake_request(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5):
            v = self._payload_value(path).lower()
            is_sleep = any(tok in v for tok in ("sleep", "pg_sleep", "waitfor", "delay"))
            return 200, {}, "", (sleep_ms if is_sleep else baseline_ms)

        with mock.patch.object(vuln_scanner, "_request_endpoint", side_effect=fake_request):
            res = vuln_scanner.audit_deep_vulnerabilities(self._dest, "93.184.216.34", [], ["id"])
        return {f["title"] for f in res["findings"]}

    def test_confirms_blind_sqli_when_delay_clears_threshold(self):
        # baseline 100ms, threshold = 100 + 0 + 5000 = 5100ms; a 5200ms sleep clears it on all 3 trials.
        titles = self._run(sleep_ms=5200.0)
        self.assertTrue(any(t.startswith("Time-Based Blind SQL Injection") for t in titles))

    def test_rejects_when_delay_below_statistical_threshold(self):
        # 5050ms < 5100ms threshold -> jitter, not an injection; no time-based finding.
        titles = self._run(sleep_ms=5050.0)
        self.assertFalse(any("Time-Based Blind" in t for t in titles))

    def test_rejects_when_baseline_is_already_slow(self):
        # Slow site (baseline 6000ms) raises the threshold to ~11000ms; a 6000ms sleep cannot confirm.
        titles = self._run(sleep_ms=6000.0, baseline_ms=6000.0)
        self.assertFalse(any("Time-Based Blind" in t for t in titles))


if __name__ == "__main__":
    unittest.main()
