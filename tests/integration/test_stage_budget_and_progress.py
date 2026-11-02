"""Per-stage budget: each stage gets its own timeout (no shared-pool squeeze), plus live progress."""

import unittest
from types import SimpleNamespace

from packages.scanner_adapters import scan_comprehensive, scan_live_nuclei, scan_live_zap
from packages.security_policies import Destination


class StageBudgetAndProgressTests(unittest.TestCase):
    def setUp(self):
        self.dest = Destination(
            url="http://203.0.113.10/", scheme="http", host="203.0.113.10", port=80,
            origin="http://203.0.113.10", ip="203.0.113.10", path="/",
        )
        self.loopback_dest = Destination(
            url="http://127.0.0.1:9/", scheme="http", host="127.0.0.1", port=9,
            origin="http://127.0.0.1:9", ip="127.0.0.1", path="/",
        )

    def _capture_timeout(self, fn):
        seen: dict[str, float] = {}

        def runner(image, argv, **kwargs):
            seen["max_seconds"] = kwargs.get("max_seconds", 0.0)
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=b"", output_truncated=False)

        fn(runner)
        return seen.get("max_seconds")

    def test_stage_honors_full_operator_timeout_no_300_clamp(self):
        # Before the redesign every stage was clamped to 300s; now a stage honors the full per-stage
        # value (up to the 600s ceiling), so a large site is not silently truncated.
        got = self._capture_timeout(
            lambda r: scan_live_nuclei(self.dest, "203.0.113.10", run=r, max_seconds=600)
        )
        self.assertEqual(got, 600.0)
        got_zap = self._capture_timeout(
            lambda r: scan_live_zap(self.dest, "203.0.113.10", run=r, max_seconds=450)
        )
        self.assertEqual(got_zap, 450.0)

    def test_stage_timeout_bounded_by_ceiling(self):
        got = self._capture_timeout(
            lambda r: scan_live_nuclei(self.dest, "203.0.113.10", run=r, max_seconds=5000)
        )
        self.assertEqual(got, 600.0)  # clamped to _STAGE_TIMEOUT_CAP, not unbounded

    def test_progress_reports_live_stage_names(self):
        stages: list[str] = []

        def runner(image, argv, **kwargs):
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=b"", output_truncated=False)

        scan_comprehensive(
            self.loopback_dest, "127.0.0.1", run=runner,
            tools=["crawler", "nuclei", "zap", "verification"], mode="standard",
            progress=stages.append,
        )
        joined = " | ".join(stages)
        self.assertIn("Nuclei vulnerability scan", joined)
        self.assertIn("OWASP ZAP web scan", joined)
        self.assertIn("Vulnerability verification", joined)
        self.assertIn("Port & service discovery", joined)


if __name__ == "__main__":
    unittest.main()
