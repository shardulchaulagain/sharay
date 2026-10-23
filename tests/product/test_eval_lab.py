"""End-to-End Evaluation Test using in-process VulnerableMockServer and BenchmarkEvaluator (Requirements K1, K2, K3)."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests.fixtures.eval_lab.evaluator import BenchmarkEvaluator
from tests.fixtures.eval_lab.vulnerable_mock_server import VulnerableMockServer


class TestEvalLabBenchmark(unittest.TestCase):
    """Asserts that findings evaluated against ground truth meet precision and FPR gates."""

    @classmethod
    def setUpClass(cls):
        cls.server = VulnerableMockServer()
        cls.server.start()
        cls.catalog_path = (
            Path(__file__).parent.parent / "fixtures" / "eval_lab" / "ground_truth_catalog.json"
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_01_mock_server_endpoints(self):
        # Verify SQLi endpoint triggers anomaly on single quote
        import urllib.request

        with urllib.request.urlopen(f"{self.server.url}/vulnerabilities/sqli/?id=1'") as resp:
            body = resp.read()
            self.assertIn(b"SQL syntax", body)

        # Verify Command Injection endpoint triggers canary on semicolon
        with urllib.request.urlopen(
            f"{self.server.url}/ping.php?ip=127.0.0.1%3B+echo+sharay_canary_cmd"
        ) as resp:
            body = resp.read()
            self.assertIn(b"sharay_canary_cmd", body)

    def test_02_benchmark_evaluator_scoring(self):
        # Synthetic findings accurately reflecting ground truth
        simulated_findings = [
            {
                "cwe_id": "CWE-89",
                "affected_url": f"{self.server.url}/vulnerabilities/sqli/?id=1",
                "title": "SQL Injection in parameter id",
                "poc": {"parameter": "id", "payload": "1' OR '1'='1"},
            },
            {
                "cwe_id": "CWE-78",
                "affected_url": f"{self.server.url}/ping.php?ip=127.0.0.1",
                "title": "OS Command Injection in parameter ip",
                "poc": {"parameter": "ip", "payload": "; echo canary"},
            },
            {
                "cwe_id": "CWE-918",
                "affected_url": f"{self.server.url}/fetch.php?url=http://127.0.0.1",
                "title": "Server-Side Request Forgery in parameter url",
                "poc": {"parameter": "url", "payload": "http://127.0.0.1"},
            },
            {
                "cwe_id": "CWE-200",
                "affected_url": f"{self.server.url}/phpinfo.php",
                "title": "PHP Information Disclosure",
                "poc": {},
            },
        ]

        metrics = BenchmarkEvaluator.evaluate(simulated_findings, self.catalog_path)
        self.assertEqual(metrics.total_ground_truth, 5)
        self.assertEqual(metrics.true_positives, 4)
        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.false_negatives, 1)  # GT-SECRET-01 undetected
        self.assertEqual(metrics.precision, 1.0)  # 100% precision
        self.assertEqual(metrics.recall, 0.8)  # 4/5, bounded by 1.0
        self.assertEqual(metrics.false_discovery_rate, 0.0)  # no spurious findings
        self.assertEqual(metrics.false_positive_rate, 0.0)  # no benign endpoint flagged
        self.assertTrue(metrics.passes_gate())


class BenchmarkScorerSoundnessTests(unittest.TestCase):
    """E08/F19: the scorer must not yield impossible metrics."""

    def _catalog(self, data: dict) -> str:
        import json
        import tempfile

        path = tempfile.mktemp(suffix=".json")
        Path(path).write_text(json.dumps(data), encoding="utf-8")
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))
        return path

    def test_empty_cwe_and_duplicates_do_not_inflate(self):
        cat = self._catalog(
            {"vulnerabilities": [{"id": "GT-1", "cwe": "CWE-89", "endpoint": "/x", "parameter": None}]}
        )
        findings = [{"cwe_id": "", "affected_url": "http://other/nope", "poc": {}} for _ in range(3)]
        m = BenchmarkEvaluator.evaluate(findings, cat)
        self.assertEqual(m.true_positives, 0)  # empty CWE must not match
        self.assertEqual(m.false_positives, 3)
        self.assertLessEqual(m.recall, 1.0)
        self.assertEqual(m.recall, 0.0)
        self.assertFalse(m.passes_gate())

    def test_cwe_match_is_exact_not_substring(self):
        # Finding targets the entry's endpoint but names a different CWE (CWE-7, not CWE-79): the
        # conflicting CWE blocks the match, so it is a false positive, not a substring true positive.
        cat = self._catalog(
            {"vulnerabilities": [{"id": "GT-X", "cwe": "CWE-79", "endpoint": "/e", "parameter": None}]}
        )
        m = BenchmarkEvaluator.evaluate([{"cwe_id": "CWE-7", "affected_url": "http://t/e", "poc": {}}], cat)
        self.assertEqual(m.true_positives, 0)  # CWE-7 is not CWE-79
        self.assertEqual(m.false_positives, 1)

    def test_redundant_detections_of_one_vuln_count_once(self):
        cat = self._catalog(
            {"vulnerabilities": [{"id": "GT-X", "cwe": "CWE-79", "endpoint": "/e", "parameter": None}]}
        )
        findings = [{"cwe_id": "CWE-79", "affected_url": "http://t/e", "poc": {}} for _ in range(3)]
        m = BenchmarkEvaluator.evaluate(findings, cat)
        self.assertEqual(m.true_positives, 1)
        self.assertEqual(m.recall, 1.0)

    def test_fpr_is_none_without_a_negative_corpus(self):
        cat = self._catalog(
            {"vulnerabilities": [{"id": "GT-X", "cwe": "CWE-79", "endpoint": "/e", "parameter": None}]}
        )
        m = BenchmarkEvaluator.evaluate([], cat)
        self.assertIsNone(m.false_positive_rate)


if __name__ == "__main__":
    unittest.main()
