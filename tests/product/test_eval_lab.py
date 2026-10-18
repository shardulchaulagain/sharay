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
        self.assertEqual(metrics.precision, 1.0)  # 100% precision
        self.assertEqual(metrics.false_positive_rate, 0.0)  # 0% FPR
        self.assertTrue(metrics.passes_gate())


if __name__ == "__main__":
    unittest.main()
