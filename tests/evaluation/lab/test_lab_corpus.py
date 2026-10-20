"""Integration and Acceptance Tests for Evaluation Lab Ground-Truth Corpus.

Validates that:
1. Paired vulnerable and patched endpoints are loaded from tests/evaluation/lab/ground_truth_manifest.json.
2. AutoPyVerifier and native detector oracles confirm vulnerabilities against the vulnerable fixture.
3. AutoPyVerifier and native detector oracles achieve ZERO false positives against the patched fixture.
4. Generates an empirical, reproducible scorecard artifact.
"""

from __future__ import annotations

import http.server
import json
import threading
import unittest
from pathlib import Path

from packages.evaluation_lab import (
    EvaluationLabRunner,
    get_ground_truth_corpus,
)
from services.ai_analysis_worker.autopyverifier import AutoPyVerifier
from tests.evaluation.lab.fixtures import PatchedLabHandler, VulnerableLabHandler


class TestLabCorpusExecution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 1. Start Vulnerable Server on localhost
        cls.vuln_server = http.server.HTTPServer(("127.0.0.1", 0), VulnerableLabHandler)
        cls.vuln_port = cls.vuln_server.server_port
        cls.vuln_thread = threading.Thread(target=cls.vuln_server.serve_forever, daemon=True)
        cls.vuln_thread.start()

        # 2. Start Patched Server on localhost
        cls.patched_server = http.server.HTTPServer(("127.0.0.1", 0), PatchedLabHandler)
        cls.patched_port = cls.patched_server.server_port
        cls.patched_thread = threading.Thread(target=cls.patched_server.serve_forever, daemon=True)
        cls.patched_thread.start()

        cls.verifier = AutoPyVerifier()
        cls.runner = EvaluationLabRunner(get_ground_truth_corpus())

    @classmethod
    def tearDownClass(cls):
        cls.vuln_server.shutdown()
        cls.vuln_server.server_close()
        cls.patched_server.shutdown()
        cls.patched_server.server_close()

    def test_manifest_file_exists_and_matches_corpus(self):
        manifest_path = Path(__file__).parent / "ground_truth_manifest.json"
        self.assertTrue(manifest_path.is_file())
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertGreaterEqual(data["total_cases"], 10)
        self.assertEqual(len(data["cases"]), data["total_cases"])

    def test_evaluation_runner_metrics_on_ground_truth_corpus(self):
        from packages.evaluation_lab import DEFAULT_REFERENCE_DETECTORS

        report = self.runner.generate_benchmark_scorecard(DEFAULT_REFERENCE_DETECTORS)
        summary = report["summary"]

        # Assert empirical metrics: zero false positives across all classes
        self.assertEqual(summary["overall_false_positive_rate"], 0.0)
        self.assertEqual(summary["overall_precision"], 1.0)
        self.assertGreaterEqual(summary["overall_recall"], 0.85)
        self.assertEqual(summary["status"], "PASS")

    def test_live_autopyverifier_differential_against_fixtures(self):
        # 1. Test SQLi: Vulnerable returns Union data -> verified
        v_script = self.verifier.synthesize_script(
            target_url=f"http://127.0.0.1:{self.vuln_port}/api/products",
            vuln_type="sqli",
            payload="' UNION SELECT username, password_hash FROM users --",
            canary="admin",
            method="GET",
            parameter="q",
            mock_mode=False,
        )
        res_v = self.verifier.execute_in_sandbox(v_script, timeout_seconds=5)
        self.assertEqual(res_v["returncode"], 0)
        self.assertEqual(res_v["status"], "verified")

        # 2. Test SQLi: Patched returns [] -> failed / demoted
        p_script = self.verifier.synthesize_script(
            target_url=f"http://127.0.0.1:{self.patched_port}/api/products",
            vuln_type="sqli",
            payload="' UNION SELECT username, password_hash FROM users --",
            canary="admin",
            method="GET",
            parameter="q",
            mock_mode=False,
        )
        res_p = self.verifier.execute_in_sandbox(p_script, timeout_seconds=5)
        self.assertNotEqual(res_p["returncode"], 0)
        self.assertEqual(res_p["status"], "failed")

        # 3. Test CMDi: Vulnerable executes command -> verified
        v_cmd_script = self.verifier.synthesize_script(
            target_url=f"http://127.0.0.1:{self.vuln_port}/tools/ping",
            vuln_type="cmdi",
            payload="127.0.0.1; id",
            canary="uid=1000",
            method="GET",
            parameter="host",
            mock_mode=False,
        )
        res_v_cmd = self.verifier.execute_in_sandbox(v_cmd_script, timeout_seconds=5)
        self.assertEqual(res_v_cmd["returncode"], 0)
        self.assertEqual(res_v_cmd["status"], "verified")

        # 4. Test CMDi: Patched rejects non-IP -> failed / demoted
        p_cmd_script = self.verifier.synthesize_script(
            target_url=f"http://127.0.0.1:{self.patched_port}/tools/ping",
            vuln_type="cmdi",
            payload="127.0.0.1; id",
            canary="uid=1000",
            method="GET",
            parameter="host",
            mock_mode=False,
        )
        res_p_cmd = self.verifier.execute_in_sandbox(p_cmd_script, timeout_seconds=5)
        self.assertNotEqual(res_p_cmd["returncode"], 0)
        self.assertEqual(res_p_cmd["status"], "failed")


if __name__ == "__main__":
    unittest.main()
