"""Test suite for Ground-Truth Evaluation Lab and Detector Benchmarking (Sector 10)."""

from __future__ import annotations

import unittest

from packages.evaluation_lab import (
    DEFAULT_REFERENCE_DETECTORS,
    EvaluationBenchmarkRunner,
    VulnClass,
    get_ground_truth_corpus,
    reference_cmdi_detector,
    reference_lfi_detector,
    reference_sqli_detector,
    reference_ssrf_detector,
    reference_xss_detector,
)


class EvaluationLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = get_ground_truth_corpus()
        self.runner = EvaluationBenchmarkRunner(self.corpus)

    def test_corpus_has_paired_vulnerable_and_patched_cases_per_class(self) -> None:
        """Every vulnerability class must have at least one vulnerable and one patched case."""
        for vuln_class in VulnClass:
            cases = [c for c in self.corpus if c.vuln_class == vuln_class]
            self.assertGreaterEqual(len(cases), 2, f"Missing cases for {vuln_class.value}")

            vuln_cases = [c for c in cases if c.is_vulnerable]
            patched_cases = [c for c in cases if not c.is_vulnerable]

            self.assertGreaterEqual(len(vuln_cases), 1, f"No vulnerable cases for {vuln_class.value}")
            self.assertGreaterEqual(len(patched_cases), 1, f"No patched cases for {vuln_class.value}")

            for p in patched_cases:
                self.assertTrue(len(p.remediation_technique) > 0)

    def test_sqli_detector_metrics_zero_false_positives(self) -> None:
        """SQLi detector achieves 100% precision and zero false positives on negative controls."""
        metrics = self.runner.run_benchmark(
            detector_fn=reference_sqli_detector,
            target_vuln_class=VulnClass.SQL_INJECTION,
        )

        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.false_positive_rate, 0.0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.f1_score, 1.0)
        self.assertGreaterEqual(metrics.true_positives, 2)
        self.assertGreaterEqual(metrics.true_negatives, 2)

    def test_xss_detector_metrics_zero_false_positives(self) -> None:
        """XSS detector achieves 100% precision and zero false positives on negative controls."""
        metrics = self.runner.run_benchmark(
            detector_fn=reference_xss_detector,
            target_vuln_class=VulnClass.CROSS_SITE_SCRIPTING,
        )

        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.false_positive_rate, 0.0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.f1_score, 1.0)

    def test_cmdi_detector_metrics_zero_false_positives(self) -> None:
        """CMDi detector achieves 100% precision and zero false positives on negative controls."""
        metrics = self.runner.run_benchmark(
            detector_fn=reference_cmdi_detector,
            target_vuln_class=VulnClass.COMMAND_INJECTION,
        )

        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.false_positive_rate, 0.0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.recall, 1.0)

    def test_lfi_detector_metrics_zero_false_positives(self) -> None:
        """LFI detector achieves 100% precision and zero false positives on negative controls."""
        metrics = self.runner.run_benchmark(
            detector_fn=reference_lfi_detector,
            target_vuln_class=VulnClass.PATH_TRAVERSAL,
        )

        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.false_positive_rate, 0.0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.recall, 1.0)

    def test_ssrf_detector_metrics_zero_false_positives(self) -> None:
        """SSRF detector achieves 100% precision and zero false positives on negative controls."""
        metrics = self.runner.run_benchmark(
            detector_fn=reference_ssrf_detector,
            target_vuln_class=VulnClass.SSRF,
        )

        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.false_positive_rate, 0.0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.recall, 1.0)

    def test_overall_benchmark_scorecard_generation(self) -> None:
        """Scorecard evaluates all classes and achieves overall PASS status."""
        detectors = {
            VulnClass.SQL_INJECTION: reference_sqli_detector,
            VulnClass.CROSS_SITE_SCRIPTING: reference_xss_detector,
            VulnClass.COMMAND_INJECTION: reference_cmdi_detector,
            VulnClass.PATH_TRAVERSAL: reference_lfi_detector,
            VulnClass.SSRF: reference_ssrf_detector,
        }

        scorecard = self.runner.generate_benchmark_scorecard(detectors)

        summary = scorecard["summary"]
        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(summary["overall_false_positive_rate"], 0.0)
        self.assertEqual(summary["overall_precision"], 1.0)
        self.assertEqual(summary["overall_recall"], 1.0)
        self.assertGreaterEqual(summary["total_evaluation_cases"], 10)

    def test_null_detector_fails_the_gate(self) -> None:
        """E02: a detector that flags nothing must FAIL, not PASS with precision 1.0 / recall 0."""
        null = {vc: (lambda case: False) for vc in DEFAULT_REFERENCE_DETECTORS}
        summary = self.runner.run_evaluation(null)["summary"]
        self.assertEqual(summary["overall_precision"], 0.0)
        self.assertEqual(summary["overall_recall"], 0.0)
        self.assertEqual(summary["status"], "FAIL")

    def test_noisy_detector_fails_on_false_positives(self) -> None:
        """A detector that flags everything has false positives and must FAIL."""
        noisy = {vc: (lambda case: True) for vc in DEFAULT_REFERENCE_DETECTORS}
        summary = self.runner.run_evaluation(noisy)["summary"]
        self.assertGreater(summary["overall_false_positive_rate"], 0.0)
        self.assertEqual(summary["status"], "FAIL")

    def test_reference_detectors_still_pass(self) -> None:
        summary = self.runner.run_evaluation()["summary"]
        self.assertEqual(summary["overall_precision"], 1.0)
        self.assertEqual(summary["overall_recall"], 1.0)
        self.assertEqual(summary["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
