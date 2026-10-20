"""Unit tests for Performance / Load Benchmark Runner & Trend Tracking Engine."""

from __future__ import annotations

import hashlib
import unittest

from packages.benchmarks import (
    BenchmarkResult,
    BenchmarkTrendTracker,
    PerformanceLoadBenchmarkRunner,
    RegressionStatus,
)


class TestPerformanceLoadBenchmarks(unittest.TestCase):
    def setUp(self):
        self.runner = PerformanceLoadBenchmarkRunner()
        self.tracker = BenchmarkTrendTracker(max_p95_regression_pct=20.0, max_memory_regression_pct=25.0)

    def test_benchmark_runner_executes_and_profiles(self):
        def sample_workload():
            data = b"benchmark payload test data 1234567890"
            for _ in range(20):
                data = hashlib.sha256(data).digest()
            return data

        result = self.runner.run_benchmark(
            workload_name="sha256_cryptographic_pipeline",
            workload_fn=sample_workload,
            total_iterations=50,
            warmup_iterations=5,
        )

        self.assertEqual(result.workload_name, "sha256_cryptographic_pipeline")
        self.assertEqual(result.total_iterations, 50)
        self.assertEqual(result.successful_iterations, 50)
        self.assertEqual(result.failed_iterations, 0)
        self.assertGreater(result.throughput_rps, 0.0)

        # Ensure percentile invariants hold: min <= p50 <= p95 <= p99 <= max
        self.assertLessEqual(result.latency_min_ms, result.latency_p50_ms)
        self.assertLessEqual(result.latency_p50_ms, result.latency_p95_ms)
        self.assertLessEqual(result.latency_p95_ms, result.latency_p99_ms)
        self.assertLessEqual(result.latency_p99_ms, result.latency_max_ms)

    def test_trend_comparison_passed(self):
        baseline = BenchmarkResult(
            workload_name="http_parser",
            run_id="run-1",
            timestamp_utc=1000.0,
            concurrency=1,
            total_iterations=100,
            successful_iterations=100,
            failed_iterations=0,
            duration_seconds=1.0,
            throughput_rps=100.0,
            latency_min_ms=5.0,
            latency_mean_ms=10.0,
            latency_p50_ms=9.8,
            latency_p95_ms=12.0,
            latency_p99_ms=14.0,
            latency_max_ms=15.0,
            memory_peak_mb=10.0,
            memory_delta_mb=0.1,
        )

        current = BenchmarkResult(
            workload_name="http_parser",
            run_id="run-2",
            timestamp_utc=2000.0,
            concurrency=1,
            total_iterations=100,
            successful_iterations=100,
            failed_iterations=0,
            duration_seconds=1.02,
            throughput_rps=98.0,
            latency_min_ms=5.1,
            latency_mean_ms=10.2,
            latency_p50_ms=10.0,
            latency_p95_ms=12.5,  # +4.1% (within 20% budget)
            latency_p99_ms=14.2,
            latency_max_ms=15.5,
            memory_peak_mb=10.2,  # +2.0% (within 25% budget)
            memory_delta_mb=0.12,
        )

        comparison = self.tracker.compare_against_baseline(current, baseline)
        self.assertEqual(comparison.status, RegressionStatus.PASSED)
        self.assertIn("stable", comparison.details[0])

    def test_trend_comparison_detects_latency_regression(self):
        baseline = BenchmarkResult(
            workload_name="payload_generator",
            run_id="run-base",
            timestamp_utc=1000.0,
            concurrency=1,
            total_iterations=100,
            successful_iterations=100,
            failed_iterations=0,
            duration_seconds=1.0,
            throughput_rps=100.0,
            latency_min_ms=5.0,
            latency_mean_ms=10.0,
            latency_p50_ms=10.0,
            latency_p95_ms=10.0,
            latency_p99_ms=12.0,
            latency_max_ms=15.0,
            memory_peak_mb=5.0,
            memory_delta_mb=0.1,
        )

        # Regressed: p95 latency jumped from 10.0ms to 13.5ms (+35%)
        regressed = BenchmarkResult(
            workload_name="payload_generator",
            run_id="run-regressed",
            timestamp_utc=2000.0,
            concurrency=1,
            total_iterations=100,
            successful_iterations=100,
            failed_iterations=0,
            duration_seconds=1.5,
            throughput_rps=66.6,
            latency_min_ms=6.0,
            latency_mean_ms=13.0,
            latency_p50_ms=12.5,
            latency_p95_ms=13.5,
            latency_p99_ms=15.0,
            latency_max_ms=18.0,
            memory_peak_mb=5.1,
            memory_delta_mb=0.1,
        )

        comparison = self.tracker.compare_against_baseline(regressed, baseline)
        self.assertEqual(comparison.status, RegressionStatus.REGRESSION_DETECTED)
        self.assertTrue(any("P95 Latency regressed" in d for d in comparison.details))

    def test_trend_comparison_detects_improvement(self):
        baseline = BenchmarkResult(
            workload_name="mincut_solver",
            run_id="run-base",
            timestamp_utc=1000.0,
            concurrency=1,
            total_iterations=50,
            successful_iterations=50,
            failed_iterations=0,
            duration_seconds=2.0,
            throughput_rps=25.0,
            latency_min_ms=20.0,
            latency_mean_ms=40.0,
            latency_p50_ms=40.0,
            latency_p95_ms=45.0,
            latency_p99_ms=50.0,
            latency_max_ms=55.0,
            memory_peak_mb=12.0,
            memory_delta_mb=0.5,
        )

        # Improved: throughput jumped from 25 to 35 RPS (+40%), p95 dropped from 45 to 32ms (-28.8%)
        improved = BenchmarkResult(
            workload_name="mincut_solver",
            run_id="run-improved",
            timestamp_utc=2000.0,
            concurrency=1,
            total_iterations=50,
            successful_iterations=50,
            failed_iterations=0,
            duration_seconds=1.42,
            throughput_rps=35.2,
            latency_min_ms=15.0,
            latency_mean_ms=28.0,
            latency_p50_ms=27.0,
            latency_p95_ms=32.0,
            latency_p99_ms=35.0,
            latency_max_ms=38.0,
            memory_peak_mb=11.5,
            memory_delta_mb=0.4,
        )

        comparison = self.tracker.compare_against_baseline(improved, baseline)
        self.assertEqual(comparison.status, RegressionStatus.IMPROVED)
        self.assertTrue(any("Latency improved" in d for d in comparison.details))
        self.assertTrue(any("Throughput increased" in d for d in comparison.details))


if __name__ == "__main__":
    unittest.main()
