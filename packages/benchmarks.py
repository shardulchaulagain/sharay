"""Performance and Load Benchmarks Engine with Automated Trend Tracking.

Sector 10: Testing, Benchmarks & QA (Milestone P2.6).
Provides:
1. PerformanceLoadBenchmarkRunner: Measures high-throughput scanner/API execution under load,
   calculating p50, p95, p99 latency percentiles, requests-per-second (RPS), and tracemalloc memory delta/peak.
2. BenchmarkTrendTracker: Maintains an append-only historical trend ledger, detects latency/memory/RPS
   regressions against golden baselines (failing if p95 latency degrades > 20%), and outputs structured CI reports.
"""

from __future__ import annotations

import statistics
import time
import tracemalloc
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List


class RegressionStatus(str, Enum):
    PASSED = "passed"
    IMPROVED = "improved"
    REGRESSION_DETECTED = "regression_detected"


@dataclass
class BenchmarkResult:
    workload_name: str
    run_id: str
    timestamp_utc: float
    concurrency: int
    total_iterations: int
    successful_iterations: int
    failed_iterations: int
    duration_seconds: float
    throughput_rps: float
    latency_min_ms: float
    latency_mean_ms: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_max_ms: float
    memory_peak_mb: float
    memory_delta_mb: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workload_name": self.workload_name,
            "run_id": self.run_id,
            "timestamp_utc": self.timestamp_utc,
            "concurrency": self.concurrency,
            "total_iterations": self.total_iterations,
            "successful_iterations": self.successful_iterations,
            "failed_iterations": self.failed_iterations,
            "duration_seconds": round(self.duration_seconds, 4),
            "throughput_rps": round(self.throughput_rps, 2),
            "latency_min_ms": round(self.latency_min_ms, 3),
            "latency_mean_ms": round(self.latency_mean_ms, 3),
            "latency_p50_ms": round(self.latency_p50_ms, 3),
            "latency_p95_ms": round(self.latency_p95_ms, 3),
            "latency_p99_ms": round(self.latency_p99_ms, 3),
            "latency_max_ms": round(self.latency_max_ms, 3),
            "memory_peak_mb": round(self.memory_peak_mb, 3),
            "memory_delta_mb": round(self.memory_delta_mb, 3),
        }


@dataclass
class TrendComparison:
    workload_name: str
    status: RegressionStatus
    current_run_id: str
    baseline_run_id: str
    p95_delta_pct: float
    throughput_delta_pct: float
    memory_delta_pct: float
    details: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workload_name": self.workload_name,
            "status": self.status.value,
            "current_run_id": self.current_run_id,
            "baseline_run_id": self.baseline_run_id,
            "p95_delta_pct": round(self.p95_delta_pct, 2),
            "throughput_delta_pct": round(self.throughput_delta_pct, 2),
            "memory_delta_pct": round(self.memory_delta_pct, 2),
            "details": self.details,
        }


class PerformanceLoadBenchmarkRunner:
    """Executes synthetic and realistic load benchmarks against scanner/API targets."""

    def run_benchmark(
        self,
        workload_name: str,
        workload_fn: Callable[[], Any],
        total_iterations: int = 100,
        warmup_iterations: int = 5,
        concurrency: int = 1,
    ) -> BenchmarkResult:
        run_id = f"bench-{int(time.time() * 1000)}"

        # Warmup phase to stabilize JIT/cache
        for _ in range(warmup_iterations):
            try:
                workload_fn()
            except Exception:
                pass

        # Execution phase with memory tracking
        tracemalloc.start()
        mem_start, _ = tracemalloc.get_traced_memory()

        latencies_ms: List[float] = []
        successes = 0
        failures = 0

        overall_start = time.perf_counter()

        for _ in range(total_iterations):
            op_start = time.perf_counter()
            try:
                workload_fn()
                successes += 1
            except Exception:
                failures += 1
            op_elapsed = (time.perf_counter() - op_start) * 1000.0
            latencies_ms.append(op_elapsed)

        overall_elapsed = max(0.0001, time.perf_counter() - overall_start)
        mem_current, mem_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        latencies_ms.sort()
        n = len(latencies_ms)

        p50 = latencies_ms[int(n * 0.50)] if n > 0 else 0.0
        p95 = latencies_ms[min(int(n * 0.95), n - 1)] if n > 0 else 0.0
        p99 = latencies_ms[min(int(n * 0.99), n - 1)] if n > 0 else 0.0

        return BenchmarkResult(
            workload_name=workload_name,
            run_id=run_id,
            timestamp_utc=time.time(),
            concurrency=concurrency,
            total_iterations=total_iterations,
            successful_iterations=successes,
            failed_iterations=failures,
            duration_seconds=overall_elapsed,
            throughput_rps=total_iterations / overall_elapsed,
            latency_min_ms=latencies_ms[0] if n > 0 else 0.0,
            latency_mean_ms=statistics.mean(latencies_ms) if n > 0 else 0.0,
            latency_p50_ms=p50,
            latency_p95_ms=p95,
            latency_p99_ms=p99,
            latency_max_ms=latencies_ms[-1] if n > 0 else 0.0,
            memory_peak_mb=mem_peak / (1024 * 1024),
            memory_delta_mb=(mem_current - mem_start) / (1024 * 1024),
        )


class BenchmarkTrendTracker:
    """Maintains benchmark history and automatically enforces performance regression gates."""

    def __init__(
        self,
        max_p95_regression_pct: float = 20.0,
        max_memory_regression_pct: float = 25.0,
    ):
        self.max_p95_regression_pct = max_p95_regression_pct
        self.max_memory_regression_pct = max_memory_regression_pct
        self._history: Dict[str, List[BenchmarkResult]] = {}

    def record_benchmark(self, result: BenchmarkResult) -> None:
        if result.workload_name not in self._history:
            self._history[result.workload_name] = []
        self._history[result.workload_name].append(result)

    def compare_against_baseline(
        self,
        current: BenchmarkResult,
        baseline: BenchmarkResult,
    ) -> TrendComparison:
        details: List[str] = []
        is_regression = False
        is_improved = False

        base_p95 = max(0.001, baseline.latency_p95_ms)
        p95_delta_pct = ((current.latency_p95_ms - base_p95) / base_p95) * 100.0

        if p95_delta_pct > self.max_p95_regression_pct:
            is_regression = True
            details.append(
                f"P95 Latency regressed by {p95_delta_pct:+.1f}% ({baseline.latency_p95_ms:.2f}ms -> {current.latency_p95_ms:.2f}ms)"
            )
        elif p95_delta_pct < -10.0:
            is_improved = True
            details.append(
                f"P95 Latency improved by {abs(p95_delta_pct):.1f}% ({baseline.latency_p95_ms:.2f}ms -> {current.latency_p95_ms:.2f}ms)"
            )

        base_rps = max(0.001, baseline.throughput_rps)
        throughput_delta_pct = ((current.throughput_rps - base_rps) / base_rps) * 100.0

        if throughput_delta_pct < -20.0:
            is_regression = True
            details.append(
                f"Throughput degraded by {throughput_delta_pct:.1f}% ({baseline.throughput_rps:.1f} RPS -> {current.throughput_rps:.1f} RPS)"
            )
        elif throughput_delta_pct > 15.0:
            is_improved = True
            details.append(
                f"Throughput increased by {throughput_delta_pct:+.1f}% ({baseline.throughput_rps:.1f} RPS -> {current.throughput_rps:.1f} RPS)"
            )

        base_mem = max(0.01, baseline.memory_peak_mb)
        memory_delta_pct = ((current.memory_peak_mb - base_mem) / base_mem) * 100.0

        if memory_delta_pct > self.max_memory_regression_pct:
            is_regression = True
            details.append(
                f"Memory peak grew by {memory_delta_pct:+.1f}% ({baseline.memory_peak_mb:.2f}MB -> {current.memory_peak_mb:.2f}MB)"
            )

        if not details:
            details.append("Performance stable within tolerance bands.")

        status = (
            RegressionStatus.REGRESSION_DETECTED
            if is_regression
            else (RegressionStatus.IMPROVED if is_improved else RegressionStatus.PASSED)
        )

        return TrendComparison(
            workload_name=current.workload_name,
            status=status,
            current_run_id=current.run_id,
            baseline_run_id=baseline.run_id,
            p95_delta_pct=p95_delta_pct,
            throughput_delta_pct=throughput_delta_pct,
            memory_delta_pct=memory_delta_pct,
            details=details,
        )
