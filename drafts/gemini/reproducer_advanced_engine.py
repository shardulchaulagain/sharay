"""Advanced Finding Reproducer, Exploit Chaining & Statistical Timing Oracle Engine.

Sector 1: Verification Core (Milestones P1.12, P1.13, P1.14).
Provides:
1. Multi-Step Exploit Chaining with Postcondition Oracles (transitions: EXPLOITED -> CHAINED -> VERIFIED).
2. Statistical Differential Timing Oracle with noise baselining, Z-score analysis,
   proportional scaling validation, and jitter rejection.
3. Containerized AutoPyVerifier sandbox runner with egress constraints.
"""

from __future__ import annotations

import hashlib
import os
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from packages.scanner_adapters.reproducer import FindingState


@dataclass
class ExploitStep:
    step_id: str
    name: str
    target_url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    # Postcondition oracle: (status_code, body_bytes, headers_dict) -> (passed: bool, extracted_data: dict, reason: str)
    postcondition_oracle: Optional[Callable[[int, bytes, Dict[str, str]], Tuple[bool, Dict[str, Any], str]]] = None


@dataclass
class ChainHopResult:
    step_id: str
    status_code: int
    elapsed_ms: float
    passed: bool
    reason: str
    extracted_variables: Dict[str, Any]
    response_hash: str


@dataclass
class ChainReproductionResult:
    confirmed: bool
    state: FindingState
    total_steps: int
    successful_steps: int
    hops: List[ChainHopResult]
    chain_seal_hash: str
    demotion_reason: Optional[str] = None


class MultiStepChainReproducer:
    """Executes multi-step sequential exploit chains and validates postconditions."""

    def __init__(
        self,
        http_client: Optional[Callable[..., Tuple[int, bytes, float]]] = None,
    ):
        self.http_client = http_client or self._default_http_request

    @staticmethod
    def _default_http_request(
        url: str,
        timeout: float = 8.0,
        headers: Optional[Dict[str, str]] = None,
        method: str = "GET",
        data: Optional[bytes] = None,
    ) -> Tuple[int, bytes, float]:
        import urllib.request
        start = time.monotonic()
        req_headers = {"User-Agent": "SHARAY-ChainReproducer/2.0"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read()
                elapsed = (time.monotonic() - start) * 1000.0
                return resp.status, body, elapsed
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000.0
            return 0, str(exc).encode(), elapsed

    def execute_chain(
        self,
        steps: List[ExploitStep],
        initial_context: Optional[Dict[str, Any]] = None,
        require_cold_replay: bool = True,
    ) -> ChainReproductionResult:
        if not steps:
            return ChainReproductionResult(
                confirmed=False,
                state=FindingState.DEMOTED,
                total_steps=0,
                successful_steps=0,
                hops=[],
                chain_seal_hash="",
                demotion_reason="No exploit steps provided",
            )

        context = dict(initial_context or {})
        hops: List[ChainHopResult] = []

        for idx, step in enumerate(steps):
            # 1. Variable interpolation in URL, headers, and body
            url = step.target_url
            for k, v in context.items():
                url = url.replace(f"{{{k}}}", str(v))

            rendered_headers = {}
            for hk, hv in step.headers.items():
                val = hv
                for k, v in context.items():
                    val = val.replace(f"{{{k}}}", str(v))
                rendered_headers[hk] = val

            rendered_body = None
            if step.body is not None:
                body_str = step.body
                for k, v in context.items():
                    body_str = body_str.replace(f"{{{k}}}", str(v))
                rendered_body = body_str.encode("utf-8")

            # 2. Execute HTTP request for this hop
            status, resp_body, elapsed = self.http_client(
                url,
                timeout=10.0,
                headers=rendered_headers,
                method=step.method,
                data=rendered_body,
            )
            resp_hash = hashlib.sha256(resp_body).hexdigest()

            # 3. Evaluate postcondition oracle
            passed = False
            extracted: Dict[str, Any] = {}
            reason = "No oracle defined"

            if step.postcondition_oracle is not None:
                passed, extracted, reason = step.postcondition_oracle(status, resp_body, rendered_headers)
            else:
                passed = (200 <= status < 400)
                reason = f"HTTP {status}"

            hops.append(
                ChainHopResult(
                    step_id=step.step_id,
                    status_code=status,
                    elapsed_ms=elapsed,
                    passed=passed,
                    reason=reason,
                    extracted_variables=extracted,
                    response_hash=resp_hash,
                )
            )

            if not passed:
                # Step failed: chain breaks immediately
                return ChainReproductionResult(
                    confirmed=False,
                    state=FindingState.DEMOTED,
                    total_steps=len(steps),
                    successful_steps=idx,
                    hops=hops,
                    chain_seal_hash="",
                    demotion_reason=f"Step '{step.name}' failed postcondition: {reason}",
                )

            # Accumulate extracted variables for subsequent hops
            context.update(extracted)

        # 4. Compute cryptographic Merkle chain seal linking all hops
        hop_digests = [f"{h.step_id}:{h.status_code}:{h.response_hash}" for h in hops]
        chain_seal = hashlib.sha256(":".join(hop_digests).encode()).hexdigest()

        # If single step, transitions to EXPLOITED; if multi-step, transitions to CHAINED / VERIFIED
        final_state = FindingState.VERIFIED if len(steps) > 1 else FindingState.EXPLOITED

        return ChainReproductionResult(
            confirmed=True,
            state=final_state,
            total_steps=len(steps),
            successful_steps=len(steps),
            hops=hops,
            chain_seal_hash=chain_seal,
            demotion_reason=None,
        )


class StatisticalTimingOracle:
    """Statistical differential timing analyzer protecting against network jitter.
    
    Uses baseline distribution profiling, Z-score hypothesis testing, and
    linear scaling verification.
    """

    @staticmethod
    def profile_baseline(latencies_ms: List[float]) -> Tuple[float, float]:
        """Calculates baseline mean (mu) and standard deviation (sigma)."""
        if not latencies_ms:
            return 30.0, 5.0
        if len(latencies_ms) == 1:
            return latencies_ms[0], 5.0
        mean = statistics.mean(latencies_ms)
        stdev = statistics.stdev(latencies_ms)
        # Avoid zero division on synthetic fixtures
        return mean, max(1.0, stdev)

    @staticmethod
    def evaluate_timing_vulnerability(
        baseline_samples_ms: List[float],
        probe_3s_ms: float,
        probe_5s_ms: float,
        negative_control_ms: float,
        z_threshold: float = 4.0,
    ) -> Tuple[bool, float, str]:
        """Evaluates time-based injection with statistical rigor.
        
        Returns (is_confirmed, z_score, diagnostic_reason).
        """
        mu_base, sigma_base = StatisticalTimingOracle.profile_baseline(baseline_samples_ms)

        # 1. Negative control check: benign query must not experience large delay
        ctrl_z = (negative_control_ms - mu_base) / sigma_base
        if ctrl_z > 3.0:
            return False, ctrl_z, f"Negative control exhibited high latency ({negative_control_ms:.1f}ms, z={ctrl_z:.2f}); target is jittery (false positive)"

        # 2. Check 3-second sleep probe
        z_3s = (probe_3s_ms - mu_base) / sigma_base
        if z_3s < z_threshold:
            return False, z_3s, f"3s probe latency ({probe_3s_ms:.1f}ms) did not meet statistical threshold (z={z_3s:.2f} < {z_threshold})"

        # 3. Check 5-second sleep probe
        z_5s = (probe_5s_ms - mu_base) / sigma_base
        if z_5s < z_threshold:
            return False, z_5s, f"5s probe latency ({probe_5s_ms:.1f}ms) did not meet statistical threshold (z={z_5s:.2f} < {z_threshold})"

        # 4. Proportional scaling test: 5s probe must be ~2000ms (+/- 800ms) slower than 3s probe
        scaling_delta = probe_5s_ms - probe_3s_ms
        if not (1200.0 <= scaling_delta <= 2800.0):
            return False, z_5s, f"Timing jitter detected: probe delta ({scaling_delta:.1f}ms) did not scale proportionally with sleep parameter (expected ~2000ms)"

        return True, round(z_5s, 2), f"Confirmed time-based injection: statistically significant delay (z={z_5s:.2f}, scaling delta={scaling_delta:.1f}ms)"


class ContainerizedAutoPyVerifier:
    """Executes AutoPyVerifier scripts within rootless container boundary with network egress pinning."""

    @staticmethod
    def build_container_run_command(
        script_path: str,
        target_ip: str,
        runtime: str = "podman",
        memory_limit: str = "128m",
        cpu_limit: str = "0.5",
    ) -> List[str]:
        """Builds hardened, non-root, egress-isolated container execution command."""
        return [
            runtime,
            "run",
            "--rm",
            "--read-only",
            f"--memory={memory_limit}",
            f"--cpus={cpu_limit}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--network=none",  # Default strict isolation unless egress allowlist attached
            "-v",
            f"{os.path.abspath(script_path)}:/app/verify.py:ro",
            "python:3.13-slim",
            "python",
            "/app/verify.py",
        ]
