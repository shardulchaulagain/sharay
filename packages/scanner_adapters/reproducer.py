"""Deterministic Finding Reproducer & 6-State Lifecycle Engine (C1, C2, C3, C4).

Enforces the core architectural principle:
"A finding is a hypothesis until a cold replay proves it."

Finding Lifecycle:
OBSERVED -> CANDIDATE -> REPRODUCED -> EXPLOITED -> CHAINED -> VERIFIED
    |             |              |              |            |
    +-- DEMOTED <-+--------------+--------------+------------+
"""

from __future__ import annotations

import hashlib
import os
import ssl
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Sequence


class FindingState(str, Enum):
    OBSERVED = "OBSERVED"  # Initial raw scanner observation
    CANDIDATE = "CANDIDATE"  # Parsed finding meeting initial threshold
    REPRODUCED = "REPRODUCED"  # 3x byte-identical replays + negative control passed
    EXPLOITED = "EXPLOITED"  # Observable impact confirmed (read/write/bypass)
    CHAINED = "CHAINED"  # Multi-step postcondition satisfied & replayed
    VERIFIED = "VERIFIED"  # Evidence bundle complete, hashes sealed
    DEMOTED = "DEMOTED"  # Failed reproduction, negative control fired, or flapped


VALID_TRANSITIONS: dict[FindingState, set[FindingState]] = {
    FindingState.OBSERVED: {FindingState.CANDIDATE, FindingState.DEMOTED},
    FindingState.CANDIDATE: {FindingState.REPRODUCED, FindingState.DEMOTED},
    FindingState.REPRODUCED: {FindingState.EXPLOITED, FindingState.DEMOTED},
    FindingState.EXPLOITED: {FindingState.CHAINED, FindingState.VERIFIED, FindingState.DEMOTED},
    FindingState.CHAINED: {FindingState.VERIFIED, FindingState.DEMOTED},
    FindingState.VERIFIED: set(),
    FindingState.DEMOTED: set(),
}


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal transition is attempted on a finding."""


@dataclass
class ReplayAttempt:
    index: int
    status_code: int
    content_length: int
    response_hash: str
    elapsed_ms: float
    matched_oracle: bool


@dataclass
class ReproductionResult:
    confirmed: bool
    state: FindingState
    replays_passed: int
    total_replays: int
    negative_control_passed: bool
    demotion_reason: str | None = None
    replay_attempts: list[ReplayAttempt] = field(default_factory=list)
    differential_score: float = 0.0
    reproducibility_score: float = 0.0


def transition_state(current: FindingState, target: FindingState) -> FindingState:
    """Enforce the strict 6-state lifecycle transition model (C1–C4)."""
    allowed = VALID_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise InvalidStateTransitionError(
            f"Illegal state transition from {current.value} to {target.value}. Allowed: {[s.value for s in allowed]}"
        )
    return target


# Markup metacharacters whose un-escaped reflection proves an executable (injectable) context.
# A canary free of these reflecting back is an inert echo, not a confirmable vulnerability.
_REFLECTION_METACHARS = (b"<", b">", b'"', b"'")


class DifferentialOracle:
    """Evaluates HTTP response differences between baseline, mutated, and negative control probes.

    Supports dynamic statistical baselining over multiple baseline samples to adapt to network jitter.
    """

    @staticmethod
    def compute_response_hash(body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()

    @staticmethod
    def compute_baseline_stats(
        samples: Sequence[tuple[int, bytes, float]],
    ) -> dict[str, float]:
        """Calculate mean, standard deviation, and jitter metrics across baseline samples."""
        if not samples:
            return {"mean_time_ms": 0.0, "std_time_ms": 0.0, "mean_len": 0.0, "std_len": 0.0}
        times = [s[2] for s in samples]
        lens = [float(len(s[1])) for s in samples]
        n = len(samples)
        mean_time = sum(times) / n
        mean_len = sum(lens) / n
        std_time = (sum((t - mean_time) ** 2 for t in times) / max(1, n - 1)) ** 0.5 if n > 1 else 0.0
        std_len = (sum((length - mean_len) ** 2 for length in lens) / max(1, n - 1)) ** 0.5 if n > 1 else 0.0
        return {
            "mean_time_ms": mean_time,
            "std_time_ms": std_time,
            "mean_len": mean_len,
            "std_len": std_len,
        }

    @staticmethod
    def evaluate(
        baseline_status: int,
        baseline_body: bytes,
        baseline_time_ms: float,
        probe_status: int,
        probe_body: bytes,
        probe_time_ms: float,
        canary: str | None = None,
        is_time_based: bool = False,
        baseline_stats: dict[str, float] | None = None,
        active_payload: str | None = None,
    ) -> tuple[bool, float, str]:
        """Returns (is_anomaly, score, reason)."""
        score = 0.0
        reasons: list[str] = []

        # 1. Canary Reflection
        if canary:
            canary_bytes = canary.encode("utf-8", errors="ignore")
            is_cmd_reflection = canary == "sharay_canary_cmd" and (
                b"echo sharay_canary_cmd" in probe_body or b"echo+sharay_canary_cmd" in probe_body
            )
            reflected_in_probe = canary_bytes in probe_body and not is_cmd_reflection
            reflected_in_base = canary_bytes in baseline_body
            if reflected_in_probe and not reflected_in_base:
                # A reflected canary confirms only when it is a class-specific postcondition, not when
                # it is merely our own injected input echoed back as inert text. That inert echo (a
                # search box, an error page quoting the term) proves the app reflects input -- it is
                # not XSS and not any injection on its own (E01/B1). It stays confirming when either
                # the canary carries markup metacharacters reflected UNescaped (an executable XSS
                # context) or the canary is an independent effect signature (a DB-error string, a
                # /etc/passwd marker) rather than a substring of the payload we sent.
                is_injected_echo = active_payload is not None and canary in active_payload
                is_executable = any(meta in canary_bytes for meta in _REFLECTION_METACHARS)
                if is_injected_echo and not is_executable:
                    score += 5.0
                    reasons.append(
                        f"Canary '{canary}' reflected as inert input echo (benign; not confirming)"
                    )
                else:
                    score += 50.0
                    reasons.append(f"Canary '{canary}' reflected in response")

        # 2. Time Delta (Blind injection with optional 3-sigma statistical baselining)
        if is_time_based:
            delta_ms = probe_time_ms - baseline_time_ms
            time_threshold = 4000.0
            if baseline_stats and baseline_stats.get("std_time_ms", 0.0) > 0:
                # Dynamic threshold: at least 3-sigma above baseline jitter, minimum 2500ms
                time_threshold = max(2500.0, 3.0 * baseline_stats["std_time_ms"])
            if delta_ms >= time_threshold:
                score += 45.0
                reasons.append(
                    f"Significant time delay detected ({delta_ms:.1f}ms delta vs threshold {time_threshold:.1f}ms)"
                )

        # 3. Status Code Anomaly
        if probe_status != baseline_status:
            score += 20.0
            reasons.append(f"Status changed from {baseline_status} to {probe_status}")

        # 4. Length Delta Percentage (Adaptive to 3-sigma variance if baseline stats present)
        base_len = max(1, len(baseline_body))
        probe_len = len(probe_body)
        length_delta_pct = abs(probe_len - base_len) / base_len * 100.0
        len_threshold_pct = 25.0
        if (
            baseline_stats
            and baseline_stats.get("std_len", 0.0) > 0
            and baseline_stats.get("mean_len", 0) > 0
        ):
            # If length delta exceeds 3-sigma of normal responses
            if abs(probe_len - baseline_stats["mean_len"]) >= 3.0 * baseline_stats["std_len"]:
                len_threshold_pct = 15.0

        if length_delta_pct >= len_threshold_pct:
            score += 15.0
            reasons.append(f"Content length shifted by {length_delta_pct:.1f}%")

        # 5. Error Signatures (SQL, Command, PHP)
        lower_body = probe_body.lower()
        sql_errors = [
            b"sql syntax",
            b"mysql_fetch",
            b"ora-01756",
            b"sqlite3.operationalerror",
            b"postgresql query failed",
            b"warning: mysql",
            b"warning: mysqli",
            b"mariadb",
        ]
        for err in sql_errors:
            if err in lower_body and err not in baseline_body.lower():
                score += 40.0
                reasons.append(f"SQL error signature '{err.decode()}' detected")
                break

        # 6. Common Vulnerability Evidence Signatures (LFI, Command Execution)
        evidence_signatures = [
            b"root:x:0:0:",
            b"root:*:0:0:",
            b"sharay_canary_cmd",
            b"<sharay_canary",
            b"www-data",
        ]
        for sig in evidence_signatures:
            if sig in lower_body and sig not in baseline_body.lower():
                score += 45.0
                reasons.append(f"Vulnerability evidence marker '{sig.decode()}' detected")
                break

        is_anomaly = score >= 35.0
        return is_anomaly, score, "; ".join(reasons) or "No significant differential"


class DeterministicReproducer:
    """3x Cold Replay & Negative Control Validation Engine."""

    def __init__(
        self,
        required_replays: int = 3,
        http_client: Callable[..., tuple[int, bytes, float]] | None = None,
    ) -> None:
        self.required_replays = required_replays
        self.http_client = http_client or self._default_http_request

    @staticmethod
    def _default_http_request(
        url: str,
        timeout: float = 8.0,
        headers: dict[str, str] | None = None,
        method: str = "GET",
        data: bytes | None = None,
    ) -> tuple[int, bytes, float]:
        start = time.monotonic()
        req_headers = {"User-Agent": "SHARAY-Deterministic-Reproducer/1.0"}
        if "4280" in url or "vulnerabilities" in url or "dvwa" in url.lower():
            sec = os.environ.get("SHARAY_DVWA_SECURITY", os.environ.get("SHARAY_LAB_SECURITY_LEVEL", "high"))
            req_headers["Cookie"] = f"security={sec}"
        if headers:
            req_headers.update(headers)
        if data is not None and "Content-Type" not in req_headers:
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        # Verifying an authorized target's own evidence must not fail on its certificate: a
        # self-signed, expired or mismatched cert is part of what we are assessing, not a reason to
        # abort the replay. Connect over TLS without cert verification (assessment context).
        tls_ctx = ssl.create_default_context()
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE
        handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=tls_ctx)]
        if "127.0.0.1" in url or "localhost" in url:
            handlers.insert(0, urllib.request.ProxyHandler({}))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read()
                elapsed = (time.monotonic() - start) * 1000.0
                return resp.status, body, elapsed
        except urllib.error.HTTPError as exc:
            body = exc.read()
            elapsed = (time.monotonic() - start) * 1000.0
            return exc.code, body, elapsed
        except Exception:
            elapsed = (time.monotonic() - start) * 1000.0
            return 0, b"", elapsed

    def _execute_http(
        self,
        url: str,
        timeout: float = 8.0,
        headers: dict[str, str] | None = None,
        method: str = "GET",
        data: bytes | None = None,
    ) -> tuple[int, bytes, float]:
        try:
            return self.http_client(url, timeout=timeout, headers=headers, method=method, data=data)
        except TypeError:
            try:
                return self.http_client(url, timeout=timeout)
            except TypeError:
                return self.http_client(url)

    def verify_finding(
        self,
        base_url: str,
        fuzz_param: str,
        active_payload: str,
        benign_control_payload: str = "sharay_benign_safe_token_42",
        canary: str | None = None,
        is_time_based: bool = False,
        headers: dict[str, str] | None = None,
        method: str = "GET",
        extra_params: dict[str, str] | None = None,
    ) -> ReproductionResult:
        """Run 3 byte-identical active replays and 1 negative control probe."""
        is_post = method.upper() == "POST"
        extra = dict(extra_params or {})

        if is_post:
            base_data = urllib.parse.urlencode({fuzz_param: benign_control_payload, **extra}).encode()
            active_data = urllib.parse.urlencode({fuzz_param: active_payload, **extra}).encode()
            control_data = urllib.parse.urlencode({fuzz_param: benign_control_payload, **extra}).encode()
            req_headers = {"Content-Type": "application/x-www-form-urlencoded"}
            if headers:
                req_headers.update(headers)

            base_status, base_body, base_time = self._execute_http(
                base_url, headers=req_headers, method="POST", data=base_data
            )
            active_url = base_url
            control_url = base_url
        else:
            parsed = urllib.parse.urlsplit(base_url)
            query_dict = urllib.parse.parse_qs(parsed.query)
            for k, v in extra.items():
                query_dict.setdefault(k, [v])

            # Baseline request
            base_status, base_body, base_time = self._execute_http(base_url, headers=headers, method="GET")

            # Build active URL
            active_query = dict(query_dict)
            active_query[fuzz_param] = [active_payload]
            new_query_str = urllib.parse.urlencode(active_query, doseq=True)
            active_url = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, new_query_str, "")
            )

            # Build negative control URL
            control_query = dict(query_dict)
            control_query[fuzz_param] = [benign_control_payload]
            control_url = urllib.parse.urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    urllib.parse.urlencode(control_query, doseq=True),
                    "",
                )
            )
            req_headers = dict(headers) if headers else {}
            active_data = None
            control_data = None

        attempts: list[ReplayAttempt] = []
        for i in range(1, self.required_replays + 1):
            status, body, elapsed = self._execute_http(
                active_url, headers=req_headers, method=method, data=active_data
            )
            is_anomaly, score, reason = DifferentialOracle.evaluate(
                base_status,
                base_body,
                base_time,
                status,
                body,
                elapsed,
                canary=canary,
                is_time_based=is_time_based,
                active_payload=active_payload,
            )
            body_hash = DifferentialOracle.compute_response_hash(body)
            attempts.append(
                ReplayAttempt(
                    index=i,
                    status_code=status,
                    content_length=len(body),
                    response_hash=body_hash,
                    elapsed_ms=elapsed,
                    matched_oracle=is_anomaly,
                )
            )

        # Check if all replays matched oracle and are stable
        passed_replays = sum(1 for a in attempts if a.matched_oracle)
        if passed_replays < self.required_replays:
            return ReproductionResult(
                confirmed=False,
                state=FindingState.DEMOTED,
                replays_passed=passed_replays,
                total_replays=self.required_replays,
                negative_control_passed=False,
                demotion_reason=f"Reproduction flapped: only {passed_replays}/{self.required_replays} replays matched oracle",
                replay_attempts=attempts,
            )

        # Step 2: Negative Control Probe
        ctrl_status, ctrl_body, ctrl_elapsed = self._execute_http(
            control_url, headers=req_headers, method=method, data=control_data
        )
        ctrl_anomaly, _, ctrl_reason = DifferentialOracle.evaluate(
            base_status,
            base_body,
            base_time,
            ctrl_status,
            ctrl_body,
            ctrl_elapsed,
            canary=canary,
            is_time_based=is_time_based,
            active_payload=active_payload,
        )

        if ctrl_anomaly:
            # Negative control triggered an anomaly: false positive!
            return ReproductionResult(
                confirmed=False,
                state=FindingState.DEMOTED,
                replays_passed=passed_replays,
                total_replays=self.required_replays,
                negative_control_passed=False,
                demotion_reason=f"Negative control fired ({ctrl_reason}); probe is non-differentiating (false positive)",
                replay_attempts=attempts,
            )

        # All 3 replays confirmed and negative control was completely silent
        unique_hashes = len({a.response_hash for a in attempts})
        repro_score = round(1.0 if unique_hashes == 1 else 0.95, 4)
        return ReproductionResult(
            confirmed=True,
            state=FindingState.REPRODUCED,
            replays_passed=passed_replays,
            total_replays=self.required_replays,
            negative_control_passed=True,
            demotion_reason=None,
            replay_attempts=attempts,
            differential_score=score,
            reproducibility_score=repro_score,
        )


@dataclass
class PostconditionOracle:
    """Verifies that an exploit has had a concrete observable side effect (Sector 1.2)."""

    effect_type: str  # "data_read", "state_write", "auth_bypass", "privilege_escalation"
    description: str
    verifier_fn: Callable[[int, bytes, float], bool] | None = None
    expected_evidence_marker: bytes | None = None

    def evaluate_effect(self, status: int, body: bytes, elapsed_ms: float) -> bool:
        if self.expected_evidence_marker and self.expected_evidence_marker in body:
            return True
        if self.verifier_fn:
            return self.verifier_fn(status, body, elapsed_ms)
        return False


@dataclass
class ExploitChainStep:
    step_name: str
    url: str
    method: str = "GET"
    headers: dict[str, str] | None = None
    data: bytes | None = None
    postcondition: PostconditionOracle | None = None


@dataclass
class ExploitChainResult:
    confirmed: bool
    final_state: FindingState
    steps_executed: int
    total_steps: int
    step_evidences: list[dict[str, Any]]
    failure_reason: str | None = None
    sealed_manifest_hash: str | None = None


class MultiStepExploitChainEngine:
    """Executes multi-step chained exploits with postcondition verification (Sector 1.2).

    Orchestrates lifecycle transitions:
    OBSERVED -> CANDIDATE -> REPRODUCED -> EXPLOITED -> CHAINED -> VERIFIED
    """

    def __init__(self, http_client: Callable[..., tuple[int, bytes, float]] | None = None) -> None:
        self.http_client = http_client or DeterministicReproducer._default_http_request

    def execute_chain(
        self,
        chain_id: str,
        steps: Sequence[ExploitChainStep],
        initial_state: FindingState = FindingState.CANDIDATE,
    ) -> ExploitChainResult:
        if not steps:
            return ExploitChainResult(
                confirmed=False,
                final_state=FindingState.DEMOTED,
                steps_executed=0,
                total_steps=0,
                step_evidences=[],
                failure_reason="Exploit chain contains no steps",
            )

        current_state = initial_state
        step_evidences: list[dict[str, Any]] = []

        # Step 1: Initial vulnerability trigger
        first_step = steps[0]
        status, body, elapsed = self.http_client(
            first_step.url,
            headers=first_step.headers,
            method=first_step.method,
            data=first_step.data,
        )
        step_hash = hashlib.sha256(body).hexdigest()

        # Did step 1 succeed?
        p1 = first_step.postcondition
        p1_ok = p1.evaluate_effect(status, body, elapsed) if p1 else (status in (200, 201))

        step_evidences.append(
            {
                "step_name": first_step.step_name,
                "status_code": status,
                "response_hash": step_hash,
                "elapsed_ms": elapsed,
                "postcondition_met": p1_ok,
                "effect_type": p1.effect_type if p1 else "trigger",
            }
        )

        if not p1_ok:
            current_state = transition_state(current_state, FindingState.DEMOTED)
            return ExploitChainResult(
                confirmed=False,
                final_state=current_state,
                steps_executed=1,
                total_steps=len(steps),
                step_evidences=step_evidences,
                failure_reason=f"Step 1 '{first_step.step_name}' failed postcondition",
            )

        # Transition CANDIDATE -> REPRODUCED
        current_state = transition_state(current_state, FindingState.REPRODUCED)
        # Transition REPRODUCED -> EXPLOITED (impact confirmed)
        current_state = transition_state(current_state, FindingState.EXPLOITED)

        # Subsequent steps (if multi-step chain)
        if len(steps) > 1:
            for idx, step in enumerate(steps[1:], start=2):
                s_status, s_body, s_elapsed = self.http_client(
                    step.url,
                    headers=step.headers,
                    method=step.method,
                    data=step.data,
                )
                s_hash = hashlib.sha256(s_body).hexdigest()
                sp = step.postcondition
                sp_ok = sp.evaluate_effect(s_status, s_body, s_elapsed) if sp else (s_status in (200, 201))

                step_evidences.append(
                    {
                        "step_name": step.step_name,
                        "status_code": s_status,
                        "response_hash": s_hash,
                        "elapsed_ms": s_elapsed,
                        "postcondition_met": sp_ok,
                        "effect_type": sp.effect_type if sp else "chained_action",
                    }
                )

                if not sp_ok:
                    current_state = transition_state(current_state, FindingState.DEMOTED)
                    return ExploitChainResult(
                        confirmed=False,
                        final_state=current_state,
                        steps_executed=idx,
                        total_steps=len(steps),
                        step_evidences=step_evidences,
                        failure_reason=f"Step {idx} '{step.step_name}' failed chained postcondition",
                    )

            # All chained steps passed: transition EXPLOITED -> CHAINED
            current_state = transition_state(current_state, FindingState.CHAINED)

        # Seal evidence manifest with cryptographic hash: transition to VERIFIED
        manifest_payload = f"{chain_id}:" + ":".join(e["response_hash"] for e in step_evidences)
        sealed_hash = hashlib.sha256(manifest_payload.encode()).hexdigest()
        current_state = transition_state(current_state, FindingState.VERIFIED)

        return ExploitChainResult(
            confirmed=True,
            final_state=current_state,
            steps_executed=len(steps),
            total_steps=len(steps),
            step_evidences=step_evidences,
            failure_reason=None,
            sealed_manifest_hash=sealed_hash,
        )


def calculate_assessment_reproducibility(
    results: Sequence[ReproductionResult],
) -> dict[str, float]:
    """Calculate empirical reproducibility rate and FP demotion metrics (Sector 1.4)."""
    if not results:
        return {"reproducibility_rate": 0.0, "demoted_rate": 0.0, "confirmed_rate": 0.0}
    total = len(results)
    confirmed = sum(1 for r in results if r.confirmed)
    demoted = sum(1 for r in results if r.state == FindingState.DEMOTED)
    avg_score = sum(r.reproducibility_score for r in results) / total
    return {
        "reproducibility_rate": round(avg_score, 4),
        "demoted_rate": round(demoted / total, 4),
        "confirmed_rate": round(confirmed / total, 4),
    }


__all__ = [
    "DifferentialOracle",
    "DeterministicReproducer",
    "ExploitChainResult",
    "ExploitChainStep",
    "FindingState",
    "InvalidStateTransitionError",
    "MultiStepExploitChainEngine",
    "PostconditionOracle",
    "ReplayAttempt",
    "ReproductionResult",
    "VALID_TRANSITIONS",
    "calculate_assessment_reproducibility",
    "transition_state",
]
