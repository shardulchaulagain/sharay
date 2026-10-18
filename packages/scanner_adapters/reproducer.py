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
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


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


class DifferentialOracle:
    """Evaluates HTTP response differences between baseline, mutated, and negative control probes."""

    @staticmethod
    def compute_response_hash(body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()

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
    ) -> tuple[bool, float, str]:
        """Returns (is_anomaly, score, reason)."""
        score = 0.0
        reasons: list[str] = []

        # 1. Canary Reflection
        if canary:
            canary_bytes = canary.encode("utf-8", errors="ignore")
            is_cmd_reflection = (
                canary == "sharay_canary_cmd"
                and (b"echo sharay_canary_cmd" in probe_body or b"echo+sharay_canary_cmd" in probe_body)
            )
            reflected_in_probe = canary_bytes in probe_body and not is_cmd_reflection
            reflected_in_base = canary_bytes in baseline_body
            if reflected_in_probe and not reflected_in_base:
                score += 50.0
                reasons.append(f"Canary '{canary}' reflected in response")

        # 2. Time Delta (Blind injection)
        if is_time_based:
            delta_ms = probe_time_ms - baseline_time_ms
            if delta_ms >= 4000.0:  # 4+ second differential
                score += 45.0
                reasons.append(f"Significant time delay detected ({delta_ms:.1f}ms delta)")

        # 3. Status Code Anomaly
        if probe_status != baseline_status:
            score += 20.0
            reasons.append(f"Status changed from {baseline_status} to {probe_status}")

        # 4. Length Delta Percentage
        base_len = max(1, len(baseline_body))
        probe_len = len(probe_body)
        length_delta_pct = abs(probe_len - base_len) / base_len * 100.0
        if length_delta_pct >= 25.0:
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
        opener = (
            urllib.request.build_opener(urllib.request.ProxyHandler({}))
            if ("127.0.0.1" in url or "localhost" in url)
            else urllib.request.build_opener()
        )
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
            base_status, base_body, base_time = self._execute_http(
                base_url, headers=headers, method="GET"
            )

            # Build active URL
            active_query = dict(query_dict)
            active_query[fuzz_param] = [active_payload]
            new_query_str = urllib.parse.urlencode(active_query, doseq=True)
            active_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query_str, ""))

            # Build negative control URL
            control_query = dict(query_dict)
            control_query[fuzz_param] = [benign_control_payload]
            control_url = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(control_query, doseq=True), "")
            )
            req_headers = headers
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
        return ReproductionResult(
            confirmed=True,
            state=FindingState.REPRODUCED,
            replays_passed=passed_replays,
            total_replays=self.required_replays,
            negative_control_passed=True,
            demotion_reason=None,
            replay_attempts=attempts,
            differential_score=score,
        )


__all__ = [
    "FindingState",
    "VALID_TRANSITIONS",
    "InvalidStateTransitionError",
    "ReplayAttempt",
    "ReproductionResult",
    "DifferentialOracle",
    "DeterministicReproducer",
]
