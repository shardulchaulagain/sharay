"""Multi-method body fuzzing, time-based oracles, SSTI and NoSQL injection (Sprint 5).

Adopted from drafts/gemini/body_fuzzer.py with the FP/safety corrections the project mandates:
  * the SQLite time vector (``RANDOMBLOB(n)`` with a 100M multiplier) is a ~500 MB memory bomb, not
    a bounded delay, so it is dropped — only parameterless network DBMS sleep vectors remain;
  * time-based findings are confirmed across 3 consecutive over-threshold trials (spec 5.2), not 2;
  * the NoSQL oracle is differential: the ``$ne`` operator must authenticate where a wrong literal is
    rejected, so a page that merely contains the word "admin" cannot raise a finding;
  * the SSTI arithmetic canary uses ``1337*1337`` (1787569) rather than ``7*7`` (49), which is far
    less likely to occur in ordinary content by chance.

Every request goes through ``request_fn`` (injectable), so the engine is hermetically testable and
the pipeline can pin it to the authorised ``allow_ip`` exactly like the other active stages.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from packages.security_policies import Destination


@dataclass
class FuzzTarget:
    """An attackable endpoint parameter or JSON body field."""

    endpoint: str
    method: str = "POST"
    content_type: str = "application/x-www-form-urlencoded"
    parameter: str = ""
    baseline_value: Any = "test"
    is_json: bool = False
    json_path: list[str] = field(default_factory=list)
    raw_body_template: str | dict | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class LatencyProfile:
    """Statistical model of baseline response latency (seconds)."""

    samples: list[float]
    mean: float
    std_dev: float
    threshold: float  # mean + 3*std_dev + ~sleep margin


# shortcut: fixed 5s sleep probes; a vulnerable field costs 3 confirmation trials of ~5s each. Live
# wiring bounds target count (see scan_comprehensive) — raise delay/trials once an OOB oracle exists.
_SLEEP_SECONDS = 5
_SSTI_EXPR = "1337*1337"
_SSTI_EVAL = "1787569"


class BodyFuzzer:
    """Multi-method, body-aware active vulnerability engine."""

    def __init__(
        self,
        destination: Destination,
        allow_ip: str,
        timeout: float = 8.0,
        request_fn: Callable[..., tuple[int, dict[str, str], str, float]] | None = None,
    ) -> None:
        self.destination = destination
        self.allow_ip = allow_ip
        self.timeout = timeout
        self.request_fn = request_fn or self._default_request

    def _default_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, str], str, float]:
        """Execute a raw HTTP request pinned strictly to allow_ip."""
        effective_timeout = timeout or self.timeout
        is_https = self.destination.scheme == "https"
        target_host = self.destination.host
        target_port = self.destination.port

        req_headers = {
            "Host": target_host,
            "User-Agent": "SHARAY-BodyFuzzer/2.0 (Security Audit Engine)",
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            req_headers.update(headers)

        if isinstance(body, str):
            encoded_body = body.encode("utf-8")
        elif isinstance(body, bytes):
            encoded_body = body
        else:
            encoded_body = b""
        if encoded_body and "Content-Length" not in req_headers:
            req_headers["Content-Length"] = str(len(encoded_body))

        started = time.monotonic()
        conn: http.client.HTTPConnection | http.client.HTTPSConnection
        sock = None
        if is_https:
            tls_ctx = ssl.create_default_context()
            tls_ctx.check_hostname = False
            tls_ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((self.allow_ip, target_port), timeout=effective_timeout)
            conn_sock = tls_ctx.wrap_socket(sock, server_hostname=target_host)
            conn = http.client.HTTPSConnection(target_host, target_port, timeout=effective_timeout)
            conn.sock = conn_sock
        else:
            conn = http.client.HTTPConnection(self.allow_ip, target_port, timeout=effective_timeout)

        try:
            conn.request(method, path, body=encoded_body or None, headers=req_headers)
            resp = conn.getresponse()
            elapsed_ms = (time.monotonic() - started) * 1000.0
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            raw_body = resp.read(512 * 1024).decode("utf-8", errors="replace")
            return resp.status, resp_headers, raw_body, elapsed_ms
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def calibrate_latency(self, endpoint: str, samples_count: int = 3) -> LatencyProfile:
        """Measure baseline latency to derive the jitter mean and standard deviation."""
        samples: list[float] = []
        for _ in range(max(2, samples_count)):
            try:
                _, _, _, elapsed_ms = self.request_fn("GET", endpoint, timeout=4.0)
                samples.append(elapsed_ms / 1000.0)
            except Exception:
                samples.append(0.05)
        mean = sum(samples) / len(samples)
        variance = sum((s - mean) ** 2 for s in samples) / len(samples)
        std_dev = math.sqrt(variance)
        # 5s sleep probe margin: mean + 3σ + 4.25s (the spec's 4.5s with a small tolerance).
        threshold = mean + 3.0 * std_dev + 4.25
        return LatencyProfile(samples=samples, mean=mean, std_dev=std_dev, threshold=threshold)

    # -- body builders --------------------------------------------------------

    @staticmethod
    def build_form_targets(forms: list[dict[str, Any]]) -> list[FuzzTarget]:
        """Turn crawler-discovered forms into one FuzzTarget per named input."""
        targets: list[FuzzTarget] = []
        for form in forms:
            action = form.get("action", "/")
            method = form.get("method", "POST").upper()
            inputs = form.get("inputs", [])
            base_data = {inp.get("name"): "1" for inp in inputs if inp.get("name")}
            for inp in inputs:
                pname = inp.get("name")
                if not pname:
                    continue
                targets.append(
                    FuzzTarget(
                        endpoint=action,
                        method=method,
                        content_type="application/x-www-form-urlencoded",
                        parameter=pname,
                        baseline_value="1",
                        raw_body_template=dict(base_data),
                    )
                )
        return targets

    @staticmethod
    def mutate_json_payload(data: Any, json_path: list[str], payload: Any) -> Any:
        """Return a clone of `data` with the field at `json_path` replaced by `payload`."""
        if not json_path:
            return payload
        if isinstance(data, dict):
            clone = dict(data)
            key = json_path[0]
            if len(json_path) == 1:
                clone[key] = payload
            elif key in clone:
                clone[key] = BodyFuzzer.mutate_json_payload(clone[key], json_path[1:], payload)
            return clone
        if isinstance(data, list):
            clone_list = list(data)
            try:
                idx = int(json_path[0])
                if len(json_path) == 1:
                    clone_list[idx] = payload
                else:
                    clone_list[idx] = BodyFuzzer.mutate_json_payload(clone_list[idx], json_path[1:], payload)
            except (ValueError, IndexError):
                pass
            return clone_list
        return data

    def _encode_body(self, target: FuzzTarget, payload: Any) -> str:
        """Render a request body for `target` with `payload` placed in the fuzzed field."""
        if target.is_json and isinstance(target.raw_body_template, (dict, list)):
            return json.dumps(self.mutate_json_payload(target.raw_body_template, target.json_path, payload))
        if isinstance(target.raw_body_template, dict):
            body_dict = dict(target.raw_body_template)
            body_dict[target.parameter] = payload
            return urlencode(body_dict)
        return urlencode({target.parameter: payload})

    # -- oracles --------------------------------------------------------------

    def audit_time_based_sqli(self, target: FuzzTarget, sleep_seconds: int = _SLEEP_SECONDS) -> dict | None:
        """Blind SQLi via statistical delay, confirmed across 3 consecutive over-threshold trials."""
        latency = self.calibrate_latency(target.endpoint)
        dbms_payloads = [
            ("PostgreSQL", f"1; SELECT pg_sleep({sleep_seconds})--"),
            ("MySQL", f"1' AND SLEEP({sleep_seconds})-- -"),
            ("MSSQL", f"1; WAITFOR DELAY '0:0:{sleep_seconds}'--"),
        ]
        headers_base = {"Content-Type": target.content_type, **target.headers}
        for dbms, payload in dbms_payloads:
            req_body = self._encode_body(target, payload)
            delays: list[float] = []
            try:
                for _ in range(3):
                    _, _, _, elapsed_ms = self.request_fn(
                        target.method,
                        target.endpoint,
                        headers=headers_base,
                        body=req_body,
                        timeout=sleep_seconds + 5.0,
                    )
                    elapsed_s = elapsed_ms / 1000.0
                    delays.append(elapsed_s)
                    if elapsed_s < latency.threshold:  # one miss rejects this payload (jitter)
                        break
            except Exception:
                continue
            if len(delays) == 3 and all(d >= latency.threshold for d in delays):
                finding_url = f"{self.destination.origin}{target.endpoint}"
                observed = min(delays)
                return {
                    "category": "injection",
                    "severity": "critical",
                    "title": f"Time-Based Blind SQL Injection ({dbms}) in '{target.parameter}'",
                    "description": (
                        f"Parameter '{target.parameter}' on {target.endpoint} delayed its response "
                        f"past a calibrated baseline (mean {latency.mean:.2f}s, threshold "
                        f"{latency.threshold:.2f}s) on 3 consecutive trials under a {dbms} sleep payload."
                    ),
                    "target_url": finding_url,
                    "fingerprint": hashlib.sha256(
                        f"time_sqli:{self.destination.host}:{target.endpoint}:{target.parameter}".encode()
                    ).hexdigest(),
                    "cwe_id": "CWE-89",
                    "confidence": "high",
                    "status": "confirmed",
                    "lifecycle_state": "REPRODUCED",
                    "remediation": "Use parameterized queries or prepared statements for all database access.",
                    "poc": {
                        "method": target.method,
                        "url": finding_url,
                        "curl_command": (
                            f"curl -s -k -X {target.method} '{finding_url}' "
                            f"-H 'Content-Type: {target.content_type}' --data '{req_body}'"
                        ),
                        "parameter": target.parameter,
                        "payload": payload,
                        "dbms": dbms,
                        "baseline_mean_seconds": round(latency.mean, 3),
                        "observed_delay_seconds": round(observed, 3),
                        "trials": 3,
                        "reproduction_steps": (
                            f"Issue HTTP {target.method} to {finding_url} with the payload and measure a "
                            f"response delayed ~{sleep_seconds}s versus a benign value, across 3 trials."
                        ),
                    },
                }
        return None

    def audit_ssti(self, target: FuzzTarget) -> dict | None:
        """SSTI via polyglot arithmetic canary: evaluated result present, absent in baseline, literal
        not reflected (so reflection/XSS cannot masquerade as template evaluation)."""
        polyglots = [
            ("Jinja2/Twig", f"{{{{{_SSTI_EXPR}}}}}"),
            ("SpringEL/MVEL", f"${{{_SSTI_EXPR}}}"),
            ("Smarty/Freemarker", f"#{{{_SSTI_EXPR}}}"),
            ("ERB/ASP", f"<%= {_SSTI_EXPR} %>"),
        ]
        try:
            _, _, base_body, _ = self.request_fn("GET", target.endpoint, timeout=3.0)
        except Exception:
            base_body = ""
        headers_base = {"Content-Type": target.content_type, **target.headers}
        for engine, payload in polyglots:
            req_body = self._encode_body(target, payload)
            try:
                _, _, probe_body, _ = self.request_fn(
                    target.method, target.endpoint, headers=headers_base, body=req_body, timeout=4.0
                )
            except Exception:
                continue
            if _SSTI_EVAL in probe_body and _SSTI_EVAL not in base_body and payload not in probe_body:
                finding_url = f"{self.destination.origin}{target.endpoint}"
                fingerprinted_engine = engine

                # Conclusive template engine fingerprinting
                if "Jinja2" in engine or "Twig" in engine:
                    # Jinja2 (Python): {{7*'7'}} -> 7777777 (string multiplication)
                    # Twig (PHP): {{7*'7'}} -> 49 (numeric coercion)
                    j_payload = "{{7*'7'}}"
                    j_body_str = self._encode_body(target, j_payload)
                    try:
                        _, _, j_resp, _ = self.request_fn(
                            target.method, target.endpoint, headers=headers_base, body=j_body_str, timeout=4.0
                        )
                        if "7777777" in j_resp and j_payload not in j_resp:
                            fingerprinted_engine = "Jinja2"
                        elif "49" in j_resp and j_payload not in j_resp:
                            fingerprinted_engine = "Twig"
                    except Exception:
                        pass
                elif "SpringEL" in engine or "MVEL" in engine:
                    # Freemarker: ${"freemarker"?upper_case} -> FREEMARKER
                    # SpringEL: ${T(java.lang.Math).max(10,20)} -> 20
                    fm_payload = '${"freemarker"?upper_case}'
                    fm_body_str = self._encode_body(target, fm_payload)
                    try:
                        _, _, fm_resp, _ = self.request_fn(
                            target.method,
                            target.endpoint,
                            headers=headers_base,
                            body=fm_body_str,
                            timeout=4.0,
                        )
                        if "FREEMARKER" in fm_resp and fm_payload not in fm_resp:
                            fingerprinted_engine = "Freemarker"
                        else:
                            sp_payload = "${T(java.lang.Math).max(10,20)}"
                            sp_body_str = self._encode_body(target, sp_payload)
                            _, _, sp_resp, _ = self.request_fn(
                                target.method,
                                target.endpoint,
                                headers=headers_base,
                                body=sp_body_str,
                                timeout=4.0,
                            )
                            if "20" in sp_resp and sp_payload not in sp_resp:
                                fingerprinted_engine = "SpringEL"
                    except Exception:
                        pass
                elif "Smarty" in engine or "Freemarker" in engine:
                    fm_payload = '#{"freemarker"?upper_case}'
                    fm_body_str = self._encode_body(target, fm_payload)
                    try:
                        _, _, fm_resp, _ = self.request_fn(
                            target.method,
                            target.endpoint,
                            headers=headers_base,
                            body=fm_body_str,
                            timeout=4.0,
                        )
                        if "FREEMARKER" in fm_resp and fm_payload not in fm_resp:
                            fingerprinted_engine = "Freemarker"
                        else:
                            sm_payload = "{$smarty.version}"
                            sm_body_str = self._encode_body(target, sm_payload)
                            _, _, sm_resp, _ = self.request_fn(
                                target.method,
                                target.endpoint,
                                headers=headers_base,
                                body=sm_body_str,
                                timeout=4.0,
                            )
                            if sm_payload not in sm_resp and len(sm_resp) > 0:
                                fingerprinted_engine = "Smarty"
                    except Exception:
                        pass
                elif "ERB" in engine or "ASP" in engine:
                    erb_payload = "<%= 'erb'*2 %>"
                    erb_body_str = self._encode_body(target, erb_payload)
                    try:
                        _, _, erb_resp, _ = self.request_fn(
                            target.method,
                            target.endpoint,
                            headers=headers_base,
                            body=erb_body_str,
                            timeout=4.0,
                        )
                        if "erberb" in erb_resp and erb_payload not in erb_resp:
                            fingerprinted_engine = "ERB"
                    except Exception:
                        pass

                return {
                    "category": "injection",
                    "severity": "critical",
                    "title": f"Server-Side Template Injection (SSTI) in '{target.parameter}'",
                    "description": (
                        f"Parameter '{target.parameter}' on {target.endpoint} evaluated template "
                        f"expression '{payload}' to '{_SSTI_EVAL}'. "
                        f"Fingerprinted engine: {fingerprinted_engine}."
                    ),
                    "target_url": finding_url,
                    "fingerprint": hashlib.sha256(
                        f"ssti:{self.destination.host}:{target.endpoint}:{target.parameter}".encode()
                    ).hexdigest(),
                    "cwe_id": "CWE-1336",
                    "confidence": "high",
                    "status": "confirmed",
                    "lifecycle_state": "REPRODUCED",
                    "remediation": "Never concatenate untrusted input into template strings; pass it as bound data.",
                    "poc": {
                        "method": target.method,
                        "url": finding_url,
                        "curl_command": (
                            f"curl -s -k -X {target.method} '{finding_url}' "
                            f"-H 'Content-Type: {target.content_type}' --data '{req_body}'"
                        ),
                        "parameter": target.parameter,
                        "payload": payload,
                        "evaluated_result": _SSTI_EVAL,
                        "candidate_engine": engine,
                        "fingerprinted_engine": fingerprinted_engine,
                        "reproduction_steps": (
                            f"Issue HTTP {target.method} to {finding_url}; the response contains the "
                            f"evaluated arithmetic '{_SSTI_EVAL}' while the literal expression is not reflected."
                        ),
                    },
                }
        return None

    def audit_nosql_injection(self, target: FuzzTarget) -> dict | None:
        """NoSQL operator bypass, confirmed differentially: the ``$ne`` operator authenticates where a
        wrong literal is rejected. A page that always contains auth-looking words cannot false-positive,
        because the control request would contain them too."""
        if not target.is_json:
            return None
        auth_tokens = ("token", "jwt", "session", "authenticated", "success", "welcome")

        def _auth_signal(payload: Any) -> bool:
            body = json.dumps(self.mutate_json_payload(target.raw_body_template, target.json_path, payload))
            try:
                status, _, probe_body, _ = self.request_fn(
                    target.method,
                    target.endpoint,
                    headers={"Content-Type": "application/json", **target.headers},
                    body=body,
                    timeout=4.0,
                )
            except Exception:
                return False
            low = probe_body.lower()
            return status == 200 and any(tok in low for tok in auth_tokens)

        operator_payload = {"$ne": None}
        # Differential: operator must succeed where an impossible literal fails.
        if not _auth_signal(operator_payload) or _auth_signal("sharay_wrong_literal_control"):
            return None

        req_body = json.dumps(
            self.mutate_json_payload(target.raw_body_template, target.json_path, operator_payload)
        )
        finding_url = f"{self.destination.origin}{target.endpoint}"
        return {
            "category": "injection",
            "severity": "high",
            "title": f"NoSQL Injection Operator Bypass in '{target.parameter}'",
            "description": (
                f"Endpoint {target.endpoint} authenticated with NoSQL operator "
                f"'{json.dumps(operator_payload)}' in field '{target.parameter}' while an impossible "
                f"literal was rejected — a differential confirming query-operator injection."
            ),
            "target_url": finding_url,
            "fingerprint": hashlib.sha256(
                f"nosqli:{self.destination.host}:{target.endpoint}:{target.parameter}".encode()
            ).hexdigest(),
            "cwe_id": "CWE-943",
            "confidence": "high",
            "status": "suspected",
            "lifecycle_state": "CANDIDATE",
            "remediation": "Reject JSON keys beginning with '$' and cast inputs to expected primitive types.",
            "poc": {
                "method": target.method,
                "url": finding_url,
                "curl_command": (
                    f"curl -s -k -X {target.method} '{finding_url}' "
                    f"-H 'Content-Type: application/json' --data '{req_body}'"
                ),
                "parameter": target.parameter,
                "payload": json.dumps(operator_payload),
                "reproduction_steps": (
                    f"Issue HTTP {target.method} with the operator payload (authenticates) and with a wrong "
                    f"literal (rejected); the differential confirms the bypass."
                ),
            },
        }


__all__ = ["BodyFuzzer", "FuzzTarget", "LatencyProfile"]
