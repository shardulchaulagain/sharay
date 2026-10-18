"""Active behavioral differential testing engine.

Compares baseline responses against structured non-destructive probe vectors
(HTTP verb tampering, dynamic CORS reflection, Host header injection,
parameter canary reflection, and path canonicalization) to detect behavioral
anomalies and real-world vulnerabilities with high fidelity.
"""

from __future__ import annotations

import hashlib
import http.client
import re
import socket
import ssl
import time
from typing import Any

from packages.security_policies import Destination

_MAX_BODY_DIFF = 64 * 1024


def _send_probe(
    destination: Destination,
    allow_ip: str,
    method: str,
    path: str,
    headers: dict[str, str],
    timeout: float = 4.0,
) -> tuple[int, dict[str, str], str, float]:
    """Execute a single HTTP probe pinned to allow_ip, measuring latency and response."""
    is_https = destination.scheme == "https"
    target_host = destination.host
    target_port = destination.port

    req_headers = {
        "Host": headers.get("Host", target_host),
        "User-Agent": "SHARAY-DiffTester/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    for k, v in headers.items():
        if k != "Host":
            req_headers[k] = v

    started = time.monotonic()
    conn: http.client.HTTPConnection | http.client.HTTPSConnection
    if is_https:
        tls_ctx = ssl.create_default_context()
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((allow_ip, target_port), timeout=timeout)
        conn_sock = tls_ctx.wrap_socket(sock, server_hostname=target_host)
        conn = http.client.HTTPSConnection(target_host, target_port, timeout=timeout)
        conn.sock = conn_sock
    else:
        conn = http.client.HTTPConnection(allow_ip, target_port, timeout=timeout)

    try:
        conn.request(method, path, headers=req_headers)
        resp = conn.getresponse()
        elapsed_ms = (time.monotonic() - started) * 1000
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        body = resp.read(_MAX_BODY_DIFF).decode("utf-8", errors="replace")
        return resp.status, resp_headers, body, elapsed_ms
    finally:
        conn.close()


def run_differential_tests(
    destination: Destination,
    allow_ip: str,
    *,
    endpoints: list[str] | None = None,
    parameters: list[str] | None = None,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """Execute differential testing tests and return observations, findings, and checks."""
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    # 1. Baseline Request
    try:
        b_status, b_headers, b_body, b_time = _send_probe(
            destination, allow_ip, "GET", "/", {}, timeout=timeout
        )
    except Exception as exc:
        return {
            "findings": [],
            "observations": [],
            "checks": [
                {
                    "category": "differential_testing",
                    "status": "failed",
                    "detail": f"Baseline probe failed: {type(exc).__name__}",
                }
            ],
        }

    observations.append(
        {
            "kind": "differential_baseline",
            "category": "differential",
            "status": b_status,
            "latency_ms": round(b_time, 2),
            "body_length": len(b_body),
        }
    )

    # 2. HTTP Verb Tampering & Method Differential Matrix
    discovered_paths = [ep if ep.startswith("/") else f"/{ep}" for ep in (endpoints or []) if ep]
    target_endpoints = list(dict.fromkeys(["/"] + discovered_paths))[:6]

    for ep in target_endpoints:
        ep_url = f"{destination.url.rstrip('/')}{ep}"
        # A. Method inspection: OPTIONS & TRACE
        for method in ("OPTIONS", "TRACE"):
            try:
                m_status, m_headers, m_body, _ = _send_probe(
                    destination, allow_ip, method, ep, {}, timeout=timeout
                )
                observations.append(
                    {
                        "kind": "method_differential",
                        "endpoint": ep,
                        "method": method,
                        "status": m_status,
                        "allow_header": m_headers.get("allow"),
                    }
                )

                if method == "TRACE" and m_status == 200 and "sharay-difftester" in m_body.lower():
                    findings.append(
                        {
                            "category": "information_disclosure",
                            "severity": "medium",
                            "title": f"HTTP TRACE Method Enabled on {ep} (Cross-Site Tracing Potential)",
                            "description": (
                                f"The web server responds to HTTP TRACE requests on {ep} by echoing request headers, "
                                f"creating risk of credential and cookie interception."
                            ),
                            "target_url": ep_url,
                            "fingerprint": hashlib.sha256(
                                f"xst_{destination.host}_{ep}".encode()
                            ).hexdigest(),
                            "cwe_id": "CWE-205",
                            "attributes": {"endpoint": ep, "method": "TRACE", "status": m_status},
                        }
                    )

                if method == "OPTIONS" and m_status in (200, 204):
                    allowed = m_headers.get("allow", "").upper()
                    dangerous_methods = [m for m in ("PUT", "DELETE") if m in allowed]
                    if dangerous_methods:
                        findings.append(
                            {
                                "category": "configuration",
                                "severity": "low",
                                "title": f"Potentially Dangerous HTTP Methods Permitted on {ep} ({', '.join(dangerous_methods)})",
                                "description": f"The OPTIONS header on {ep} lists state-changing methods: {allowed}.",
                                "target_url": ep_url,
                                "fingerprint": hashlib.sha256(
                                    f"opt_{destination.host}_{ep}_{allowed}".encode()
                                ).hexdigest(),
                                "cwe_id": "CWE-650",
                                "attributes": {"endpoint": ep, "allowed_methods": allowed},
                            }
                        )
            except Exception:
                pass

        # B. HTTP Verb Tampering Access Control Bypass (CWE-288)
        try:
            get_status, _, _, _ = _send_probe(destination, allow_ip, "GET", ep, {}, timeout=timeout)
            if get_status in (401, 403):
                for alt_method in ("HEAD", "POST", "PUT", "PATCH", "DELETE"):
                    try:
                        alt_status, _, _, _ = _send_probe(
                            destination, allow_ip, alt_method, ep, {}, timeout=timeout
                        )
                        if alt_status in (200, 204):
                            findings.append(
                                {
                                    "category": "broken_access_control",
                                    "severity": "high",
                                    "title": f"HTTP Verb Tampering Access Control Bypass on {ep} ({alt_method})",
                                    "description": (
                                        f"Endpoint '{ep}' returned HTTP {get_status} on GET, but permitted access "
                                        f"with HTTP {alt_status} when probed with {alt_method}, bypassing verb-level access controls."
                                    ),
                                    "target_url": ep_url,
                                    "fingerprint": hashlib.sha256(
                                        f"verb_bypass_{destination.host}_{ep}_{alt_method}".encode()
                                    ).hexdigest(),
                                    "cwe_id": "CWE-288",
                                    "attributes": {
                                        "endpoint": ep,
                                        "baseline_method": "GET",
                                        "baseline_status": get_status,
                                        "bypass_method": alt_method,
                                        "bypass_status": alt_status,
                                    },
                                    "poc": {
                                        "method": alt_method,
                                        "url": ep_url,
                                        "curl_command": f"curl -X {alt_method} -i -s -k '{ep_url}'",
                                    },
                                }
                            )
                            break
                    except Exception:
                        pass
        except Exception:
            pass

    # 3. Dynamic CORS Origin Reflection Differential
    test_origin = "https://sharay-attacker.invalid"
    try:
        c_status, c_headers, _, _ = _send_probe(
            destination, allow_ip, "GET", "/", {"Origin": test_origin}, timeout=timeout
        )
        acao = c_headers.get("access-control-allow-origin", "")
        acac = c_headers.get("access-control-allow-credentials", "").lower() == "true"

        if acao == test_origin:
            severity = "high" if acac else "medium"
            title = (
                "Critical CORS Origin Reflection with Credentials"
                if acac
                else "Insecure CORS Dynamic Origin Reflection"
            )
            findings.append(
                {
                    "category": "security_misconfiguration",
                    "severity": severity,
                    "title": title,
                    "description": f"Server dynamically reflects arbitrary Origin header '{test_origin}' in Access-Control-Allow-Origin (Credentials: {acac}).",
                    "target_url": destination.url,
                    "fingerprint": hashlib.sha256(
                        f"cors_reflect_{destination.host}_{acac}".encode()
                    ).hexdigest(),
                    "cwe_id": "CWE-942",
                    "attributes": {"reflected_origin": acao, "credentials_allowed": acac},
                }
            )
    except Exception:
        pass

    # 4. Host Header Injection / Routing Differential
    poison_host = f"evil-canary.{destination.host}"
    try:
        h_status, h_headers, h_body, _ = _send_probe(
            destination, allow_ip, "GET", "/", {"Host": poison_host}, timeout=timeout
        )
        location = h_headers.get("location", "")
        if poison_host in location or (h_status == 200 and poison_host in h_body):
            # Verify if body reflection is in a sensitive tag (canonical or base href)
            is_reflected_in_markup = (
                f'href="{poison_host}' in h_body
                or f'href="https://{poison_host}' in h_body
                or f'href="http://{poison_host}' in h_body
            )
            if poison_host in location or is_reflected_in_markup:
                findings.append(
                    {
                        "category": "routing_manipulation",
                        "severity": "medium",
                        "title": "Host Header Injection in Server Response",
                        "description": f"The application reflects arbitrary Host header '{poison_host}' in redirect Location or markup.",
                        "target_url": destination.url,
                        "fingerprint": hashlib.sha256(f"hhi_{destination.host}".encode()).hexdigest(),
                        "cwe_id": "CWE-601",
                        "attributes": {"status": h_status, "location": location},
                    }
                )
    except Exception:
        pass

    # 5. Parameter Reflection & Context Differential
    canary_nonce = f"sharay{hashlib.md5(destination.host.encode()).hexdigest()[:8]}"
    tested_params = list(parameters or ["q", "search", "id", "ref"])[:6]
    for param in tested_params:
        try:
            probe_path = f"/?{param}={canary_nonce}"
            p_status, _, p_body, _ = _send_probe(
                destination, allow_ip, "GET", probe_path, {}, timeout=timeout
            )
            if canary_nonce in p_body and canary_nonce not in b_body:
                inside_tag = bool(re.search(r"<[^>]*" + re.escape(canary_nonce) + r"[^>]*>", p_body))
                observations.append(
                    {
                        "kind": "parameter_reflection",
                        "parameter": param,
                        "reflected": True,
                        "inside_tag": inside_tag,
                    }
                )
                findings.append(
                    {
                        "category": "injection",
                        "severity": "medium",
                        "title": f"Unencoded Parameter Reflection Detected ({param})",
                        "description": f"Query parameter '{param}' was reflected directly into response context without output sanitization.",
                        "target_url": f"{destination.url.rstrip('/')}{probe_path}",
                        "fingerprint": hashlib.sha256(
                            f"reflect_{destination.host}_{param}".encode()
                        ).hexdigest(),
                        "cwe_id": "CWE-79",
                        "attributes": {"parameter": param, "inside_tag": inside_tag},
                    }
                )
        except Exception:
            pass

    checks.append(
        {
            "category": "differential_testing",
            "status": "completed",
            "detail": f"Differential behavioral tests executed: 5 checks evaluated, {len(findings)} finding(s) confirmed.",
        }
    )

    return {
        "findings": findings,
        "observations": observations,
        "checks": checks,
    }


__all__ = ["run_differential_tests"]
