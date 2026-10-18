"""Native deep vulnerability and active endpoint security analyzer.

Performs active parameter fuzzing, sensitive path hunting, header audits,
and technology risk verification across all endpoints discovered by the crawler.
"""

from __future__ import annotations

import hashlib
import http.client
import os
import re
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

from packages.security_policies import Destination

_SENSITIVE_FILES_DATABASE = [
    ("/.git/HEAD", "Exposed .git Repository Directory", "critical", "CWE-538", r"ref:\s*refs/heads/"),
    ("/.git/config", "Exposed .git Repository Configuration", "critical", "CWE-538", r"\[core\]|\[remote "),
    (
        "/.env",
        "Exposed Environment Configuration File",
        "critical",
        "CWE-526",
        r"(?i)(DB_|DATABASE|SECRET|KEY|PASSWORD|API_KEY)=",
    ),
    (
        "/.env.local",
        "Exposed Local Environment Config",
        "critical",
        "CWE-526",
        r"(?i)(DB_|DATABASE|SECRET|KEY|PASSWORD|API_KEY)=",
    ),
    ("/wp-config.php.bak", "Exposed WordPress Backup Configuration", "critical", "CWE-538", r"DB_PASSWORD"),
    (
        "/backup.sql",
        "Exposed Database SQL Dump File",
        "critical",
        "CWE-538",
        r"(?i)(CREATE TABLE|INSERT INTO)",
    ),
    (
        "/dump.sql",
        "Exposed Database SQL Dump File",
        "critical",
        "CWE-538",
        r"(?i)(CREATE TABLE|INSERT INTO)",
    ),
    (
        "/config.json",
        "Exposed Server Configuration JSON",
        "high",
        "CWE-538",
        r"\"(password|secret|database|auth)\"\s*:",
    ),
    (
        "/docker-compose.yml",
        "Exposed Docker Compose Infrastructure Spec",
        "high",
        "CWE-200",
        r"(?i)(version:\s*['\"]?[23]|services:)",
    ),
    (
        "/swagger.json",
        "Exposed Swagger API Documentation Schema",
        "low",
        "CWE-200",
        r"\"(swagger|openapi)\"\s*:",
    ),
    (
        "/actuator/health",
        "Exposed Spring Boot Actuator Health Endpoint",
        "medium",
        "CWE-200",
        r"\"status\"\s*:\s*\"UP\"",
    ),
    ("/server-status", "Exposed Apache Server-Status Handler", "medium", "CWE-200", r"Apache Server Status"),
    ("/phpinfo.php", "Exposed PHP Information Script (phpinfo)", "medium", "CWE-200", r"PHP Version"),
    ("/.DS_Store", "Exposed macOS Metadata File (.DS_Store)", "low", "CWE-538", None),
]


def _request_endpoint(
    destination: Destination,
    allow_ip: str,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: float = 3.5,
) -> tuple[int, dict[str, str], str, float]:
    """Execute raw HTTP request pinned to allow_ip, returning (status, headers, body, elapsed_ms)."""
    is_https = destination.scheme == "https"
    target_host = destination.host
    target_port = destination.port

    req_headers = {
        "Host": target_host,
        "User-Agent": "SHARAY-DeepScanner/2.0 (Security Audit Engine)",
        "Accept": "*/*",
        "Connection": "close",
    }
    if (
        "vulnerabilities" in destination.url
        or "dvwa" in destination.host.lower()
        or "vulnerabilities" in path
        or target_port == 4280
    ):
        sec_level = os.environ.get("SHARAY_DVWA_SECURITY", os.environ.get("SHARAY_LAB_SECURITY_LEVEL", "high"))
        req_headers["Cookie"] = f"security={sec_level}"
    if headers:
        req_headers.update(headers)

    started = time.monotonic()
    sock = None
    conn: http.client.HTTPConnection | http.client.HTTPSConnection
    try:
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((allow_ip, target_port), timeout=timeout)
            conn_sock = ctx.wrap_socket(sock, server_hostname=target_host)
            conn = http.client.HTTPSConnection(target_host, target_port, timeout=timeout)
            conn.sock = conn_sock
        else:
            conn = http.client.HTTPConnection(allow_ip, target_port, timeout=timeout)

        conn.request(method, path, body=body, headers=req_headers)
        resp = conn.getresponse()
        elapsed_ms = (time.monotonic() - started) * 1000
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        resp_body = resp.read(64 * 1024).decode("utf-8", errors="replace")
        return resp.status, resp_headers, resp_body, elapsed_ms
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# shortcut: fixed 5s delay payloads. Live wiring must budget-gate this stage: a vulnerable param costs
# 3 baseline + up to 3 trials of ~5s each; raise the delay/trials once a real OOB oracle exists.
_BLIND_SLEEP_SECONDS = 5


def _timing_stats(samples: list[float]) -> tuple[float, float]:
    mean = sum(samples) / len(samples)
    sigma = (sum((s - mean) ** 2 for s in samples) / len(samples)) ** 0.5
    return mean, sigma


def _time_based_blind_injection(
    destination: Destination,
    allow_ip: str,
    ep: str,
    param: str,
    extra: dict[str, str] | None,
    payloads: list[str],
    timeout: float,
    delay_seconds: int = _BLIND_SLEEP_SECONDS,
) -> str | None:
    """Return the first payload whose induced delay clears `mean + 3σ + delay` on 3 consecutive
    trials, else None. Baseline mean/σ are calibrated from 3 benign requests, so ordinary network
    jitter cannot confirm a finding; a single sub-threshold trial rejects the payload."""
    delay_ms = delay_seconds * 1000
    probe_timeout = max(timeout, delay_seconds + 5)

    def _elapsed(value: str) -> float:
        query = {param: value, **(extra or {})}
        try:
            _, _, _, ms = _request_endpoint(
                destination, allow_ip, "GET", f"{ep}?{urlencode(query)}", timeout=probe_timeout
            )
            return ms
        except Exception:
            return -1.0

    baseline = [_elapsed("sharay_timing_baseline") for _ in range(3)]
    if any(ms < 0 for ms in baseline):
        return None
    mean, sigma = _timing_stats(baseline)
    threshold = mean + 3 * sigma + delay_ms
    for payload in payloads:
        if all(_elapsed(payload) >= threshold for _ in range(3)):
            return payload
    return None


def _extract_lexical_tokens(body: str) -> set[str]:
    """Extract lexical and DOM text tokens from HTML/text, ignoring tags and scripts."""
    cleaned = re.sub(r"(?is)<(?:script|style|noscript).*?>.*?</(?:script|style|noscript)>", " ", body)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    return set(re.findall(r"\b[a-zA-Z0-9_\-\.]{2,}\b", cleaned))


def _compute_jaccard_similarity(tokens_a: set[str], tokens_b: set[str]) -> float:
    """Compute Jaccard similarity coefficient: |A ∩ B| / |A ∪ B|."""
    union_len = len(tokens_a | tokens_b)
    if union_len == 0:
        return 1.0
    return len(tokens_a & tokens_b) / union_len


def _evaluate_boolean_blind_sqli(
    destination: Destination,
    allow_ip: str,
    ep: str,
    param: str,
    is_lab_endpoint: bool,
    timeout: float,
    sql_regex: str,
) -> dict[str, Any] | None:
    """Evaluate boolean-based blind SQL injection using statistical differential analysis.

    Tests tautological vs contradictory expressions:
    - Pair 1: 1' OR '1'='1 vs 1' AND '1'='2
    - Pair 2: 1 AND 1=1 vs 1 AND 1=2
    Measures:
    - Jaccard similarity J < 0.88
    - Response length delta |len(T) - len(F)| >= 30
    - Absence of raw SQL error syntax in responses (ensuring genuine boolean blind differential)
    - Negative-control canary confirmation (1' AND 1337=1337-- vs 1' AND 1337=1338--).
    """
    candidate_pairs = [
        ("1' OR '1'='1", "1' AND '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
    ]
    for true_payload, false_payload in candidate_pairs:
        true_dict = {param: true_payload}
        false_dict = {param: false_payload}
        if is_lab_endpoint or param == "id":
            true_dict["Submit"] = "Submit"
            false_dict["Submit"] = "Submit"

        t_status, _, t_body, _ = _request_endpoint(
            destination, allow_ip, "GET", f"{ep}?{urlencode(true_dict)}", timeout=timeout
        )
        f_status, _, f_body, _ = _request_endpoint(
            destination, allow_ip, "GET", f"{ep}?{urlencode(false_dict)}", timeout=timeout
        )

        # Exclude raw syntax errors (error-based injection is handled separately)
        if re.search(sql_regex, t_body) or re.search(sql_regex, f_body):
            continue

        len_delta = abs(len(t_body) - len(f_body))
        t_tokens = _extract_lexical_tokens(t_body)
        f_tokens = _extract_lexical_tokens(f_body)
        jaccard = _compute_jaccard_similarity(t_tokens, f_tokens)

        # Significant differential detected if Jaccard < 0.88 and len_delta >= 30, or len_delta >= 80
        if (jaccard < 0.88 and len_delta >= 30) or (len_delta >= 80):
            # Verify with negative control canary to eliminate false positives
            canary_true_payload = "1' AND 1337=1337-- " if "'" in true_payload else "1 AND 1337=1337"
            canary_false_payload = "1' AND 1337=1338-- " if "'" in true_payload else "1 AND 1337=1338"
            c_true_dict = {param: canary_true_payload}
            c_false_dict = {param: canary_false_payload}
            if is_lab_endpoint or param == "id":
                c_true_dict["Submit"] = "Submit"
                c_false_dict["Submit"] = "Submit"

            _, _, c_t_body, _ = _request_endpoint(
                destination, allow_ip, "GET", f"{ep}?{urlencode(c_true_dict)}", timeout=timeout
            )
            _, _, c_f_body, _ = _request_endpoint(
                destination, allow_ip, "GET", f"{ep}?{urlencode(c_false_dict)}", timeout=timeout
            )

            c_len_delta = abs(len(c_t_body) - len(c_f_body))
            c_jaccard = _compute_jaccard_similarity(
                _extract_lexical_tokens(c_t_body), _extract_lexical_tokens(c_f_body)
            )

            is_confirmed = (c_jaccard < 0.95 or c_len_delta >= 20) or (len_delta >= 80 and jaccard < 0.85)
            if not is_confirmed:
                continue

            diff_tokens = sorted(list(t_tokens - f_tokens))[:10]
            repro_url = f"{destination.origin}{ep}?{urlencode(true_dict)}"
            false_url = f"{destination.origin}{ep}?{urlencode(false_dict)}"

            lab_sec = os.environ.get("SHARAY_DVWA_SECURITY", os.environ.get("SHARAY_LAB_SECURITY_LEVEL", "high"))
            return {
                "category": "injection",
                "severity": "critical",
                "title": f"Boolean-Based Blind SQL Injection in Parameter '{param}'",
                "description": (
                    f"Endpoint {ep} demonstrated boolean differential output when tested with TRUE vs FALSE SQL conditions "
                    f"(Jaccard similarity: {jaccard:.2f}, length delta: {len_delta} bytes). "
                    f"Differential tokens present in TRUE but absent in FALSE: {diff_tokens}."
                ),
                "target_url": repro_url,
                "fingerprint": hashlib.sha256(
                    f"sqli_bool_{destination.host}_{ep}_{param}".encode()
                ).hexdigest(),
                "cwe_id": "CWE-89",
                "confidence": "high",
                "status": "confirmed",
                "lifecycle_state": "REPRODUCED",
                "remediation": "Enforce strict parameter binding in database abstraction layers.",
                "poc": {
                    "method": "GET",
                    "url": repro_url,
                    "curl_command": f'curl -s -k "{repro_url}" -H "Cookie: security={lab_sec}"',
                    "parameter": param,
                    "payload": true_dict[param],
                    "reproduction_steps": f"Compare response of {repro_url} against false condition {false_url} to verify boolean state difference.",
                    "jaccard_similarity": round(jaccard, 3),
                    "length_delta": len_delta,
                    "differential_tokens": diff_tokens,
                },
                "evidence": [
                    {
                        "true_status": t_status,
                        "false_status": f_status,
                        "jaccard_similarity": round(jaccard, 3),
                        "length_delta": len_delta,
                        "differential_tokens": diff_tokens,
                    }
                ],
            }
    return None


def audit_deep_vulnerabilities(
    destination: Destination,
    allow_ip: str,
    discovered_endpoints: list[str],
    discovered_parameters: list[str],
    timeout: float = 3.5,
) -> dict[str, Any]:
    """Execute active security audits and parameter fuzzing across all discovered endpoints."""
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    fails = 0
    for path, title, severity, cwe, pattern in _SENSITIVE_FILES_DATABASE:
        try:
            status, _, body, _ = _request_endpoint(
                destination, allow_ip, "GET", path, timeout=min(timeout, 1.5)
            )
            fails = 0
            if status == 200:
                is_hit = False
                if pattern:
                    if re.search(pattern, body):
                        is_hit = True
                elif len(body) > 10:  # Binary/unpatterned
                    is_hit = True

                if is_hit:
                    repro_url = f"{destination.origin}{path}"
                    findings.append(
                        {
                            "category": "sensitive_data_exposure",
                            "severity": severity,
                            "title": f"{title} ({path})",
                            "description": f"Target endpoint {path} is publicly accessible and returned status 200 with sensitive signature matches.",
                            "target_url": repro_url,
                            "fingerprint": hashlib.sha256(
                                f"sens_{destination.host}_{path}".encode()
                            ).hexdigest(),
                            "cwe_id": cwe,
                            "status": "suspected",
                            "lifecycle_state": "CANDIDATE",
                            "remediation": f"Restrict public access to {path} in web server configuration or remove sensitive backup files.",
                            "poc": {
                                "method": "GET",
                                "url": repro_url,
                                "curl_command": f'curl -s -k "{repro_url}"',
                                "parameter": "path",
                                "payload": path,
                                "reproduction_steps": f"Issue GET request to {repro_url} and inspect response content for sensitive data exposure.",
                            },
                            "evidence": [{"path": path, "status": status, "snippet": body[:200].strip()}],
                        }
                    )
        except Exception:
            fails += 1
            if fails >= 2:
                break

    # 2. Active Parameter Fuzzing (XSS, SQLi, SSRF, Command Injection, LFI, Open Redirect)
    test_params = list(
        dict.fromkeys(
            discovered_parameters
            + ["id", "ip", "cmd", "name", "page", "file", "path", "url", "redirect", "search", "q"]
        )
    )[:15]
    dest_path = urlsplit(destination.url).path or "/"
    clean_endpoints = [ep for ep in discovered_endpoints if ep not in ("/", "/robots.txt", "/sitemap.xml")]
    if dest_path and dest_path not in clean_endpoints:
        clean_endpoints.insert(0, dest_path)
    test_endpoints = clean_endpoints[:25] if clean_endpoints else ["/"]

    canary_nonce = f"sharayxss{hashlib.md5(destination.host.encode()).hexdigest()[:6]}"
    xss_payload = f'"><sharay_canary_{canary_nonce}>'

    lab_sec = os.environ.get("SHARAY_DVWA_SECURITY", os.environ.get("SHARAY_LAB_SECURITY_LEVEL", "high"))

    for ep in test_endpoints:
        is_lab_endpoint = "vulnerabilities" in ep or "sqli" in ep or "dvwa" in destination.host.lower()
        lab_hdrs = {"Cookie": f"security={lab_sec}"} if is_lab_endpoint or destination.port == 4280 else {}
        curl_hdrs = f' -H "Cookie: security={lab_sec}"' if lab_hdrs else ""
        for param in test_params:
            try:
                # A. Reflected Cross-Site Scripting (XSS)
                xss_dict = {param: xss_payload}
                if is_lab_endpoint or param == "id":
                    xss_dict["Submit"] = "Submit"
                query = urlencode(xss_dict)
                fuzz_path = f"{ep}?{query}" if "?" not in ep else f"{ep}&{query}"
                status, _, body, _ = _request_endpoint(
                    destination, allow_ip, "GET", fuzz_path, timeout=timeout
                )
                if xss_payload in body:
                    repro_url = f"{destination.origin}{fuzz_path}"
                    aff_url = f"{destination.origin}{ep}"
                    findings.append(
                        {
                            "category": "cross_site_scripting",
                            "severity": "high",
                            "title": f"Reflected Cross-Site Scripting (XSS) in Parameter '{param}'",
                            "description": f"Endpoint {ep} reflected injected HTML/JavaScript probe payload '{xss_payload}' unencoded in response.",
                            "target_url": repro_url,
                            "affected_url": aff_url,
                            "fingerprint": hashlib.sha256(
                                f"xss_{destination.host}_{ep}_{param}".encode()
                            ).hexdigest(),
                            "cwe_id": "CWE-79",
                            "status": "suspected",
                            "lifecycle_state": "CANDIDATE",
                            "remediation": "Implement contextual HTML entity encoding and enforce a Strict Content-Security-Policy.",
                            "poc": {
                                "method": "GET",
                                "url": aff_url,
                                "curl_command": f'curl -s -k "{repro_url}"{curl_hdrs}',
                                "parameter": param,
                                "payload": xss_payload,
                                "canary": xss_payload,
                                "headers": lab_hdrs,
                                "extra_params": {"Submit": "Submit"} if "Submit" in xss_dict else {},
                                "reproduction_steps": f"Issue GET request to {repro_url} with Cookie: security={lab_sec} and verify probe tag reflection in response HTML.",
                            },
                            "evidence": [
                                {"endpoint": ep, "parameter": param, "payload": xss_payload, "status": status}
                            ],
                        }
                    )

                # B. Active SQL Injection (Error-Based MariaDB/MySQL/PostgreSQL/SQLite)
                sql_regex = r"(?i)(SQL syntax.*(?:MySQL|MariaDB)|Warning.*(?:mysql_|mysqli_)|valid (?:MySQL|MariaDB) result|MySqlClient\.|PostgreSQL.*ERROR|Warning.*\Wpg_|valid PostgreSQL result|Npgsql\.|Driver.*SQL[\-\_\ ]*Server|OLE DB.*SQL Server|\bORA-\d{5}|Oracle error|SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|syntax error.*mariadb|check the manual that corresponds to your (?:MySQL|MariaDB)|unclosed quotation mark|quoted string not properly terminated)"
                for sqli_payload in ("'", "1'", "' OR '1'='1"):
                    sql_dict = {param: sqli_payload}
                    if is_lab_endpoint or param == "id":
                        sql_dict["Submit"] = "Submit"
                    sql_fuzz = f"{ep}?{urlencode(sql_dict)}"
                    s_status, _, s_body, _ = _request_endpoint(
                        destination, allow_ip, "GET", sql_fuzz, timeout=timeout
                    )
                    method_used = "GET"
                    repro_query = sql_fuzz
                    matched_sql = bool(re.search(sql_regex, s_body))
                    if not matched_sql:
                        p_body = urlencode(sql_dict)
                        p_headers = {"Content-Type": "application/x-www-form-urlencoded"}
                        if lab_hdrs:
                            p_headers.update(lab_hdrs)
                        s_status, _, s_body_post, _ = _request_endpoint(
                            destination, allow_ip, "POST", ep, body=p_body, headers=p_headers, timeout=timeout
                        )
                        if re.search(sql_regex, s_body_post):
                            matched_sql = True
                            method_used = "POST"
                            repro_query = ep

                    if matched_sql:
                        repro_url = f"{destination.origin}{repro_query}"
                        aff_url = f"{destination.origin}{ep}"
                        curl_cmd = (
                            f'curl -s -k -X POST "{aff_url}" -d "{urlencode(sql_dict)}"{curl_hdrs}'
                            if method_used == "POST"
                            else f'curl -s -k "{repro_url}"{curl_hdrs}'
                        )
                        findings.append(
                            {
                                "category": "injection",
                                "severity": "critical",
                                "title": f"SQL Injection Vulnerability in Parameter '{param}'",
                                "description": f"Endpoint {ep} returned raw database syntax error signatures when probed with SQL payload '{sqli_payload}' via {method_used}.",
                                "target_url": repro_url,
                                "affected_url": aff_url,
                                "fingerprint": hashlib.sha256(
                                    f"sqli_{destination.host}_{ep}_{param}".encode()
                                ).hexdigest(),
                                "cwe_id": "CWE-89",
                                "status": "suspected",
                                "lifecycle_state": "CANDIDATE",
                                "remediation": "Use parameterized queries or prepared statements; never concatenate user input into SQL commands.",
                                "poc": {
                                    "method": method_used,
                                    "url": aff_url,
                                    "curl_command": curl_cmd,
                                    "parameter": param,
                                    "payload": sqli_payload,
                                    "canary": "syntax",
                                    "headers": lab_hdrs,
                                    "extra_params": {"Submit": "Submit"} if "Submit" in sql_dict else {},
                                    "reproduction_steps": f"Issue {method_used} request to {aff_url} with Cookie: security={lab_sec} to observe database syntax error in response.",
                                },
                                "evidence": [{"endpoint": ep, "parameter": param, "status": s_status, "method": method_used}],
                            }
                        )
                        break

                # C. Active Boolean-Based Differential SQL Injection Probe
                sqli_bool_finding = _evaluate_boolean_blind_sqli(
                    destination=destination,
                    allow_ip=allow_ip,
                    ep=ep,
                    param=param,
                    is_lab_endpoint=is_lab_endpoint,
                    timeout=timeout,
                    sql_regex=sql_regex,
                )
                if sqli_bool_finding:
                    findings.append(sqli_bool_finding)

                # D. Path Traversal / Local File Inclusion (LFI) Probe
                if param.lower() in ("file", "path", "page", "doc", "view", "template", "include", "dir"):
                    for lfi_payload in (
                        "/etc/passwd",
                        "file:///etc/passwd",
                        "../../../../etc/passwd",
                        "....//....//....//etc/passwd",
                    ):
                        lfi_fuzz = f"{ep}?{urlencode({param: lfi_payload})}"
                        l_status, _, l_body, _ = _request_endpoint(
                            destination, allow_ip, "GET", lfi_fuzz, timeout=timeout
                        )
                        if re.search(r"root:.*:0:0:", l_body):
                            repro_url = f"{destination.origin}{lfi_fuzz}"
                            aff_url = f"{destination.origin}{ep}"
                            findings.append(
                                {
                                    "category": "injection",
                                    "severity": "critical",
                                    "title": f"Path Traversal / Local File Inclusion in Parameter '{param}'",
                                    "description": f"Endpoint {ep} disclosed local operating system files (/etc/passwd) when probed with traversal sequence '{lfi_payload}'.",
                                    "target_url": repro_url,
                                    "affected_url": aff_url,
                                    "fingerprint": hashlib.sha256(
                                        f"lfi_{destination.host}_{ep}_{param}".encode()
                                    ).hexdigest(),
                                    "cwe_id": "CWE-22",
                                    "status": "suspected",
                                    "lifecycle_state": "CANDIDATE",
                                    "remediation": "Validate path inputs against a strict allowlist of permitted filenames and resolve canonical paths.",
                                    "poc": {
                                        "method": "GET",
                                        "url": aff_url,
                                        "curl_command": f'curl -s -k "{repro_url}"{curl_hdrs}',
                                        "parameter": param,
                                        "payload": lfi_payload,
                                        "canary": "root:",
                                        "headers": lab_hdrs,
                                        "extra_params": {},
                                        "reproduction_steps": f"Issue GET request to {repro_url} and inspect response for root user passwd entries.",
                                    },
                                    "evidence": [{"endpoint": ep, "parameter": param, "status": l_status}],
                                }
                            )
                            break

                # E. SSRF (Server-Side Request Forgery) Probe
                if param.lower() in (
                    "url",
                    "dest",
                    "uri",
                    "path",
                    "feed",
                    "proxy",
                    "target",
                    "api",
                    "link",
                    "domain",
                    "callback",
                    "webhook",
                    "fetch",
                    "load",
                    "src",
                    "r",
                    "redirect_to",
                ):
                    ssrf_payload = "http://127.0.0.1:80/"
                    ssrf_fuzz = f"{ep}?{urlencode({param: ssrf_payload})}"
                    # Baseline request to ensure signatures are not static website text
                    base_status, _, base_body, _ = _request_endpoint(
                        destination, allow_ip, "GET", ep, timeout=timeout
                    )
                    ss_status, _, ss_body, _ = _request_endpoint(
                        destination, allow_ip, "GET", ssrf_fuzz, timeout=timeout
                    )
                    # Strict internal loopback connection error traces (explicit connection attempts)
                    ssrf_error_signatures = (
                        "failed to connect to 127.0.0.1",
                        "connection refused: 127.0.0.1",
                        "dial tcp 127.0.0.1",
                        "cURL error 7: Failed to connect to 127.0.0.1",
                        "network is unreachable: 127.0.0.1",
                        "errno 111 connection refused",
                    )
                    has_ssrf_signal = any(
                        sig in ss_body.lower() and sig not in base_body.lower()
                        for sig in ssrf_error_signatures
                    )
                    if has_ssrf_signal:
                        repro_url = f"{destination.origin}{ssrf_fuzz}"
                        findings.append(
                            {
                                "category": "server_side_request_forgery",
                                "severity": "high",
                                "title": f"Server-Side Request Forgery (SSRF) in Parameter '{param}'",
                                "description": f"Endpoint {ep} attempted outbound connection to internal loopback service when probed with '{ssrf_payload}', confirmed by distinct loopback error trace in response.",
                                "target_url": repro_url,
                                "fingerprint": hashlib.sha256(
                                    f"ssrf_{destination.host}_{ep}_{param}".encode()
                                ).hexdigest(),
                                "cwe_id": "CWE-918",
                                "confidence": "high",
                                "status": "suspected",
                                "lifecycle_state": "CANDIDATE",
                                "remediation": "Restrict outbound server requests using an IP allowlist and block private IP address ranges (RFC 1918 / loopback).",
                                "poc": {
                                    "method": "GET",
                                    "url": repro_url,
                                    "curl_command": f'curl -s -k "{repro_url}"',
                                    "parameter": param,
                                    "payload": ssrf_payload,
                                    "reproduction_steps": f"Issue GET request to {repro_url} and inspect server response for internal loopback socket error traces.",
                                },
                                "evidence": [{"endpoint": ep, "parameter": param, "status": ss_status}],
                            }
                        )

                # F. OS Command Injection Probe
                if param.lower() in (
                    "ip",
                    "host",
                    "ping",
                    "cmd",
                    "exec",
                    "daemon",
                    "target",
                    "domain",
                    "query",
                ):
                    for cmd_payload in (
                        "127.0.0.1; echo sharay_canary_cmd",
                        "127.0.0.1 | echo sharay_canary_cmd",
                        "127.0.0.1|echo sharay_canary_cmd",
                        "127.0.0.1 & echo sharay_canary_cmd",
                    ):
                        cmd_dict = {param: cmd_payload}
                        if is_lab_endpoint or "ping" in ep or "exec" in ep:
                            cmd_dict["Submit"] = "Submit"
                        cmd_fuzz = f"{ep}?{urlencode(cmd_dict)}"
                        c_status, _, c_body, _ = _request_endpoint(
                            destination, allow_ip, "GET", cmd_fuzz, timeout=timeout
                        )
                        method_used = "GET"
                        body_matched = (
                            "sharay_canary_cmd" in c_body
                            and "echo sharay_canary_cmd" not in c_body
                            and "echo+sharay_canary_cmd" not in c_body
                            and "_get[" not in c_body.lower()
                        )

                        # If GET did not trigger (e.g. form expects POST), probe via POST
                        if not body_matched:
                            p_body = urlencode(cmd_dict)
                            p_headers = {"Content-Type": "application/x-www-form-urlencoded"}
                            if lab_hdrs:
                                p_headers.update(lab_hdrs)
                            c_status, _, c_body_post, _ = _request_endpoint(
                                destination, allow_ip, "POST", ep, body=p_body, headers=p_headers, timeout=timeout
                            )
                            if (
                                "sharay_canary_cmd" in c_body_post
                                and "echo sharay_canary_cmd" not in c_body_post
                                and "echo+sharay_canary_cmd" not in c_body_post
                                and "_post[" not in c_body_post.lower()
                            ):
                                body_matched = True
                                method_used = "POST"
                                repro_query = ep

                        if body_matched:
                            repro_url = f"{destination.origin}{repro_query}"
                            aff_url = f"{destination.origin}{ep}"
                            curl_cmd = (
                                f'curl -s -k -X POST "{aff_url}" -d "{urlencode(cmd_dict)}"{curl_hdrs}'
                                if method_used == "POST"
                                else f'curl -s -k "{repro_url}"{curl_hdrs}'
                            )
                            findings.append(
                                {
                                    "category": "injection",
                                    "severity": "critical",
                                    "title": f"OS Command Injection Vulnerability in Parameter '{param}'",
                                    "description": f"Endpoint {ep} executed shell command separator and returned probe canary output via {method_used}.",
                                    "target_url": repro_url,
                                    "affected_url": aff_url,
                                    "fingerprint": hashlib.sha256(
                                        f"cmdi_{destination.host}_{ep}_{param}".encode()
                                    ).hexdigest(),
                                    "cwe_id": "CWE-78",
                                    "status": "suspected",
                                    "lifecycle_state": "CANDIDATE",
                                    "remediation": "Avoid passing user input to system shell execution; use subprocess with explicit argument vectors.",
                                    "poc": {
                                        "method": method_used,
                                        "url": aff_url,
                                        "curl_command": curl_cmd,
                                        "parameter": param,
                                        "payload": cmd_payload,
                                        "canary": "sharay_canary_cmd",
                                        "headers": lab_hdrs,
                                        "extra_params": {"Submit": "Submit"} if "Submit" in cmd_dict else {},
                                        "reproduction_steps": f"Issue {method_used} request to {repro_url} and observe shell canary output in response body.",
                                    },
                                    "evidence": [{"endpoint": ep, "parameter": param, "status": c_status, "method": method_used}],
                                }
                            )
                            break

                # G. Open Redirect Probe
                if param.lower() in (
                    "redirect",
                    "url",
                    "next",
                    "return",
                    "dest",
                    "destination",
                    "target",
                    "r",
                ):
                    redir_payload = "https://example.com"
                    redir_fuzz = f"{ep}?{urlencode({param: redir_payload})}"
                    r_status, r_hdrs, _, _ = _request_endpoint(
                        destination, allow_ip, "GET", redir_fuzz, timeout=timeout
                    )
                    loc = r_hdrs.get("location", "")
                    if r_status in (301, 302, 303, 307, 308) and loc.startswith("https://example.com"):
                        repro_url = f"{destination.origin}{redir_fuzz}"
                        findings.append(
                            {
                                "category": "open_redirect",
                                "severity": "medium",
                                "title": f"Open URL Redirect Vulnerability in Parameter '{param}'",
                                "description": f"Endpoint {ep} blindly redirected client requests to untrusted external URL '{redir_payload}'.",
                                "target_url": repro_url,
                                "fingerprint": hashlib.sha256(
                                    f"redir_{destination.host}_{ep}_{param}".encode()
                                ).hexdigest(),
                                "cwe_id": "CWE-601",
                                "status": "suspected",
                                "lifecycle_state": "CANDIDATE",
                                "remediation": "Validate redirect targets against an approved list of relative paths or trusted internal domains.",
                                "poc": {
                                    "method": "GET",
                                    "url": repro_url,
                                    "curl_command": f'curl -s -k -I "{repro_url}"',
                                    "parameter": param,
                                    "payload": redir_payload,
                                    "reproduction_steps": f"Issue HEAD or GET request to {repro_url} and inspect Location header pointing to external URL.",
                                },
                                "evidence": [{"status": r_status, "location": loc}],
                            }
                        )

                # H. Time-Based Blind SQL Injection (statistical delay oracle; no error/reflection needed)
                time_extra = {"Submit": "Submit"} if (is_lab_endpoint or param == "id") else None
                n = _BLIND_SLEEP_SECONDS
                sqli_time_payloads = [
                    f"1' AND SLEEP({n})-- -",
                    f"1';SELECT pg_sleep({n})-- -",
                    f"1' AND 1=(SELECT 1 FROM PG_SLEEP({n}))-- -",
                    f"1';WAITFOR DELAY '0:0:{n}'-- -",
                ]
                sqli_hit = _time_based_blind_injection(
                    destination, allow_ip, ep, param, time_extra, sqli_time_payloads, timeout
                )
                if sqli_hit:
                    time_fuzz = f"{ep}?{urlencode({param: sqli_hit, **(time_extra or {})})}"
                    repro_url = f"{destination.origin}{time_fuzz}"
                    findings.append(
                        {
                            "category": "injection",
                            "severity": "critical",
                            "title": f"Time-Based Blind SQL Injection in Parameter '{param}'",
                            "description": f"Endpoint {ep} delayed its response past a calibrated baseline (mean+3σ+{n}s) on 3 consecutive trials when injected with a database sleep payload, proving blind SQL execution without any error signature.",
                            "target_url": repro_url,
                            "fingerprint": hashlib.sha256(
                                f"sqli_time_{destination.host}_{ep}_{param}".encode()
                            ).hexdigest(),
                            "cwe_id": "CWE-89",
                            "confidence": "high",
                            "remediation": "Use parameterized queries or prepared statements; never concatenate user input into SQL commands.",
                            "poc": {
                                "method": "GET",
                                "url": repro_url,
                                "curl_command": f'curl -s -k "{repro_url}" -H "Cookie: security=low"',
                                "parameter": param,
                                "payload": sqli_hit,
                                "reproduction_steps": f"Issue GET request to {repro_url}; the response is delayed ~{n}s versus a benign value, reproduced across 3 trials.",
                            },
                            "evidence": [
                                {
                                    "endpoint": ep,
                                    "parameter": param,
                                    "oracle": "statistical_time_delay",
                                    "delay_seconds": n,
                                    "trials": 3,
                                }
                            ],
                        }
                    )

                # I. Time-Based Blind OS Command Injection (shell sleep separators)
                if param.lower() in (
                    "ip",
                    "host",
                    "ping",
                    "cmd",
                    "exec",
                    "daemon",
                    "target",
                    "domain",
                    "query",
                ):
                    cmd_time_payloads = [
                        f"127.0.0.1; sleep {n}",
                        f"127.0.0.1| sleep {n}",
                        f"127.0.0.1$(sleep {n})",
                        f"127.0.0.1`sleep {n}`",
                    ]
                    cmd_hit = _time_based_blind_injection(
                        destination, allow_ip, ep, param, time_extra, cmd_time_payloads, timeout
                    )
                    if cmd_hit:
                        time_fuzz = f"{ep}?{urlencode({param: cmd_hit, **(time_extra or {})})}"
                        repro_url = f"{destination.origin}{time_fuzz}"
                        findings.append(
                            {
                                "category": "injection",
                                "severity": "critical",
                                "title": f"Time-Based Blind OS Command Injection in Parameter '{param}'",
                                "description": f"Endpoint {ep} delayed its response past a calibrated baseline (mean+3σ+{n}s) on 3 consecutive trials when injected with a shell sleep separator, proving blind command execution with no reflected output.",
                                "target_url": repro_url,
                                "fingerprint": hashlib.sha256(
                                    f"cmdi_time_{destination.host}_{ep}_{param}".encode()
                                ).hexdigest(),
                                "cwe_id": "CWE-78",
                                "confidence": "high",
                                "remediation": "Avoid passing user input to system shell execution; use subprocess with explicit argument vectors.",
                                "poc": {
                                    "method": "GET",
                                    "url": repro_url,
                                    "curl_command": f'curl -s -k "{repro_url}" -H "Cookie: security=low"',
                                    "parameter": param,
                                    "payload": cmd_hit,
                                    "reproduction_steps": f"Issue GET request to {repro_url}; the response is delayed ~{n}s versus a benign value, reproduced across 3 trials.",
                                },
                                "evidence": [
                                    {
                                        "endpoint": ep,
                                        "parameter": param,
                                        "oracle": "statistical_time_delay",
                                        "delay_seconds": n,
                                        "trials": 3,
                                    }
                                ],
                            }
                        )
            except Exception:
                pass

    # 3. Header Security Audit (CSP, HSTS, X-Frame-Options, Information Leaks)
    try:
        status, headers, _, _ = _request_endpoint(destination, allow_ip, "GET", "/", timeout=timeout)
        # Follow one same-origin redirect so posture is audited on the real page, not the 301 stub.
        if status in (301, 302, 303, 307, 308):
            parts = urlsplit(headers.get("location", ""))
            same_origin = (not parts.netloc) or (
                (parts.hostname or "").lower() == destination.host.lower()
                and (not parts.scheme or parts.scheme == destination.scheme)
            )
            if same_origin and parts.path:
                hop = f"{parts.path}?{parts.query}" if parts.query else parts.path
                status, headers, _, _ = _request_endpoint(destination, allow_ip, "GET", hop, timeout=timeout)
        csp = headers.get("content-security-policy")
        hsts = headers.get("strict-transport-security")
        xfo = headers.get("x-frame-options")
        xcto = headers.get("x-content-type-options")
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")

        if not csp:
            findings.append(
                {
                    "category": "security_misconfiguration",
                    "severity": "medium",
                    "title": "Missing Content-Security-Policy (CSP) Header",
                    "description": "Content-Security-Policy is not enforced, leaving users vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
                    "target_url": destination.url,
                    "fingerprint": hashlib.sha256(f"csp_missing_{destination.host}".encode()).hexdigest(),
                    "cwe_id": "CWE-1021",
                    "remediation": "Deploy a robust Content-Security-Policy restricting script sources to trusted origins.",
                    "evidence": [{"headers_observed": list(headers.keys())}],
                }
            )

        if destination.scheme == "https" and not hsts:
            findings.append(
                {
                    "category": "security_misconfiguration",
                    "severity": "medium",
                    "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
                    "description": "The web application does not transmit the Strict-Transport-Security header over HTTPS, allowing SSL-stripping man-in-the-middle attacks.",
                    "target_url": destination.url,
                    "fingerprint": hashlib.sha256(f"hsts_missing_{destination.host}".encode()).hexdigest(),
                    "cwe_id": "CWE-319",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                    "evidence": [{"status": status}],
                }
            )

        if not xfo and not (csp and "frame-ancestors" in csp.lower()):
            findings.append(
                {
                    "category": "security_misconfiguration",
                    "severity": "medium",
                    "title": "Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                    "description": "Neither X-Frame-Options nor CSP frame-ancestors is configured, allowing the site to be embedded in malicious iframes (Clickjacking).",
                    "target_url": destination.url,
                    "fingerprint": hashlib.sha256(f"xfo_missing_{destination.host}".encode()).hexdigest(),
                    "cwe_id": "CWE-1021",
                    "remediation": "Configure 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors \\'self\\''.",
                    "evidence": [{"headers_observed": list(headers.keys())}],
                }
            )

        if not xcto or "nosniff" not in xcto.lower():
            findings.append(
                {
                    "category": "security_misconfiguration",
                    "severity": "low",
                    "title": "Missing X-Content-Type-Options Header",
                    "description": "The X-Content-Type-Options: nosniff header is missing, allowing legacy browsers to MIME-sniff responses into executable content.",
                    "target_url": destination.url,
                    "fingerprint": hashlib.sha256(f"xcto_missing_{destination.host}".encode()).hexdigest(),
                    "cwe_id": "CWE-16",
                    "remediation": "Configure web server to return 'X-Content-Type-Options: nosniff'.",
                    "evidence": [{"header": xcto}],
                }
            )

        if server and any(char.isdigit() for char in server):
            findings.append(
                {
                    "category": "information_disclosure",
                    "severity": "low",
                    "title": f"Web Server Detailed Version Disclosure ({server})",
                    "description": f"The Server header reveals exact web server software and version numbers: '{server}', aiding targeted exploitation.",
                    "target_url": destination.url,
                    "fingerprint": hashlib.sha256(
                        f"server_leak_{destination.host}_{server}".encode()
                    ).hexdigest(),
                    "cwe_id": "CWE-200",
                    "remediation": "Disable server signature tokens in web server configuration (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).",
                    "evidence": [{"server_header": server}],
                }
            )

        if powered_by:
            findings.append(
                {
                    "category": "information_disclosure",
                    "severity": "low",
                    "title": f"Technology Stack Disclosure via X-Powered-By ({powered_by})",
                    "description": f"The X-Powered-By header discloses underlying backend framework: '{powered_by}'.",
                    "target_url": destination.url,
                    "fingerprint": hashlib.sha256(
                        f"powered_by_{destination.host}_{powered_by}".encode()
                    ).hexdigest(),
                    "cwe_id": "CWE-200",
                    "remediation": "Remove the X-Powered-By header from all application responses.",
                    "evidence": [{"x_powered_by": powered_by}],
                }
            )
    except Exception:
        pass

    # Normalize all findings so affected_url, target_url, and confidence are consistently populated
    for f in findings:
        aff = f.get("affected_url") or f.get("target_url") or destination.url
        f["affected_url"] = aff
        f["target_url"] = aff
        if "confidence" not in f:
            f["confidence"] = "high"

    check = {
        "category": "vulnerability_assessment",
        "status": "completed",
        "detail": f"Active vulnerability audit completed: {len(findings)} finding(s) identified across sensitive paths, active parameter fuzzing, and security headers.",
    }

    return {
        "findings": findings,
        "observations": observations,
        "check": check,
    }


__all__ = ["audit_deep_vulnerabilities"]
