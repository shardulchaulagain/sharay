# SHARAY Scanner Adapter & Detection Pack Plugin SDK

**Version:** 2.0.0  
**Target:** Plugin Authors, Security Tool Developers, Integration Engineers

---

## 1. Overview & Architecture

SHARAY features a modular, pluggable engine for incorporating specialized security scanners, fuzzers, and detection engines. All scanner adapters must derive from the `BaseScannerAdapter` specification defined in `aegis.onboarding` (or `packages.scanner_adapters`).

```
+-----------------------------------------------------------+
|                   SHARAY Execution Core                   |
+-----------------------------------------------------------+
                              |
       +----------------------+----------------------+
       |                      |                      |
       v                      v                      v
+--------------+      +---------------+      +---------------+
| Core Crawler |      | Built-in DAST |      | Custom Plugin |
| (Auth, Forms)|      |  (SQLi, XSS)  |      | (BaseScanner) |
+--------------+      +---------------+      +---------------+
       |                      |                      |
       +----------------------+----------------------+
                              |
                              v
                 Egress Policy Firewall Guard
                              |
                              v
                     Target Host Socket
```

---

## 2. BaseScannerAdapter Specification

All plugins must implement the following abstract interface:

```python
from typing import Any, Dict, List
from aegis.onboarding import BaseScannerAdapter


class CustomSecurityScanner(BaseScannerAdapter):
    """Custom security scanner plugin for detecting specialized vulnerabilities."""

    def name(self) -> str:
        """Returns the unique identifier for the scanner plugin."""
        return "custom_security_scanner_v1"

    def supported_vuln_classes(self) -> List[str]:
        """Returns a list of CWE / vulnerability categories evaluated by this plugin."""
        return [
            "CWE-16: Configuration",
            "CWE-693: Protection Mechanism Failure",
        ]

    def run_check(
        self,
        target_origin: str,
        endpoint: str,
        parameters: List[str],
    ) -> List[Dict[str, Any]]:
        """Executes targeted checks against the authorized target endpoint.
        
        Args:
            target_origin: Base origin URL (e.g., 'https://target.corp')
            endpoint: Target relative URI (e.g., '/api/v1/user')
            parameters: Discovered query or body parameters
            
        Returns:
            List of findings conforming to the SHARAY Finding schema:
            {
                "title": str,
                "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
                "cwe": str,
                "target_url": str,
                "evidence": { ... },
                "remediation": str
            }
        """
        ...
```

---

## 3. Mandatory Security & Correctness Constraints

Every custom scanner adapter must strictly comply with the following architectural invariants:

1. **Strict Target Scope Adherence:** Plugins must never construct requests to third-party CDNs, external analytics, or out-of-scope hostnames. All socket calls must traverse the internal scoped proxy or `resolve_pinned` connection harness.
2. **Deterministic Evidence Requirement:** Pure statistical or generic HTTP 200 checks are strictly rejected. Findings must attach raw request/response transcripts or verifiable canary markers.
3. **Safe Parameterized Testing:** Destructive verbs (`DROP`, `DELETE`, `TRUNCATE`, `rm -rf`) are barred. Use non-destructive arithmetic evaluation or time-delay oracles with statistical bounds ($p < 0.01$).
4. **Clean Error Handling:** Network timeouts, connection resets, and TLS handshake failures must be caught gracefully and recorded as observations rather than unhandled exceptions.

---

## 4. Reference Implementation: Security Headers Plugin

Here is a complete, production-ready reference scanner plugin:

```python
import urllib.request
from typing import Any, Dict, List
from aegis.onboarding import BaseScannerAdapter


class StrictSecurityHeadersAdapter(BaseScannerAdapter):
    """Evaluates HTTP response headers for missing enterprise security controls."""

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": "HSTS must be enforced with max-age >= 31536000 and includeSubDomains.",
        "Content-Security-Policy": "A restrictive CSP header prevents cross-site scripting and unauthorized script execution.",
        "X-Content-Type-Options": "X-Content-Type-Options must be set to 'nosniff' to mitigate MIME confusion attacks.",
        "X-Frame-Options": "X-Frame-Options must be DENY or SAMEORIGIN to prevent clickjacking.",
    }

    def name(self) -> str:
        return "strict_security_headers_adapter"

    def supported_vuln_classes(self) -> List[str]:
        return ["CWE-16", "CWE-693", "CWE-1021"]

    def run_check(self, target_origin: str, endpoint: str, parameters: List[str]) -> List[Dict[str, Any]]:
        url = f"{target_origin.rstrip('/')}/{endpoint.lstrip('/')}"
        findings: List[Dict[str, Any]] = []

        req = urllib.request.Request(url, headers={"User-Agent": "SHARAY-Security-Auditor/2.0"})
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                headers = {k.title(): v for k, v in resp.headers.items()}
                for h_name, guidance in self.REQUIRED_HEADERS.items():
                    if h_name not in headers:
                        findings.append({
                            "title": f"Missing Hardening Header: {h_name}",
                            "severity": "LOW" if h_name != "Content-Security-Policy" else "MEDIUM",
                            "cwe": "CWE-693",
                            "target_url": url,
                            "evidence": {"checked_header": h_name, "received_headers": list(headers.keys())},
                            "remediation": guidance,
                        })
        except Exception:
            pass

        return findings
```
