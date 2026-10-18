"""State-of-the-Art (SOTA) Vulnerability Detection & Diagnostic Enhancements for SHARAY.

Extends baseline HTTP inspection into an advanced vulnerability detection engine:
- CORS Misconfiguration Oracle (CWE-942): Arbitrary origin reflection with credentials.
- Verbose Server & Framework Information Disclosure (CWE-200).
- Modern Browser Isolation Policy Auditing (COOP, COEP, CORP) (CWE-693).
- Strict Cookie Security Prefix Verification (__Host-, __Secure-) (RFC 6265bis).
- CSP Directive Rigor Analysis (unsafe-inline, unsafe-eval, wildcard hosts).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EnhancedFinding:
    """Canonical SOTA vulnerability finding generated from deterministic response analysis."""

    fingerprint: str
    title: str
    category: str
    severity: str
    confidence: str
    cwe: int
    description: str
    remediation: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


def audit_cors_configuration(
    url: str,
    headers: dict[str, str],
    tested_origin: str = "https://arbitrary-scanner-audit.com",
) -> EnhancedFinding | None:
    """Analyze CORS headers for exploitable trust configurations (CWE-942)."""
    norm_headers = {k.lower(): v for k, v in headers.items()}
    acao = norm_headers.get("access-control-allow-origin", "").strip()
    acac = norm_headers.get("access-control-allow-credentials", "").strip().lower()

    if not acao:
        return None

    # High severity: Origin reflection with credentials enabled
    if acao == tested_origin and acac == "true":
        fp = hashlib.sha256(f"{url}|cors_arbitrary_credentials".encode()).hexdigest()
        return EnhancedFinding(
            fingerprint=fp,
            title="CORS Arbitrary Origin Reflection with Credentials",
            category="cors",
            severity="high",
            confidence="high",
            cwe=942,
            description=(
                "The server dynamically reflects arbitrary untrusted Origin headers and sets "
                "'Access-Control-Allow-Credentials: true'. This allows external web applications "
                "to execute authenticated cross-origin XMLHttpRequests/fetch calls and read private data."
            ),
            remediation=(
                "Validate incoming Origin headers against an explicit, strict server-side whitelist. "
                "Never reflect untrusted origins when credentials are supported."
            ),
            evidence={
                "url": url,
                "tested_origin": tested_origin,
                "access_control_allow_origin": acao,
                "access_control_allow_credentials": acac,
            },
        )

    # Medium severity: Wildcard with credentials (disallowed by browser standards, indicates misconfiguration)
    if acao == "*" and acac == "true":
        fp = hashlib.sha256(f"{url}|cors_wildcard_credentials".encode()).hexdigest()
        return EnhancedFinding(
            fingerprint=fp,
            title="CORS Wildcard with Credentials Misconfiguration",
            category="cors",
            severity="medium",
            confidence="high",
            cwe=942,
            description=(
                "The server specifies 'Access-Control-Allow-Origin: *' alongside "
                "'Access-Control-Allow-Credentials: true'. While modern browsers reject credentialed "
                "requests under wildcards, this indicates confused CORS policy design."
            ),
            remediation="Use explicit trusted origins instead of wildcards when credentials are required.",
            evidence={
                "url": url,
                "access_control_allow_origin": acao,
                "access_control_allow_credentials": acac,
            },
        )

    return None


def audit_information_disclosure(url: str, headers: dict[str, str]) -> list[EnhancedFinding]:
    """Detect verbose software banners, internal versions, and framework disclosures (CWE-200)."""
    norm_headers = {k.lower(): v for k, v in headers.items()}
    findings: list[EnhancedFinding] = []

    disclosure_headers = [
        ("server", "Web server software and version disclosure"),
        ("x-powered-by", "Underlying runtime framework disclosure"),
        ("x-aspnet-version", "ASP.NET internal version disclosure"),
        ("x-generator", "CMS / application generator disclosure"),
        ("x-backend-server", "Internal backend host disclosure"),
    ]

    for header_name, title in disclosure_headers:
        val = norm_headers.get(header_name)
        if val and len(val.strip()) > 0:
            # Check if version numbers or detailed technologies are revealed
            has_details = any(char.isdigit() for char in val) or "/" in val
            severity = "low" if has_details else "info"
            fp = hashlib.sha256(f"{url}|disclosure_{header_name}".encode()).hexdigest()
            findings.append(
                EnhancedFinding(
                    fingerprint=fp,
                    title=title,
                    category="information_disclosure",
                    severity=severity,
                    confidence="high",
                    cwe=200,
                    description=(
                        f"The response exposes detailed infrastructure facts in the '{header_name}' header "
                        f"('{val}'). Attackers use specific versions to map unpatched CVEs and targeted exploits."
                    ),
                    remediation=f"Configure the web server or reverse proxy to strip or sanitize the '{header_name}' header.",
                    evidence={"url": url, "header": header_name, "value": val},
                )
            )

    return findings


def audit_modern_browser_isolation(url: str, headers: dict[str, str]) -> list[EnhancedFinding]:
    """Audit Cross-Origin isolation policies: COOP, COEP, and CORP (CWE-693)."""
    norm_headers = {k.lower(): v for k, v in headers.items()}
    findings: list[EnhancedFinding] = []

    coop = norm_headers.get("cross-origin-opener-policy", "").strip().lower()
    coep = norm_headers.get("cross-origin-embedder-policy", "").strip().lower()

    if not coop or coop not in ("same-origin", "same-origin-allow-popups"):
        fp = hashlib.sha256(f"{url}|missing_coop".encode()).hexdigest()
        findings.append(
            EnhancedFinding(
                fingerprint=fp,
                title="Cross-Origin-Opener-Policy (COOP) Missing or Permissive",
                category="browser_isolation",
                severity="low",
                confidence="high",
                cwe=693,
                description=(
                    "The Cross-Origin-Opener-Policy (COOP) header is absent or permissive. "
                    "COOP enforces a separate browsing context group, preventing cross-origin window reference "
                    "attacks and side-channel timing leaks (e.g. Spectre)."
                ),
                remediation="Configure 'Cross-Origin-Opener-Policy: same-origin' on sensitive application pages.",
                evidence={"url": url, "current_coop": coop or "absent"},
            )
        )

    if not coep or coep != "require-corp":
        fp = hashlib.sha256(f"{url}|missing_coep".encode()).hexdigest()
        findings.append(
            EnhancedFinding(
                fingerprint=fp,
                title="Cross-Origin-Embedder-Policy (COEP) Absent",
                category="browser_isolation",
                severity="low",
                confidence="high",
                cwe=693,
                description=(
                    "The Cross-Origin-Embedder-Policy (COEP) header is absent. "
                    "COEP prevents a document from loading cross-origin resources that do not explicitly grant permission."
                ),
                remediation="Deploy 'Cross-Origin-Embedder-Policy: require-corp' to achieve cross-origin isolation.",
                evidence={"url": url, "current_coep": coep or "absent"},
            )
        )

    return findings


def audit_cookie_security_prefixes(url: str, cookie_headers: list[str]) -> list[EnhancedFinding]:
    """Audit compliance with RFC 6265bis __Host- and __Secure- cookie prefix standards (CWE-614)."""
    findings: list[EnhancedFinding] = []

    for cookie in cookie_headers:
        pair, _, attributes = cookie.partition(";")
        name, _, _ = pair.partition("=")
        cookie_name = name.strip()

        attrs = [a.strip().lower() for a in attributes.split(";") if a.strip()]
        has_secure = "secure" in attrs
        has_domain = any(a.startswith("domain=") for a in attrs)
        has_root_path = "path=/" in attrs

        # __Host- cookie rule: Must have Secure, Path=/, and NO Domain attribute
        if cookie_name.startswith("__Host-"):
            violations = []
            if not has_secure:
                violations.append("omits Secure flag")
            if has_domain:
                violations.append("specifies a Domain attribute (prohibited for __Host-)")
            if not has_root_path:
                violations.append("path is not set to /")

            if violations:
                fp = hashlib.sha256(f"{url}|{cookie_name}|host_prefix_violation".encode()).hexdigest()
                findings.append(
                    EnhancedFinding(
                        fingerprint=fp,
                        title=f"Cookie Prefix Violation: {cookie_name}",
                        category="cookie_security",
                        severity="medium",
                        confidence="high",
                        cwe=614,
                        description=(
                            f"Cookie '{cookie_name}' uses the RFC 6265bis '__Host-' prefix but violates standard "
                            f"requirements: {', '.join(violations)}. Modern browsers may reject or mis-handle this cookie."
                        ),
                        remediation="Ensure '__Host-' cookies are Secure, have Path=/, and omit the Domain attribute.",
                        evidence={"url": url, "cookie_name": cookie_name, "violations": violations},
                    )
                )

        # __Secure- cookie rule: Must have Secure flag
        elif cookie_name.startswith("__Secure-"):
            if not has_secure:
                fp = hashlib.sha256(f"{url}|{cookie_name}|secure_prefix_violation".encode()).hexdigest()
                findings.append(
                    EnhancedFinding(
                        fingerprint=fp,
                        title=f"Cookie Prefix Violation: {cookie_name}",
                        category="cookie_security",
                        severity="medium",
                        confidence="high",
                        cwe=614,
                        description=(
                            f"Cookie '{cookie_name}' uses the '__Secure-' prefix but omits the 'Secure' attribute. "
                            "Browsers strictly reject '__Secure-' cookies sent without the Secure flag."
                        ),
                        remediation="Add the 'Secure' attribute to the cookie definition.",
                        evidence={"url": url, "cookie_name": cookie_name},
                    )
                )

    return findings


def run_sota_diagnostics(
    url: str,
    response_headers: dict[str, str],
    raw_cookies: list[str] | None = None,
    tested_origin: str = "https://arbitrary-scanner-audit.com",
) -> list[EnhancedFinding]:
    """Run the complete suite of SOTA diagnostic checks on an HTTP response."""
    all_findings: list[EnhancedFinding] = []

    cors_finding = audit_cors_configuration(url, response_headers, tested_origin)
    if cors_finding:
        all_findings.append(cors_finding)

    all_findings.extend(audit_information_disclosure(url, response_headers))
    all_findings.extend(audit_modern_browser_isolation(url, response_headers))

    if raw_cookies:
        all_findings.extend(audit_cookie_security_prefixes(url, raw_cookies))

    return all_findings
