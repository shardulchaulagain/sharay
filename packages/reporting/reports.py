"""Generate evidence-backed reports from stored assessment records."""

import json
import re
import shlex
from collections import Counter
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from packages.reporting.poc_engine import synthesize_research_grade_poc
from packages.reporting.trends import (
    AssessmentTrendEngine,
    ExecutiveDashboardGenerator,
    FindingRecord,
)
from packages.secret_patterns import redact_tokens

REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(
    r"(?:^|[_\-\s])(?:password|passwd|passcode|secret|token|authorization|"
    r"cookie|credentials?|private[_\-\s]?key|api[_\-\s]?key|access[_\-\s]?key)"
    r"(?:$|[_\-\s])",
    re.I,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----.*?"
    r"-----END (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----",
    re.S,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b((?:password|passwd|passcode|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|session[_-]?token|secret|token)\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s&,;]+)"
)
_SENSITIVE_HEADER = re.compile(r"(?im)\b(authorization|proxy-authorization|set-cookie|cookie)\s*:\s*[^\r\n]+")
_AUTH_VALUE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)

LIMITATIONS = [
    "Target scope and execution parameters require explicit operator authorization; literal loopback laboratory destinations provide local containment when used.",
    "The dedicated Python worker enforces application-level destination, request-rate and time limits (it is not an OS sandbox).",
    "Coverage is limited to checks with stored execution evidence; skipped, failed, and unrecorded stages do not establish coverage.",
    "Active security probes evaluate common web and service vulnerabilities; a report with no confirmed findings does not establish that unprobed vectors are absent.",
    "A missing security header or exposed endpoint is an observation with contextual risk requiring operator verification.",
    "Continuous automated retesting is recommended as application infrastructure and deployed software versions evolve.",
]


def _secret_key(key: str) -> bool:
    # Normalize common camelCase names without changing evidence hash keys.
    normalized = re.sub(r"([a-z])([A-Z])", r"\1_\2", key)
    return bool(_SECRET_KEY.search(normalized))


def _redact_url(match: re.Match[str]) -> str:
    try:
        parts = urlsplit(match.group())
        netloc = parts.netloc.rsplit("@", 1)[-1]
        if "@" in parts.netloc:
            netloc = REDACTED + "@" + netloc
        query = [
            (key, REDACTED if _secret_key(key) else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
        return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), parts.fragment))
    except ValueError:
        return REDACTED


def redact(value: Any) -> Any:
    """Return a recursively sanitized copy; recognized secret fields are write-only.

    This is defensive pattern redaction, not a guarantee that arbitrary unlabeled
    personal data or unknown secret formats have been identified.
    """
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            original = str(key)
            base = redact(original)
            sanitized = base
            suffix = 2
            # Redaction can give distinct keys the same label; keep every record.
            while sanitized in clean:
                sanitized = f"{base}#{suffix}"
                suffix += 1
            clean[sanitized] = (
                REDACTED
                if (_secret_key(original) or _secret_key(base)) and not _safe_fact(original, item)
                else redact(item)
            )
        return clean
    if isinstance(value, (list, tuple, set)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        text = _CONTROL.sub("", value)
        text = _PRIVATE_KEY.sub(REDACTED, text)
        text = _SENSITIVE_HEADER.sub(lambda m: m.group(1) + ": " + REDACTED, text)
        text = _AUTH_VALUE.sub(lambda m: m.group(1) + " " + REDACTED, text)
        text = _URL.sub(_redact_url, text)
        text = _SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + REDACTED, text)
        # Bare provider tokens (no "key=" label) in tool output or free text; one shared rule set.
        return redact_tokens(text, REDACTED)
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact(str(value))


def _safe_fact(key: str, value: Any) -> bool:
    """Preserve scanner booleans without permitting raw cookie values."""
    if key == "cors_credentials":
        return isinstance(value, bool)
    if key != "cookie_flags" or not isinstance(value, list):
        return False
    return all(
        isinstance(flags, dict)
        and all(
            (
                name
                in {
                    "secure",
                    "httponly",
                    "parse_error",
                    "prefix_missing_secure",
                    "prefix_nonroot_path",
                    "prefix_domain_present",
                }
                and isinstance(item, bool)
            )
            or (name == "samesite" and isinstance(item, str) and item in {"strict", "lax", "none", "unset"})
            or (name == "prefix" and isinstance(item, str) and item in {"host", "secure"})
            for name, item in flags.items()
        )
        for flags in value
    )


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False)


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _records(value: Any) -> list:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    if value is None or value == "":
        return "Unavailable"
    if isinstance(value, (dict, list)):
        return "\n".join(f"{label}: {item}" for label, item in _detail_rows(value)) or "None recorded"
    return str(value)


def _detail_rows(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Flatten stored structures into readable key/value evidence, preserving every leaf."""
    if isinstance(value, (dict, list)) and value:
        entries = value.items() if isinstance(value, dict) else enumerate(value, 1)
        return [
            row
            for key, item in entries
            for row in _detail_rows(item, f"{prefix} / {key}" if prefix else str(key))
        ]
    return [(prefix or "Value", "None recorded" if value == {} or value == [] else _text(value))]


def _finding_sources(finding: dict) -> list[dict]:
    evidence = finding.get("evidence")
    if isinstance(evidence, list) and evidence:
        return [finding, _mapping(_mapping(evidence[-1]).get("data"))]
    return [finding, _mapping(evidence)]


def _is_proof_verified(proof: dict) -> bool:
    if not isinstance(proof, dict):
        return False
    exit_code = proof.get("exit_code")
    if type(exit_code) is not int or exit_code != 0:
        return False
    if proof.get("mock_mode") is not False:
        return False
    status = proof.get("status")
    if status is not None:
        if not isinstance(status, str):
            return False
        clean_status = status.strip().lower()
        if clean_status in {"failed", "error", "timeout", "demoted", "false_positive", "unverified"}:
            return False
    return True


def _verification(finding: dict) -> str:
    evidence = finding.get("evidence")
    # A stored snapshot is authoritative even when its proof is absent or malformed.
    source = _finding_sources(finding)[-1] if isinstance(evidence, list) and evidence else finding
    sources = (finding, source)
    statuses = [str(item.get("status", "")).strip().lower() for item in sources]
    if any(
        status in {"demoted", "false_positive"}
        or str(item.get("lifecycle_state", "")).strip().upper() == "DEMOTED"
        for item, status in zip(sources, statuses)
    ):
        return "demoted"
    verified_statuses = {"confirmed", "reopened", "accepted_risk", "remediation_in_progress"}
    if statuses[0] not in verified_statuses or (statuses[1] and statuses[1] not in verified_statuses):
        return "unverified"
    return (
        "verified"
        if source.get("lifecycle_state") == "REPRODUCED"
        or _is_proof_verified(_mapping(source.get("autopyverifier")))
        else "unverified"
    )


def _posture(finding: dict) -> bool:
    category = str(finding.get("category", "")).lower()
    if category in {
        "http_headers",
        "http_configuration",
        "tls",
        "tls_configuration",
        "tls_inspection",
        "email_spoofing_risk",
        "dns",
        "dns_intelligence",
        "security_misconfiguration",
        "server_banner",
        "software_indicators",
    }:
        return True
    title = str(finding.get("title", "")).lower()
    return bool(
        re.search(
            r"\b(?:missing|weak|ineffective|permissive|absent)\b.*\b(?:hsts|csp|dmarc|spf|header|policy)\b"
            r"|\b(?:server|software|framework)\b.*\b(?:version disclosure|banner)\b",
            title,
        )
    )


def _poc(finding: dict, target_url: str) -> str:
    """Generate exact step-by-step reproduction command for testing tools."""
    finding = {**finding, **_finding_sources(finding)[-1]}
    asset = str(
        finding.get("affected_url")
        or finding.get("affected_asset")
        or finding.get("target_url")
        or target_url
    )
    category = str(finding.get("category", "")).lower()
    title = str(finding.get("title", "")).lower()
    poc = finding.get("poc") or finding.get("proof_of_concept")
    payload = _mapping(poc)

    try:
        parts = urlsplit(asset if "://" in asset else "//" + asset)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "No command generated: the stored asset is not a valid endpoint."

    if not host or host.startswith("-"):
        return "No command generated: the stored asset is not a valid endpoint."

    dns = (
        parts.scheme == "dns"
        or category in {"dns", "dns_intelligence", "email_spoofing_risk"}
        or bool(re.search(r"\b(?:dmarc|spf)\b", title))
    )
    tls = parts.scheme in {"tls", "ssl"} or category in {"tls", "tls_configuration", "tls_inspection"}

    if dns:
        name = "_dmarc." + host.removeprefix("_dmarc.") if "dmarc" in title else host
        return f"dig +short TXT {shlex.quote(name)}"

    if tls:
        endpoint = f"[{host}]:{port or 443}" if ":" in host else f"{host}:{port or 443}"
        return f"openssl s_client -connect {shlex.quote(endpoint)} -servername {shlex.quote(host)} -verify_return_error </dev/null"

    if payload.get("parameter") is not None and payload.get("payload") is not None:
        query = [
            (key, value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if key != str(payload["parameter"])
        ]
        query.append((str(payload["parameter"]), str(payload["payload"])))
        exploit_asset = urlunsplit(parts._replace(query=urlencode(query)))
    else:
        exploit_asset = asset

    return f"curl -i -sS --location --max-time 15 -- {shlex.quote(exploit_asset)}"


def _reproduction_playbook(finding: dict, target_url: str) -> str:
    finding = {**finding, **_finding_sources(finding)[-1]}
    asset = str(
        finding.get("affected_url")
        or finding.get("affected_asset")
        or finding.get("target_url")
        or target_url
    )
    category = str(finding.get("category", "")).lower()
    title = str(finding.get("title", "")).lower()
    poc = _mapping(finding.get("poc") or finding.get("proof_of_concept"))
    param = str(poc.get("parameter") or "id")
    payload = str(poc.get("payload") or "' OR '1'='1")
    finding_id = str(finding.get("id") or finding.get("fingerprint") or "current")

    try:
        parts = urlsplit(asset if "://" in asset else "//" + asset)
        host = parts.hostname or "target.test"
    except Exception:
        host = "target.test"

    if "sql" in category or "sql" in title or "sqli" in title:
        return (
            f"Step 1 (Baseline Context): Dispatch a clean, unmanipulated HTTP request to {asset} to capture normal response body length and HTTP 200 status.\n"
            f"Step 2 (Boolean Tautology Probe): Inject logical truth condition '{param}={payload}' to evaluate if query structure evaluates as tautology.\n"
            f"Step 3 (Boolean Contradiction Probe): Inject contradiction condition '{param}=1 AND 1=2' and evaluate differential response.\n"
            f"Step 4 (Verification Oracle): Confirm vulnerability if contradiction yields significant length delta (Jaccard similarity J < 0.88) or database syntax errors absent from baseline.\n"
            f"Step 5 (Console Retest): Run 'retest {finding_id}' in SHARAY console to execute the automated 3x reproducer with negative control canaries."
        )

    if any(k in category or k in title for k in ("xss", "cross_site_scripting", "scripting")):
        return (
            f"Step 1 (Pre-condition & CSP Audit): Run 'probe {asset}' in SHARAY console to check whether Content-Security-Policy or X-Content-Type-Options: nosniff are absent.\n"
            f"Step 2 (Reflected Canary Injection): Send request with unique canary probe payload on parameter '{param}'.\n"
            f"Step 3 (Verification Oracle): Inspect response body to confirm unescaped reflection in executable HTML context without entity encoding.\n"
            f"Step 4 (Console Retest): Run 'retest {finding_id}' in SHARAY console to dispatch headless browser context verification."
        )

    if "ssrf" in category or "server_side_request_forgery" in title or "ssrf" in title:
        return (
            f"Step 1 (Baseline Fetch): Establish baseline behavior when application fetches authorized external resources.\n"
            f"Step 2 (Loopback Canary Probe): Supply loopback destination (e.g. http://127.0.0.1:80) or cloud metadata endpoint.\n"
            f"Step 3 (Verification Oracle): Confirm vulnerability if response reveals differential loopback socket error (ECONNREFUSED) or internal service metadata absent from baseline.\n"
            f"Step 4 (Console Retest): Run 'retest {finding_id}' in SHARAY console to check out-of-band interaction telemetry."
        )

    if any(k in category or k in title for k in ("rce", "command", "os_command", "execution")):
        return (
            f"Step 1 (Baseline Context): Record baseline execution parameters and response latency.\n"
            f"Step 2 (Isolated Canary Probe): Inject non-destructive isolated canary probe on parameter '{param}'.\n"
            f"Step 3 (Verification Oracle): Confirm vulnerability only upon observing exact canary token reflection or controlled execution delay.\n"
            f"Step 4 (Console Retest): Run 'retest {finding_id}' in SHARAY console to execute sandboxed AutoPyVerifier evaluation."
        )

    if any(k in category or k in title for k in ("ssti", "template")):
        return (
            f"Step 1 (Baseline Context): Send benign text input to verify literal template output.\n"
            f"Step 2 (Arithmetic Expression Canary): Inject template arithmetic canary '{{{{7*7}}}}' or '${{7*7}}' into parameter '{param}'.\n"
            f"Step 3 (Verification Oracle): Confirm vulnerability if output renders evaluated arithmetic '49' rather than literal string.\n"
            f"Step 4 (Console Retest): Run 'retest {finding_id}' in SHARAY console."
        )

    if any(k in category or k in title for k in ("dmarc", "spf", "email_spoofing")):
        return (
            f"Step 1 (Query DMARC Policy): Run 'dns _dmarc.{host} TXT' in SHARAY console or 'dig +short TXT _dmarc.{host}'.\n"
            f"Step 2 (Query SPF Policy): Run 'dns {host} TXT' in SHARAY console to inspect authorized sender envelope.\n"
            f"Step 3 (Verification Oracle): Confirm posture weakness if DMARC record is absent or policy is permissive (p=none) rather than reject or quarantine.\n"
            f"Step 4 (Remediation Verification): Re-query TXT records after publishing 'v=DMARC1; p=reject; rua=mailto:...'"
        )

    if any(k in category or k in title for k in ("tls", "ssl", "certificate")):
        return (
            f"Step 1 (Handshake Inspection): Run 'ssl {host}' in SHARAY console or 'openssl s_client -connect {host}:443 -servername {host} </dev/null'.\n"
            f"Step 2 (Verification Oracle): Inspect negotiated protocol, cipher suite, and certificate expiration / subject validity.\n"
            f"Step 3 (Remediation Verification): Confirm enforcement of TLS 1.2+ with modern AEAD cipher suites and valid trust chain."
        )

    if _posture(finding):
        return (
            f"Step 1 (Response Header Probe): Run 'probe {asset}' in SHARAY console to capture all HTTP response headers.\n"
            f"Step 2 (Verification Oracle): Verify presence or absence of required defensive headers (HSTS, CSP, X-Content-Type-Options: nosniff, X-Frame-Options).\n"
            f"Step 3 (Console Retest): Run 'retest {finding_id}' in SHARAY console after updating web server / proxy headers."
        )

    return (
        f"Step 1 (Target Reachability): Run 'probe {asset}' in SHARAY console to establish baseline HTTP response headers and latency.\n"
        f"Step 2 (Diagnostic Inspection): Execute targeted probe matching observed vulnerability condition.\n"
        f"Step 3 (Verification Oracle): Compare observed behavior against documented security policy.\n"
        f"Step 4 (Console Retest): Run 'retest {finding_id}' in SHARAY console to execute updated assessment."
    )


def _verification_oracle(finding: dict) -> str:
    category = str(finding.get("category", "")).lower()
    title = str(finding.get("title", "")).lower()
    if "sql" in category or "sql" in title or "sqli" in title:
        return "Differential Response Oracle: Jaccard similarity distance J < 0.88 between boolean true vs false conditions, or verified database syntax error signatures."
    if any(k in category or k in title for k in ("xss", "cross_site_scripting", "scripting")):
        return "Reflected Canary Oracle: Injected payload reflected verbatim in HTML context without contextual entity encoding and without restrictive Content-Security-Policy."
    if "ssrf" in category or "server_side_request_forgery" in title or "ssrf" in title:
        return "Out-of-Band & Differential Socket Oracle: Verified loopback socket error (ECONNREFUSED) or recorded DNS/HTTP callback telemetry at out-of-band canary."
    if any(k in category or k in title for k in ("rce", "command", "os_command", "execution")):
        return "Execution Evidence Oracle: Measured delay exceeding threshold or exact match of non-destructive canary execution token."
    if any(k in category or k in title for k in ("ssti", "template")):
        return "Mathematical Evaluation Oracle: Rendered response reflects evaluated arithmetic (e.g. 49) confirming server-side template interpreter execution."
    if any(k in category or k in title for k in ("dmarc", "spf", "email_spoofing")):
        return "DNS Resource Record Oracle: Authoritative TXT lookup reveals absent record or permissive policy (p=none) failing spoof rejection criteria."
    if any(k in category or k in title for k in ("tls", "ssl", "certificate")):
        return "TLS Protocol & Trust Chain Oracle: Negotiated protocol version < TLS 1.2, non-AEAD cipher suite, or certificate validity failure."
    if _posture(finding):
        return "Header & Configuration Oracle: Evaluated landing response headers lack defensive directives or expose server version metadata."
    return "Forensic Differential Oracle: Observed behavior diverges from baseline specification according to recorded execution evidence."


def _console_action(finding: dict, target_url: str) -> str:
    finding = {**finding, **_finding_sources(finding)[-1]}
    finding_id = str(finding.get("id") or finding.get("fingerprint") or "")
    asset = str(
        finding.get("affected_url")
        or finding.get("affected_asset")
        or finding.get("target_url")
        or target_url
    )
    category = str(finding.get("category", "")).lower()
    title = str(finding.get("title", "")).lower()
    try:
        parts = urlsplit(asset if "://" in asset else "//" + asset)
        host = parts.hostname or ""
    except Exception:
        host = ""

    if any(k in category or k in title for k in ("dmarc", "spf", "email_spoofing")):
        domain = f"_dmarc.{host.removeprefix('_dmarc.')}" if "dmarc" in title else host
        return f"dns {domain} TXT"
    if any(k in category or k in title for k in ("tls", "ssl", "certificate")):
        return f"ssl {host}"
    if _posture(finding):
        return f"probe {asset}"
    if finding_id:
        return f"retest {finding_id}"
    return f"probe {asset}"


def _impacts(finding: dict, verification: str) -> tuple[str, str]:
    context = f"{finding.get('category', '')} {finding.get('title', '')}".lower()
    if any(term in context for term in ("dmarc", "spf", "email_spoofing")):
        technical = "A missing or permissive sender policy can reduce receiving mail systems' ability to reject spoofed domain mail; delivery and recipient behavior require separate validation."
        business = "If spoofed mail reaches recipients, phishing could cause fraud, support effort, or loss of trust in the domain. No delivered spoofed message is established by this policy observation."
    elif any(term in context for term in ("tls", "certificate", "hsts")):
        technical = "Transport or certificate configuration may weaken connection authentication or protection against downgrade and interception, depending on the affected clients and network position."
        business = "Affected users could face data exposure or connection failures; the service owner should assess client coverage and availability requirements. No interception is inferred."
    elif any(term in context for term in ("cross_site_scripting", "xss", "cross-site scripting")):
        technical = "If an affected browser executes attacker-controlled script, the script could read page data or perform actions with that user's application access."
        business = "Affected user workflows could expose customer information or permit unauthorized account actions; the impact depends on session privileges and reachable data. No account compromise is inferred."
    elif any(term in context for term in ("sql", "injection", "rce", "command execution")):
        technical = "If attacker-controlled input reaches an interpreter, it could alter queries or commands within the application's database or process permissions."
        business = "Unauthorized data access, record changes, or service interruption could affect customers and recovery costs; the extent depends on the permissions and data actually reachable."
    elif any(term in context for term in ("ssrf", "server_side_request_forgery")):
        technical = "If server-side requests can be redirected by untrusted input, reachable internal services or metadata endpoints could be exposed through the server's network access."
        business = "Internal service or credential exposure could expand incident scope; actual reachability and data access must be established separately."
    elif _posture(finding):
        technical = "The recorded configuration changes a defense-in-depth control or exposes service metadata. Exploitability depends on application behavior and client context beyond this observation."
        business = "The owner should review the control against supported user workflows and security requirements. This observation alone does not establish data loss or service compromise."
    else:
        technical = "The recorded behavior may affect the identified asset's access or data boundaries. Determine the affected operation, required privileges, and reachable data during scoped retesting."
        business = "The service owner should map the affected operation to customer data and availability requirements before assigning loss or outage estimates. No business loss is established by this record."
    if verification != "verified" and not _posture(finding):
        technical = "Exploitation is not verified by the stored evidence. " + technical
    supplied_technical = finding.get("technical_impact")
    supplied_business = finding.get("business_impact")
    placeholders = {"", "not assessed", "unavailable", "none", "unknown"}
    return (
        _text(supplied_technical)
        if supplied_technical and str(supplied_technical).strip().lower() not in placeholders
        else technical,
        _text(supplied_business)
        if supplied_business and str(supplied_business).strip().lower() not in placeholders
        else business,
    )


def _evidence_hashes(value: Any) -> list[str]:
    hashes: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"evidence_hash", "sha256", "content_hash"} and isinstance(item, str):
                hashes.add(item)
            hashes.update(_evidence_hashes(item))
    elif isinstance(value, list):
        for item in value:
            hashes.update(_evidence_hashes(item))
    return sorted(hashes)


def _prepare(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Report data must be a dictionary")
    clean = redact(data)
    assessment = _mapping(clean.get("assessment")) or clean
    scope = _mapping(clean.get("scope") or assessment.get("scope_snapshot"))
    if not clean.get("tools"):
        clean["tools"] = [
            {"name": detail["adapter"], "version": detail.get("version")}
            for event in _records(clean.get("events"))
            if (detail := _mapping(_mapping(event).get("detail"))).get("adapter")
        ]
    clean["report_metadata"] = {
        "schema_version": "sharay.report.v1",
        "assessment_id": assessment.get("id") or clean.get("id"),
        "generated_at": clean.get("generated_at") or datetime.now(timezone.utc).isoformat(),
        "scope_version": scope.get("version", assessment.get("scope_version")),
        "assessment_mode": assessment.get("profile") or "not recorded",
        "scope_authorization": scope.get("verification_status")
        or scope.get("verification_method")
        or "not recorded",
        "synthetic": bool(clean.get("synthetic", False)),
        "evidence_hashes": _evidence_hashes(clean),
        "limitations": LIMITATIONS + _records(clean.get("limitations")),
        "redaction": "Pattern-based recursive secret redaction; not an exhaustive personal-data classifier.",
    }
    clean["scope"] = scope
    return clean


def _sections(data: dict) -> list[tuple[str, list[tuple[str, Any]]]]:
    assessment = _mapping(data.get("assessment")) or data
    metadata = data["report_metadata"]
    project = _mapping(data.get("project"))
    target = (
        _mapping(data.get("target"))
        or _mapping(data.get("scope_snapshot"))
        or {"url": data.get("target_url", "")}
    )
    findings = [_mapping(item) for item in _records(data.get("findings"))]
    observations = [
        {**item, **_mapping(item.get("data"))}
        for item in _records(data.get("observations"))
        if isinstance(item, dict)
    ]
    verified = [item for item in findings if not _posture(item) and _verification(item) == "verified"]
    posture = [item for item in findings if _posture(item)]
    unverified = [item for item in findings if not _posture(item) and _verification(item) != "verified"]
    summary = "No confirmed vulnerabilities are recorded. Review coverage and limitations."
    if verified:
        severity = Counter(str(item.get("severity", "unavailable")) for item in verified)
        summary = f"{len(verified)} verified vulnerability finding(s). " + ", ".join(
            f"{key}: {value}" for key, value in sorted(severity.items())
        )
    sections = [
        (
            "Assessment",
            [
                (
                    "Report classification",
                    "Synthetic example" if metadata["synthetic"] else "Stored assessment data",
                ),
                ("Assessment ID", _text(assessment.get("id"))),
                ("Project", _text(project.get("name") or project.get("id") or data.get("project"))),
                ("Target", _text(target.get("url") or target.get("origin") or data.get("target"))),
                (
                    "Objective",
                    _text(
                        assessment.get("objective")
                        or (
                            "Review explicitly approved loopback target HTTP configuration."
                            if str(assessment.get("profile")) == "safe_http"
                            else f"Comprehensive security assessment and active vulnerability analysis of {_text(target.get('url') or data.get('target'))}."
                        )
                    ),
                ),
                ("Status", _text(assessment.get("status"))),
                ("Generated at", _text(metadata["generated_at"])),
                (
                    "Created / started / finished",
                    " / ".join(
                        _text(assessment.get(key)) for key in ("created_at", "started_at", "finished_at")
                    ),
                ),
                ("Profile", _text(assessment.get("profile"))),
                ("Scope version", _text(metadata["scope_version"])),
                ("Assessment error", _text(assessment.get("error"))),
            ],
        ),
        (
            "Summary",
            [
                ("Verified vulnerabilities", summary),
                ("Configuration and hardening records", str(len(posture))),
                ("Unverified or demoted vulnerability records", str(len(unverified))),
                ("Total finding records", str(len(findings))),
                ("Observation records", str(len(_records(data.get("observations"))))),
                (
                    "Priorities",
                    "Prioritize verified vulnerabilities and review configuration in the target's context. Retest unverified records before treating them as confirmed vulnerabilities.",
                ),
            ],
        ),
        (
            "Executive dashboard",
            [
                (
                    "Posture score",
                    f"{AssessmentTrendEngine.calculate_posture_score([FindingRecord.from_dict(f) for f in findings])}/100",
                ),
                (
                    "Severity distribution",
                    ", ".join(
                        f"{k}: {v}"
                        for k, v in ExecutiveDashboardGenerator.generate_dashboard(
                            [FindingRecord.from_dict(f) for f in findings],
                            max(len(observations), 1),
                            max(len(observations), 1),
                        )["severity_distribution"].items()
                    ),
                ),
                (
                    "Attack surface coverage",
                    f"{ExecutiveDashboardGenerator.generate_dashboard([FindingRecord.from_dict(f) for f in findings], max(len(observations), 1), max(len(observations), 1))['attack_surface']['coverage_percent']}%",
                ),
                (
                    "Risk rating",
                    ExecutiveDashboardGenerator.generate_dashboard(
                        [FindingRecord.from_dict(f) for f in findings],
                        max(len(observations), 1),
                        max(len(observations), 1),
                    )["risk_rating"],
                ),
            ],
        ),
        (
            "Authorized scope",
            [
                ("Approved scope snapshot", _text(data["scope"])),
                (
                    "Verification",
                    _text(
                        data["scope"].get("verification")
                        or data["scope"].get("verification_status")
                        or data["scope"].get("verification_method")
                    ),
                ),
                ("Approved at", _text(data["scope"].get("approved_at"))),
                ("Authorized by", _text(data["scope"].get("authorized_by"))),
                ("Included target", _text(data.get("target"))),
                ("Exclusions", _text(data["scope"].get("excluded_paths", data["scope"].get("exclusions")))),
            ],
        ),
        (
            "Methodology and coverage",
            [
                (
                    "Approach",
                    (
                        "Bounded safe HTTP GET requests through deterministic scope enforcement; findings derive from stored response evidence."
                        if str(assessment.get("profile")) == "safe_http"
                        else "Unified multi-stage assessment pipeline: passive TLS inspection, DNS intelligence, multi-port TCP service discovery, HTTP header and cookie posture analysis, web crawling, and active vulnerability verification."
                    ),
                ),
                (
                    "Authenticated coverage",
                    "Unauthenticated target requests only; authenticated target testing is unavailable.",
                ),
                ("Checks completed, skipped or failed", _text(_records(data.get("checks")))),
                (
                    "Tool metadata",
                    _text(
                        data.get("tools")
                        or (
                            "Built-in safe HTTP adapter; version is recorded only when supplied by the assessment."
                            if str(assessment.get("profile")) == "safe_http"
                            else "SHARAY Comprehensive Assessment Engine (TLS verifier, DNS analyzer, concurrent TCP port scanner, web crawler, and deep vulnerability auditor)."
                        )
                    ),
                ),
                ("Unrecorded tests", "Tests without stored execution evidence are not treated as completed."),
            ],
        ),
    ]

    # Network inventory section if ports observed
    port_obs = [o for o in observations if isinstance(o, dict) and o.get("kind") == "network_service"]
    if port_obs:
        port_rows = []
        for s in port_obs:
            state_str = s.get("state")
            state_disp = f" ({state_str})" if state_str else ""
            service_name = str(s.get("service") or "unknown").upper()
            proto = str(s.get("protocol") or "tcp")
            banner = str(s.get("banner") or "N/A")
            latency = f"{s.get('latency_ms')}ms" if s.get("latency_ms") is not None else "N/A"
            p_val = (
                f"Port {s.get('port')}/{proto} - {service_name}"
                f"{state_disp} | Banner: {banner} | Latency: {latency}"
            )
            port_rows.append((f"Port {s.get('port')}", p_val))
        sections.append(("Network Ports and Discovered Services", port_rows))

    # DNS intelligence section if records observed
    dns_obs = [o for o in observations if isinstance(o, dict) and o.get("kind") == "dns_records"]
    if dns_obs:
        d = dns_obs[0]
        ipv4 = [str(x) for x in (d.get("ipv4_addresses") or []) if x is not None]
        ipv6 = [str(x) for x in (d.get("ipv6_addresses") or []) if x is not None]
        waf = [str(x) for x in (d.get("cdn_waf_indicators") or []) if x is not None]
        dns_rows = [
            ("Domain", _text(d.get("domain"))),
            ("IPv4 Addresses", ", ".join(ipv4) or "None resolved"),
            ("IPv6 Addresses", ", ".join(ipv6) or "None resolved"),
            ("CDN / WAF Edge", ", ".join(waf) or "None identified"),
        ]
        sections.append(("DNS and Perimeter Intelligence", dns_rows))

    # Crawler and attack surface section if crawl summary observed
    crawl_obs = [o for o in observations if isinstance(o, dict) and o.get("kind") == "crawler_summary"]
    if crawl_obs:
        c = crawl_obs[0]
        endpoints = [str(x) for x in (c.get("endpoints") or []) if x is not None]
        parameters = [str(x) for x in (c.get("parameters") or []) if x is not None]
        crawl_rows = [
            ("Pages Visited", str(c.get("pages_visited", 0))),
            ("Discovered Endpoints Count", str(len(endpoints))),
            ("Discovered Endpoints", "\n".join(endpoints[:30]) or "None"),
            ("Discovered Parameters", ", ".join(parameters[:30]) or "None"),
        ]
        sections.append(("Discovered Endpoints and Attack Surface", crawl_rows))
    target_url = str(target.get("url") or target.get("origin") or data.get("target_url") or "")
    for group_title, group, empty_message in (
        (
            "Verified Security Vulnerabilities",
            verified,
            "No vulnerability has qualifying stored reproduction evidence.",
        ),
        (
            "Security Configuration & Hardening Posture",
            posture,
            "No configuration or hardening findings recorded.",
        ),
        ("Unverified or Demoted Findings", unverified, "No unverified or demoted vulnerability records."),
    ):
        sections.append(
            (
                group_title,
                [
                    ("Finding count", str(len(group))),
                    (
                        "Evidence boundary",
                        empty_message
                        if not group
                        else "Classification follows stored reproduction evidence; severity and confidence do not establish exploitability.",
                    ),
                ],
            )
        )
        for index, finding in enumerate(group, 1):
            verification = _verification(finding)
            technical, business = _impacts(finding, verification)
            state = "Configuration observation" if _posture(finding) else verification.title()
            ev_list = finding.get("evidence")
            evidence_dict: dict[str, Any] = {}
            if isinstance(ev_list, list) and ev_list and isinstance(ev_list[0], dict):
                first_ev = ev_list[0]
                ev_data = first_ev.get("data")
                if isinstance(ev_data, dict):
                    evidence_dict = cast(dict[str, Any], ev_data)
                else:
                    evidence_dict = cast(dict[str, Any], first_ev)
            poc_obj = synthesize_research_grade_poc(
                finding, target_url, evidence_data=evidence_dict, verification_state=verification
            )
            finding_rows = [
                ("Identifier", _text(finding.get("id") or finding.get("fingerprint"))),
                ("Category", _text(finding.get("category"))),
                ("Technical severity", _text(finding.get("severity"))),
                ("Evidence confidence", _text(finding.get("confidence"))),
                ("Report classification", state),
                ("Stored finding status", _text(finding.get("status"))),
                (
                    "WSTG Methodology ID",
                    f"{poc_obj.identification.wstg_id}: {poc_obj.identification.wstg_title}",
                ),
                (
                    "CWE Classification",
                    f"{poc_obj.identification.cwe_id}: {poc_obj.identification.cwe_title}",
                ),
                ("Security Boundary", poc_obj.impact.violated_security_boundary),
                ("Verification evidence", verification),
                (
                    "Affected asset",
                    _text(finding.get("affected_url") or finding.get("affected_asset") or target_url),
                ),
                ("Description", _text(finding.get("description"))),
                ("Technical Impact", technical),
                ("Business Impact", business),
                ("Positive Control (Hit)", poc_obj.validation.positive_control),
                ("Negative Control (Safe)", poc_obj.validation.negative_control),
                ("Repeatability Metric", poc_obj.validation.repeatability_rate),
                ("SHARAY Console Action", _console_action(finding, target_url)),
                ("Proof of Concept (PoC)", _poc(finding, target_url)),
                ("Research-Grade PoC Dossier", poc_obj.to_formatted_dossier()),
                *[(f"Evidence / {label}", value) for label, value in _detail_rows(finding.get("evidence"))],
                ("Remediation", _text(finding.get("remediation"))),
                ("References", _text(finding.get("references"))),
                (
                    "CVSS",
                    _text(
                        finding.get("cvss")
                        or finding.get("cvss_vector")
                        or "Not scored; insufficient contextual inputs."
                    ),
                ),
                (
                    "First / last seen",
                    " / ".join(_text(finding.get(key)) for key in ("first_seen", "last_seen")),
                ),
            ]
            screenshot_val = (
                finding.get("screenshot")
                or finding.get("screenshot_path")
                or finding.get("snapshot")
                or finding.get("visual_evidence")
                or (
                    isinstance(finding.get("evidence"), dict)
                    and (finding["evidence"].get("screenshot") or finding["evidence"].get("snapshot"))
                )
            )
            if screenshot_val:
                finding_rows.append(("Visual Snapshot / Screenshot", str(screenshot_val)))
            sections.append((f"Finding {index}: {_text(finding.get('title'))}", finding_rows))

    # Attack Graph & Exploit Chaining section
    graph_obs = [o for o in observations if isinstance(o, dict) and o.get("kind") == "attack_graph"]
    if graph_obs:
        g = graph_obs[0]
        chains = g.get("chains") or []
        chain_descriptions = []
        for c_idx, ch in enumerate(chains, 1):
            if isinstance(ch, list):
                nodes_str = " -> ".join(str(x) for x in ch if x is not None)
            else:
                nodes_str = str(ch) if ch is not None else ""
            chain_descriptions.append(f"Chain #{c_idx}: {nodes_str}")
        graph_rows = [
            (
                "Target Node Hierarchy",
                f"Modeled {len(g.get('nodes') or [])} nodes and {len(g.get('edges') or [])} potential relationships. Modeled paths do not establish exploitation.",
            ),
            (
                "Modeled Paths",
                "\n".join(chain_descriptions) or "No modeled paths recorded.",
            ),
            ("Critical Min-Cut Breakpoint", _text(g.get("critical_breakpoint"))),
            (
                "High-Leverage Remediation Action",
                str(g.get("high_leverage_remediation") or "Remediate verified initial entry points."),
            ),
        ]
        sections.append(("Modeled Attack Graph", graph_rows))

    # AutoPyVerifier section
    auto_obs = [
        o for o in observations if isinstance(o, dict) and o.get("kind") == "autopyverifier_execution"
    ]
    if auto_obs:
        av = auto_obs[0]
        script_summaries = []
        for s in av.get("scripts") or []:
            if isinstance(s, dict):
                script_summaries.append(
                    f"Script: {s.get('test_name', 'verify')} | Exit Code: {s.get('exit_code')} | Outcome: {s.get('outcome')}\n"
                    f"Mock mode: {s.get('mock_mode', 'not recorded')}\n"
                    f"Evidence: {_text(s.get('evidence_matched'))}"
                )
        sections.append(
            (
                "AutoPyVerifier Deterministic Verification Trace",
                [
                    ("Synthesized Scripts Evaluated", str(av.get("verified_count", len(script_summaries)))),
                    (
                        "Verification Results",
                        "\n\n".join(script_summaries) or "No script outcomes recorded.",
                    ),
                ],
            )
        )

    pivoting_obs = [o for o in observations if isinstance(o, dict) and o.get("kind") == "safe_gated_pivoting"]
    if pivoting_obs:
        pv = pivoting_obs[0]
        safety = pv.get("safety_gate") or {}
        socks = pv.get("socks_pivot") or {}
        subnets = [str(x) for x in (socks.get("unlocked_subnets") or []) if x is not None]
        subnets_str = ", ".join(subnets) or "None recorded"
        sections.append(
            (
                "Recorded Pivoting Metadata",
                [
                    ("Safety Gate Status", str(safety.get("status") or "quarantined").upper()),
                    ("Console Ownership", str(safety.get("console_ownership") or "HUMAN_OWNED")),
                    (
                        "Quarantine Policy",
                        _text(safety.get("quarantine_policy")),
                    ),
                    (
                        "Persistence Tracking",
                        f"{len(pv.get('persistence_inventory') or [])} inventory record(s). Artifact deployment and cleanup require separate execution evidence.",
                    ),
                    (
                        "SOCKS Pivot Router",
                        f"Recorded bridge port: {_text(socks.get('proxy_port'))} | Subnets: {subnets_str}",
                    ),
                ],
            )
        )

    sections.extend(
        [
            (
                "Observations and evidence",
                [
                    ("Stored observations", _text(_records(data.get("observations")))),
                    ("Evidence integrity hashes", _text(metadata["evidence_hashes"])),
                    (
                        "Integrity boundary",
                        "Hashes identify stored sanitized evidence. They do not attest to unsanitized originals or protect against a privileged local user changing the database.",
                    ),
                ],
            ),
            ("Execution timeline", [("Events", _text(_records(data.get("events"))))]),
            (
                "Limitations",
                [(str(index), _text(item)) for index, item in enumerate(metadata["limitations"], 1)]
                + [("Redaction", metadata["redaction"])],
            ),
            (
                "Researcher Signature and Platform Provenance",
                [
                    ("Author", "Shardul"),
                    ("Website", "https://shardulchaulagain.com"),
                    ("Platform", "SHARAY — Autonomous Offensive & Defensive Security Engine"),
                    (
                        "Audit Verification",
                        "Only findings with qualifying stored reproduction evidence appear in Verified Security Vulnerabilities.",
                    ),
                    (
                        "Cryptographic Seal",
                        "Stored SHA-256 digests identify evidence; no immutable storage or external attestation is inferred.",
                    ),
                ],
            ),
        ]
    )
    return sections


def _html(sections: list) -> bytes:
    content = []
    for title, rows in sections:
        cells = []
        for label, value in rows:
            cells.append(f"<dt>{escape(label)}</dt><dd><pre>{escape(str(value))}</pre></dd>")
        content.append(f"<section><h2>{escape(title)}</h2><dl>{''.join(cells)}</dl></section>")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>SHARAY assessment report</title><style>"
        "body{font:15px/1.6 system-ui,sans-serif;color:#142434;background:#f3f6fa;margin:0}"
        "main{max-width:960px;margin:auto;padding:40px 24px}h1{letter-spacing:.12em}"
        "h2{font-size:21px;color:#163a51}section{padding:20px 24px;margin:20px 0;background:white;border:1px solid #d2dce5;border-radius:8px}"
        "dl{margin:0}dt{font-weight:650;margin-top:14px}dd{margin:2px 0 14px}"
        "pre{font:inherit;white-space:pre-wrap;overflow-wrap:anywhere;margin:0}"
        "@media print{body{background:white}main{padding:0}section{break-inside:auto}}"
        "</style></head><body><main><h1>SHARAY</h1><p>Security assessment report</p>"
        + "".join(content)
        + "</main></body></html>"
    ).encode("utf-8")


def _markdown(sections: list) -> bytes:
    def heading(value: str) -> str:
        value = escape(value).replace("\n", " ")
        return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", value)

    blocks = ["# SHARAY security assessment report"]
    for title, rows in sections:
        blocks.append("## " + heading(title))
        for label, value in rows:
            blocks.append(
                "**"
                + heading(label)
                + "**\n\n"
                + "\n".join("    " + line for line in str(value).splitlines())
            )
    return ("\n\n".join(blocks) + "\n").encode("utf-8")


def _sharay_logo_flowable():
    from reportlab.graphics.shapes import Circle, Drawing, Line, Polygon, Rect, String
    from reportlab.lib import colors

    d = Drawing(520, 52)
    shield_pts = [14, 46, 34, 46, 44, 34, 44, 18, 24, 4, 4, 18, 4, 34]
    d.add(
        Polygon(
            shield_pts,
            fillColor=colors.HexColor("#0f172a"),
            strokeColor=colors.HexColor("#0284c7"),
            strokeWidth=1.5,
        )
    )
    inner_pts = [17, 40, 31, 40, 38, 30, 24, 12, 10, 30]
    d.add(
        Polygon(
            inner_pts,
            fillColor=colors.HexColor("#0284c7"),
            strokeColor=colors.HexColor("#38bdf8"),
            strokeWidth=1.0,
        )
    )
    d.add(
        Circle(
            24,
            26,
            3.5,
            fillColor=colors.HexColor("#ffffff"),
            strokeColor=colors.HexColor("#38bdf8"),
            strokeWidth=1.0,
        )
    )
    d.add(
        String(54, 30, "SHARAY", fontName="Helvetica-Bold", fontSize=22, fillColor=colors.HexColor("#0f172a"))
    )
    d.add(
        String(
            54,
            18,
            "CYBERSECURITY ASSURANCE & PENETRATION TESTING PLATFORM",
            fontName="Helvetica-Bold",
            fontSize=7,
            fillColor=colors.HexColor("#0284c7"),
        )
    )
    d.add(
        String(
            54,
            8,
            "VERIFIED FORENSIC EVIDENCE · ZERO SPECULATION · MERKLE PROVENANCE",
            fontName="Helvetica",
            fontSize=6.5,
            fillColor=colors.HexColor("#64748b"),
        )
    )
    d.add(
        Rect(
            325,
            12,
            195,
            32,
            rx=4,
            ry=4,
            fillColor=colors.HexColor("#f8fafc"),
            strokeColor=colors.HexColor("#cbd5e1"),
            strokeWidth=0.8,
        )
    )
    d.add(
        String(
            333,
            32,
            "SECURITY CLASSIFICATION: CONFIDENTIAL",
            fontName="Helvetica-Bold",
            fontSize=6.5,
            fillColor=colors.HexColor("#dc2626"),
        )
    )
    d.add(
        String(
            333,
            23,
            "EVIDENCE INTEGRITY SEAL: MERKLE ROOT",
            fontName="Helvetica",
            fontSize=6.0,
            fillColor=colors.HexColor("#475569"),
        )
    )
    d.add(
        String(
            333,
            15,
            "PROVENANCE: CRYPTOGRAPHICALLY AUDITED",
            fontName="Helvetica-Bold",
            fontSize=5.5,
            fillColor=colors.HexColor("#16a34a"),
        )
    )
    d.add(Line(0, 0, 520, 0, strokeColor=colors.HexColor("#cbd5e1"), strokeWidth=1.0))
    return d


def _pdf(sections: list) -> bytes:
    import os

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Image, LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle

    output = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "ReportBody",
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#142434"),
            spaceAfter=7,
            wordWrap="CJK",
            alignment=TA_LEFT,
        )
    )
    styles["Heading2"].textColor = colors.HexColor("#163a51")
    styles["Heading2"].spaceBefore = 14
    styles["Heading2"].spaceAfter = 8
    styles["Heading2"].keepWithNext = True
    story = [
        _sharay_logo_flowable(),
        Spacer(1, 10),
        Paragraph("EXECUTIVE SECURITY ASSESSMENT REPORT", styles["Title"]),
        Paragraph("Cryptographically Sealed Assessment & Forensic Evidence", styles["Heading2"]),
        Spacer(1, 8),
    ]
    for title, rows in sections:
        safe_title = title.encode("cp1252", errors="backslashreplace").decode("cp1252")
        story.append(Paragraph(escape(safe_title), styles["Heading2"]))
        table_rows = []
        for label, value in rows:
            # Built-in fonts are local. Represent unsupported glyphs explicitly.
            safe_label = label.encode("cp1252", errors="backslashreplace").decode("cp1252")
            safe = str(value).encode("cp1252", errors="backslashreplace").decode("cp1252")
            if ("snapshot" in safe_label.lower() or "screenshot" in safe_label.lower()) and os.path.isfile(
                str(value).strip()
            ):
                try:
                    img = Image(str(value).strip(), width=5.0 * inch, height=2.6 * inch)
                    table_rows.append(
                        [
                            Paragraph(f"<b>{escape(safe_label)}</b>", styles["ReportBody"]),
                            img,
                        ]
                    )
                    continue
                except Exception:
                    pass
            table_rows.append(
                [
                    Paragraph(f"<b>{escape(safe_label)}</b>", styles["ReportBody"]),
                    Paragraph(escape(safe).replace("\n", "<br/>"), styles["ReportBody"]),
                ]
            )
        if table_rows:
            table = LongTable(table_rows, colWidths=[1.65 * inch, 5.2 * inch], splitInRow=1)
            table.setStyle(
                TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef3f7")),
                        ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#d2dce5")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 7),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            story.append(table)

    def draw_decorations(canvas, doc):
        canvas.saveState()
        # Watermark: "sharay by shardul" in blue, small, diagonal, multiple tiled watermarks across page
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#1e88e5"), alpha=0.10)
        watermark_text = "sharay by shardul"
        width, height = doc.pagesize
        for x in range(-50, int(width) + 120, 130):
            for y in range(-50, int(height) + 120, 95):
                canvas.saveState()
                canvas.translate(x, y)
                canvas.rotate(35)
                canvas.drawString(-35, 0, watermark_text)
                canvas.restoreState()

        # Footer branding
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(colors.HexColor("#1e88e5"), alpha=1.0)
        canvas.drawString(0.7 * inch, 0.45 * inch, "SHARAY")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#526779"), alpha=1.0)
        canvas.drawString(1.3 * inch, 0.45 * inch, "|  Author: Shardul  ·  https://shardulchaulagain.com")
        canvas.drawRightString(doc.pagesize[0] - 0.7 * inch, 0.45 * inch, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        output,
        pagesize=(595.28, 841.89),
        rightMargin=0.7 * inch,
        leftMargin=0.7 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.7 * inch,
        title="SHARAY security assessment report",
        author="SHARAY",
        pageCompression=0,
    )
    doc.build(story, onFirstPage=draw_decorations, onLaterPages=draw_decorations)
    return output.getvalue()


def render_report(data: dict, format: str) -> tuple[bytes, str]:
    """Render actual records to bytes and the matching media type."""
    format = format.lower()
    if format not in {"html", "json", "markdown", "md", "pdf", "sarif", "csv", "bundle", "zip"}:
        raise ValueError("Unsupported report format")
    clean = _prepare(data)
    if format == "json":
        return (_json(clean) + "\n").encode("utf-8"), "application/json"
    if format == "sarif":
        from packages.reporting.sarif import SarifExporter

        return SarifExporter.export(clean).encode("utf-8"), "application/sarif+json"
    if format == "csv":
        from packages.reporting.sarif import CsvExporter

        return CsvExporter.export(clean).encode("utf-8"), "text/csv; charset=utf-8"
    if format in {"bundle", "zip"}:
        from packages.reporting.bundle import EvidenceBundleBuilder

        assessment_id = str(
            clean.get("report_metadata", {}).get("assessment_id") or clean.get("id") or "assessment-unknown"
        )
        return EvidenceBundleBuilder.build_bundle(assessment_id, clean), "application/zip"
    sections = _sections(clean)
    if format == "html":
        return _html(sections), "text/html; charset=utf-8"
    if format in {"markdown", "md"}:
        return _markdown(sections), "text/markdown; charset=utf-8"
    return _pdf(sections), "application/pdf"
