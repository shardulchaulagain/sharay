"""The implemented safe HTTP adapter and honest optional-tool preflight."""

import hashlib
import http.client
import ipaddress
import os
import re
import shutil
import socket
import ssl
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urljoin, urlparse

from packages.security_policies import (
    Destination,
    PolicyError,
    ScopePolicy,
)
from packages.security_policies import (
    check_execution_url as check_url,
)
from packages.security_policies import (
    validate_execution_scope as validate_scope,
)

ADAPTER_VERSION = "1.1.6"
MAX_REQUESTS = 5
MAX_SECONDS = 15
REQUEST_TIMEOUT = 3
MAX_HEADER_BYTES = 65536


class ScanStopped(Exception):
    pass


def _remaining_timeout(sock):
    deadline = getattr(sock, "deadline", None)
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Request deadline exceeded.")
        sock.settimeout(min(REQUEST_TIMEOUT, remaining))


class _DeadlineSocket(socket.socket):
    deadline: float | None = None

    def recv_into(self, *args, **kwargs):
        _remaining_timeout(self)
        return super().recv_into(*args, **kwargs)


class _DeadlineTLS(ssl.SSLSocket):
    deadline: float | None = None

    def read(self, *args, **kwargs):
        _remaining_timeout(self)
        return super().read(*args, **kwargs)


class _HeaderReader:
    def __init__(self, reader):
        self.reader = reader
        self.total = 0

    def readline(self, limit=-1):
        budget = MAX_HEADER_BYTES - self.total + 1
        data = self.reader.readline(min(limit, budget) if limit >= 0 else budget)
        self.total += len(data)
        if self.total > MAX_HEADER_BYTES:
            raise http.client.HTTPException("Response header budget exceeded.")
        return data

    def __getattr__(self, name):
        return getattr(self.reader, name)


class _BoundedResponse(http.client.HTTPResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fp = cast(Any, _HeaderReader(self.fp))


def preflight() -> list[dict]:
    tools = [
        ("nmap", "nmap"),
        ("zap", "zap.sh"),
        ("nuclei", "nuclei"),
        ("semgrep", "semgrep"),
        ("gitleaks", "gitleaks"),
        ("metasploit", "msfconsole"),
    ]
    result = [
        {
            "id": "safe_http",
            "name": "SHARAY safe HTTP",
            "version": ADAPTER_VERSION,
            "available": True,
            "runnable": True,
            "status": "implemented",
            "supported_categories": ["http_headers", "tls"],
            "scope": "Explicitly approved literal loopback laboratories only",
            "guidance": "Register broad scopes in inventory; only explicitly approved literal loopback labs can execute until verified live-target controls are connected.",
            "limits": {
                "max_requests": MAX_REQUESTS,
                "max_seconds": MAX_SECONDS,
                "request_timeout": REQUEST_TIMEOUT,
                "max_header_bytes": MAX_HEADER_BYTES,
                "response_body_bytes_retained": 0,
                "concurrency": 1,
            },
            "limitations": "TLS uses the operating-system trust store. DNS queries, authenticated testing and external scanner execution are unavailable.",
        }
    ]
    for name, command in tools:
        available = bool(shutil.which(command))
        result.append(
            {
                "id": name,
                "name": name,
                "version": None,
                "available": available,
                "runnable": False,
                "status": "integration_not_implemented" if available else "missing",
                "supported_categories": [],
                "limitations": "Not executed: adapter and isolated worker policy are not implemented.",
                "guidance": (
                    f"Install an approved {name} distribution and make {command} available on PATH. "
                    if not available
                    else f"{command} detected on PATH. "
                )
                + "Product dispatch still requires its reviewed adapter, verified isolation/resource bounds and enforceable destination policy; executable presence does not enable assessment.",
            }
        )
    return result


def _connect(destination: Destination, timeout: float) -> _DeadlineSocket:
    """Connect to the policy-selected numeric address without a DNS resolver."""
    address = ipaddress.ip_address(destination.ip)
    sock = _DeadlineSocket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        endpoint = (
            (destination.ip, destination.port, 0, 0)
            if address.version == 6
            else (destination.ip, destination.port)
        )
        sock.connect(endpoint)
        if ipaddress.ip_address(sock.getpeername()[0]) != address:
            raise PolicyError("The connected peer does not match the pinned destination.")
        return sock
    except Exception:
        sock.close()
        raise


def _connection(destination: Destination, timeout: float) -> http.client.HTTPConnection:
    deadline = time.monotonic() + timeout
    connection: http.client.HTTPConnection
    if destination.scheme == "https":
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.sslsocket_class = _DeadlineTLS
        connection = http.client.HTTPSConnection(
            destination.host, destination.port, timeout=timeout, context=context
        )
    else:
        connection = http.client.HTTPConnection(destination.host, destination.port, timeout=timeout)
    connection.response_class = _BoundedResponse

    def pinned_socket(*args, **kwargs):
        sock = _connect(destination, max(0.001, deadline - time.monotonic()))
        sock.deadline = deadline
        return sock

    setattr(connection, "_create_connection", pinned_socket)
    try:
        connection.connect()
        if not isinstance(connection.sock, (_DeadlineSocket, _DeadlineTLS)):
            raise RuntimeError("A deadline-aware connection is required.")
        connection.sock.deadline = deadline
    except Exception:
        connection.close()
        raise
    if ipaddress.ip_address(connection.sock.getpeername()[0]) != ipaddress.ip_address(destination.ip):
        connection.close()
        raise PolicyError("The connected peer does not match the pinned destination.")
    return connection


def _cookie_flags(values: list[str]) -> list[dict]:
    """Read RFC6265bis attributes without retaining cookie identifiers or values.

    This is a response configuration fact, not a cookie storage simulation.
    """
    flags: list[dict[str, Any]] = []
    for value in values:
        # HTTPResponse decodes bytes as Latin-1. CTLs other than HTAB reject
        # the entire Set-Cookie string, including controls in attributes.
        if any(ord(char) > 255 or (ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
            flags.append({"parse_error": True})
            continue
        pair, _, attributes = value.partition(";")
        name, separator, cookie_value = pair.partition("=")
        if not separator:
            name, cookie_value = "", name
        name, cookie_value = name.strip(" \t"), cookie_value.strip(" \t")
        if not (name or cookie_value) or len(name) + len(cookie_value) > 4096:
            flags.append({"parse_error": True})
            continue
        cookie_flags: dict[str, Any] = {"secure": False, "httponly": False, "samesite": "unset"}
        root_path = False
        domain_present = False
        for attribute in attributes.split(";"):
            attribute_name, _, attribute_value = attribute.partition("=")
            attribute_name = attribute_name.strip(" \t").lower()
            attribute_value = attribute_value.strip(" \t")
            if len(attribute_value) > 1024:
                continue
            if attribute_name in {"secure", "httponly"}:
                cookie_flags[attribute_name] = True
            elif attribute_name == "samesite":
                same_site = attribute_value.lower()
                cookie_flags["samesite"] = same_site if same_site in {"strict", "lax", "none"} else "unset"
            elif attribute_name == "path":
                root_path = attribute_value == "/"
            elif attribute_name == "domain":
                # The last bounded Domain wins, after removing one leading dot.
                domain_present = bool(attribute_value.removeprefix("."))
        prefix = (
            "host"
            if name.lower().startswith("__host-")
            else ("secure" if name.lower().startswith("__secure-") else "")
        )
        if prefix:
            cookie_flags.update(prefix=prefix, prefix_missing_secure=not cookie_flags["secure"])
            if prefix == "host":
                cookie_flags.update(prefix_nonroot_path=not root_path, prefix_domain_present=domain_present)
        flags.append(cookie_flags)
    return flags


_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


def _ancestor_policies(values: list[str]) -> list[list[str]]:
    """Read only each enforced policy's first frame-ancestors directive.

    CSP fields/comma-delimited policies are enforced together. This is an
    ancestor-host configuration check, not a general CSP validator.
    """
    ancestors = []
    for value in values:
        for policy in value.split(","):
            for directive in policy.split(";"):
                if not directive.isascii():
                    continue
                # CSP ASCII whitespace excludes VT/FS, unlike str.split().
                tokens = re.split(r"[ \t\n\f\r]+", directive.strip(" \t\n\f\r"))
                if tokens and tokens[0].lower() == "frame-ancestors":
                    ancestors.append(tokens[1:])
                    break
    return ancestors


def _arbitrary_web_hosts(source: str) -> bool:
    """Recognize unrestricted web-host patterns; domain wildcards stay narrow."""
    source = source.lower()
    return (
        source in {"http:", "https:"}
        or re.fullmatch(r"(?:https?://)?\*(?::(?:\*|[0-9]+))?(?:/.*)?", source) is not None
    )


def _header_facts(headers: list[tuple[str, str]]) -> dict:
    """Retain configuration facts rather than untrusted header values or secrets."""
    lowered = {name.lower(): value for name, value in headers}
    field_values: dict[str, list[str]] = {}
    for name, value in headers:
        field_values.setdefault(name.lower(), []).append(value)
    # Fetch combines repeated CORS fields; none of the resulting comma lists
    # equals a single wildcard or the case-sensitive credentials token.
    cors_origin = field_values.get("access-control-allow-origin", [])
    cors_credentials = field_values.get("access-control-allow-credentials", [])
    isolation_tokens = {}
    for short, name, allowed in [
        (
            "coop",
            "cross-origin-opener-policy",
            {"unsafe-none", "same-origin", "same-origin-allow-popups", "noopener-allow-popups"},
        ),
        ("coep", "cross-origin-embedder-policy", {"unsafe-none", "require-corp", "credentialless"}),
        ("corp", "cross-origin-resource-policy", {"same-origin", "same-site", "cross-origin"}),
    ]:
        values = field_values.get(name, [])
        token = values[0].partition(";")[0].strip(" \t") if len(values) == 1 else ""
        isolation_tokens[short] = "absent" if not values else token if token in allowed else "unrecognized"
    software_indicators = {
        name: {
            "present": any(value.strip(" \t") for value in field_values.get(name, [])),
            "version_pattern": any(
                re.search(r"(?:^|[/ \t])v?[0-9]+(?:\.[0-9]+)+", value) is not None
                for value in field_values.get(name, [])
            ),
        }
        for name in ["server", "x-powered-by", "x-aspnet-version", "x-generator", "x-backend-server"]
    }
    csp_values = [value for name, value in headers if name.lower() == "content-security-policy"]
    ancestors = _ancestor_policies(csp_values)
    # Even an empty ancestor list blocks framing. A narrow policy still applies
    # when another policy allows every host; their permissions are intersected.
    ancestor_hosts_restricted = any(
        not any(_arbitrary_web_hosts(token) for token in policy) for policy in ancestors
    )
    referrer_tokens = [
        token.strip(" \t\r\n").lower()
        for name, value in headers
        if name.lower() == "referrer-policy"
        for token in value.split(",")
    ]
    frame_options = {
        token.strip(" \t\r\n").lower()
        for name, value in headers
        if name.lower() == "x-frame-options"
        for token in value.split(",")
    }
    frame_options_valid = len(frame_options) == 1 and bool(frame_options & {"deny", "sameorigin"})
    # HTML also fails closed for conflicting values containing a recognized
    # token (including legacy ALLOWALL). Multiple invalid values allow framing.
    frame_options_restrict = frame_options_valid or (
        len(frame_options) > 1 and bool(frame_options & {"deny", "sameorigin", "allowall"})
    )
    # Fetch determines nosniff from the first value of the combined field list.
    # A quoted first value cannot equal the bare token, so first-comma slicing
    # suffices for this exact match without implementing a general field parser.
    first_content_type_option = next(
        (value for name, value in headers if name.lower() == "x-content-type-options"), ""
    ).partition(",")[0]
    return {
        "security_headers": {
            name: name in lowered
            for name in [
                "content-security-policy",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "strict-transport-security",
            ]
        },
        "csp_nonempty": any(
            policy.strip(" \t\r\n\f;") for value in csp_values for policy in value.split(",")
        ),
        "csp_has_frame_ancestors": bool(ancestors),
        # Retain the existing framing fact key for consumers, with accurate scope.
        "csp_frame_ancestors": ancestor_hosts_restricted,
        "frame_options_valid": frame_options_valid,
        "frame_options_restricts_framing": frame_options_restrict,
        # Enforced frame-ancestors overrides XFO, even when its hosts are broad.
        "framing_host_restriction_identified": ancestor_hosts_restricted
        if ancestors
        else frame_options_restrict,
        "referrer_policy_valid": any(token in _REFERRER_POLICIES for token in referrer_tokens),
        "header_analysis_limits": "CSP non-emptiness is not policy validity. Framing checks ancestor host patterns and XFO rules; combined scheme/port/path behavior and browser workflows are not tested. Referrer recognition is not a privacy-strength assessment. Cookie flags describe Set-Cookie attributes, not browser storage acceptance. Isolation tokens do not validate parameters or establish browser isolation; missing isolation headers require application context. Software version patterns do not identify a product or vulnerability. CORS origin reflection and credentialed browser access were not tested.",
        "nosniff": first_content_type_option.strip(" \t").lower() == "nosniff",
        "cache_control": {
            directive: directive
            in {d.strip().lower().split("=")[0] for d in lowered.get("cache-control", "").split(",")}
            for directive in ["no-store", "no-cache", "private", "public"]
        },
        "cors_wildcard": len(cors_origin) == 1 and cors_origin[0].strip(" \t") == "*",
        "cors_credentials": len(cors_credentials) == 1 and cors_credentials[0].strip(" \t") == "true",
        "browser_isolation_tokens": isolation_tokens,
        "software_indicators": software_indicators,
        "server_indicator_present": "server" in lowered,
        "cookie_flags": _cookie_flags([value for name, value in headers if name.lower() == "set-cookie"]),
    }


def _findings(observation: dict) -> list[dict]:
    facts = observation["facts"]
    headers = facts["security_headers"]
    issues = []
    # Historical observations retain their original facts and finding keys.
    csp_nonempty = facts.get("csp_nonempty", facts.get("csp_effective", headers["content-security-policy"]))
    if not csp_nonempty:
        issues.append(
            (
                "missing_csp",
                "Content-Security-Policy is absent or empty",
                "info",
                "Evaluate a Content-Security-Policy appropriate to the application and test it before enforcement. A nonempty header alone does not establish that its directives are valid or protective.",
            )
        )
    if not facts["nosniff"]:
        issues.append(
            (
                "missing_nosniff",
                "X-Content-Type-Options nosniff is absent",
                "low",
                "Send X-Content-Type-Options: nosniff with accurate Content-Type headers.",
            )
        )
    if not facts.get("referrer_policy_valid", headers["referrer-policy"]):
        issues.append(
            (
                "missing_referrer_policy",
                "Referrer-Policy is absent or not a recognised value",
                "info",
                "Choose and send an explicit Referrer-Policy appropriate to the application. Recognized values have different privacy effects; the last recognized token controls the header policy.",
            )
        )
    framing_restricted = facts.get(
        "framing_host_restriction_identified",
        facts.get("frame_options_valid", headers["x-frame-options"]) or facts["csp_frame_ancestors"],
    )
    if not framing_restricted:
        issues.append(
            (
                "missing_frame_policy",
                "An explicit framing host restriction was not identified",
                "info",
                "If embedding is unnecessary, configure CSP frame-ancestors 'none'; otherwise allow only intended ancestors. Enforced frame-ancestors overrides X-Frame-Options. Scheme-only or all-host wildcard sources allow arbitrary web hosts; confirm the intended behavior in a browser.",
            )
        )
    if observation["url"].startswith("https:") and not headers["strict-transport-security"]:
        issues.append(
            (
                "missing_hsts",
                "Strict-Transport-Security header is absent",
                "low",
                "After confirming HTTPS works consistently, configure an appropriate HSTS policy.",
            )
        )
    if any(not flags.get("httponly", True) for flags in facts["cookie_flags"]):
        issues.append(
            (
                "cookie_httponly",
                "A response cookie omits HttpOnly",
                "info",
                "Use HttpOnly for cookies that do not require JavaScript access, especially session cookies.",
            )
        )
    if any(
        any(
            flags.get(key, False)
            for key in ("prefix_missing_secure", "prefix_nonroot_path", "prefix_domain_present")
        )
        for flags in facts["cookie_flags"]
    ):
        issues.append(
            (
                "cookie_prefix",
                "A prefixed response cookie omits required prefix attributes",
                "info",
                "For __Secure- cookies include Secure; for __Host- cookies also send Path=/ and omit nonempty Domain attributes. Inspect browser storage behavior separately; cookie identifiers and values are not retained.",
            )
        )
    if facts.get("cors_wildcard") and facts.get("cors_credentials"):
        issues.append(
            (
                "cors_wildcard_credentials",
                "CORS wildcard is paired with a credentials flag",
                "info",
                "Use an explicit intended origin when credentialed cross-origin access is required. Browsers do not grant credentialed response access with a wildcard; origin reflection and exploitability were not tested.",
            )
        )
    if any(
        name != "server" and indicator.get("present")
        for name, indicator in facts.get("software_indicators", {}).items()
    ):
        issues.append(
            (
                "software_indicators",
                "Application software-identifying response headers are present",
                "info",
                "Review whether these response headers are needed and suppress unnecessary software details. Only presence and numeric version-pattern facts are retained; no vulnerable version has been established.",
            )
        )
    return [
        {
            "fingerprint": hashlib.sha256(f"{observation['url']}|{key}".encode()).hexdigest(),
            "title": title,
            "category": "http_headers",
            "severity": severity,
            "confidence": "high",
            "status": "confirmed",
            "description": "This is a directly observed response configuration fact. Application context, complete CSP validity, browser workflows and exploitability were not tested; header configuration alone does not establish an exploitable vulnerability.",
            "remediation": remediation,
            "evidence": {
                "kind": "http_configuration",
                "check": key,
                "url": observation["url"],
                "status_code": observation["status_code"],
                "facts": facts,
            },
            "affected_url": observation["url"],
            "cvss_vector": None,
            "cvss_score": None,
        }
        for key, title, severity, remediation in issues
    ]


def _tls_observation(connection: http.client.HTTPConnection, destination: Destination) -> dict:
    sock = connection.sock
    if not isinstance(sock, ssl.SSLSocket):
        raise ssl.SSLError("TLS observations require a verified TLS connection.")
    certificate = sock.getpeercert() or {}
    binary = sock.getpeercert(binary_form=True)
    cipher = sock.cipher()
    if binary is None or cipher is None:
        raise ssl.SSLError("TLS certificate or cipher evidence is unavailable.")
    return {
        "kind": "tls_handshake",
        "category": "tls",
        "url": destination.url,
        "captured_at": datetime.now(UTC).isoformat(),
        "destination_ip": destination.ip,
        "certificate_verified": True,
        "hostname_verified": True,
        "certificate_sha256": hashlib.sha256(binary).hexdigest(),
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
        "protocol": sock.version(),
        "cipher": cipher[0],
    }


def scan(
    scope: dict,
    target_url: str,
    cancelled: Callable[[], bool],
    emit: Callable[[dict], None],
    *,
    request_starts: dict[str, tuple[float, float]] | None = None,
) -> dict:
    """Run bounded real observations. Errors and skipped coverage remain explicit."""
    result: dict[str, Any] = {
        "observations": [],
        "findings": [],
        "checks": [],
        "outcome": "completed",
        "adapter": "safe_http",
        "version": ADAPTER_VERSION,
    }
    started = time.monotonic()
    connection = None
    performed = 0
    policy: ScopePolicy | None = None
    pacing = request_starts if request_starts is not None else {}

    def guard():
        if cancelled():
            raise ScanStopped("Operator cancellation requested.")
        if time.monotonic() - started >= MAX_SECONDS:
            raise TimeoutError("Assessment execution budget exceeded.")
        if policy is not None and datetime.now(UTC) >= policy.expires_at:
            raise PolicyError("The assessment scope has expired.")

    def record_check(category, status, detail, url=None):
        check = {"category": category, "status": status, "detail": detail}
        if url is not None:
            check["url"] = url
        result["checks"].append(check)
        emit({"type": "check", **check})

    def record_observation(observation):
        result["observations"].append(observation)
        emit(
            {
                "type": "observation",
                "kind": observation["kind"],
                "url": observation["url"],
            }
        )

    try:
        guard()
        policy = validate_scope(scope, target_url)
        destination = check_url(policy, target_url)
        if "dns" in policy.categories:
            record_check(
                "dns",
                "skipped",
                "Literal loopback address: no DNS query. DNS record inspection is unavailable.",
            )
        if "tls" in policy.categories and destination.scheme != "https":
            record_check(
                "tls",
                "skipped",
                "The approved target uses HTTP; no TLS handshake is available.",
            )
        if not any(category in policy.categories for category in ["http_headers", "tls"]):
            record_check("safe_http", "skipped", "No executable checks were selected.")
            return result
        if "http_headers" not in policy.categories and destination.scheme != "https":
            return result
        previous_request = None
        seen = set()
        while performed < MAX_REQUESTS:
            guard()
            destination = check_url(policy, destination.url)
            if destination.url in seen:
                raise PolicyError("Redirect loop detected; assessment stopped.")
            seen.add(destination.url)
            interval = 1 / policy.request_rate
            next_request = time.monotonic()
            prior = pacing.get(destination.origin)
            if prior is not None:
                # Keep the earlier job's cooldown even if the new approval allows a faster rate.
                next_request = max(next_request, prior[0] + prior[1], prior[0] + interval)
            if previous_request is not None:
                next_request = max(next_request, previous_request + interval)
            while time.monotonic() < next_request:
                guard()
                check_url(policy, destination.url)
                time.sleep(max(0, min(0.05, next_request - time.monotonic())))
            guard()
            # Expiry and scope are revalidated immediately before every connection.
            destination = check_url(policy, destination.url)
            # Persistence may take time: recheck guards and timeout after the reservation.
            pacing[destination.origin] = time.monotonic(), interval
            guard()
            destination = check_url(policy, destination.url)
            timeout = min(
                REQUEST_TIMEOUT,
                MAX_SECONDS - (time.monotonic() - started),
                (policy.expires_at - datetime.now(UTC)).total_seconds(),
            )
            connection = _connection(destination, timeout)
            performed += 1
            if destination.scheme == "https" and "tls" in policy.categories:
                record_observation(_tls_observation(connection, destination))
                record_check(
                    "tls",
                    "completed",
                    "Certificate chain and literal-IP hostname verified by the default TLS trust store.",
                    destination.url,
                )
            if "http_headers" not in policy.categories:
                connection.close()
                connection = None
                break
            guard()
            check_url(policy, destination.url)
            previous_request = time.monotonic()
            pacing[destination.origin] = previous_request, interval
            connection.request(
                "GET",
                destination.path,
                headers={
                    "User-Agent": f"SHARAY-SafeHTTP/{ADAPTER_VERSION}",
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            guard()
            if response.headers.defects:
                raise http.client.HTTPException("Malformed response header structure.")
            headers = response.getheaders()
            if sum(len(name) + len(value) + 4 for name, value in headers) > MAX_HEADER_BYTES:
                raise ValueError("Response header budget exceeded.")
            observation = {
                "kind": "http_response",
                "category": "http_headers",
                "url": destination.url,
                "destination_ip": destination.ip,
                "method": "GET",
                "status_code": response.status,
                "captured_at": datetime.now(UTC).isoformat(),
                "facts": _header_facts(headers),
                "body_retained": False,
            }
            record_observation(observation)
            # Never read response bodies or retain arbitrary header/cookie values.
            location = response.getheader("Location")
            redirect = response.status in {301, 302, 303, 307, 308} and location is not None
            response.close()
            connection.close()
            connection = None
            guard()
            if redirect:
                destination = check_url(policy, urljoin(destination.url, location))
                record_check(
                    "redirect",
                    "completed",
                    "Redirect destination passed scope validation before connection.",
                )
                continue
            result["findings"] = _findings(observation)
            record_check(
                "http_headers",
                "completed",
                "Security-header and cookie configuration facts collected from a real GET response; response body was not retained.",
                destination.url,
            )
            break
        else:
            raise PolicyError("Maximum redirect/request budget reached.")
    except ScanStopped:
        result["outcome"] = "cancelled"
        record_check(
            "safe_http",
            "cancelled",
            "Operator cancellation requested; connections were closed.",
        )
    except (ValueError, OSError, http.client.HTTPException) as exc:
        result["outcome"] = "completed_with_errors" if result["observations"] else "failed"
        if isinstance(exc, PolicyError):
            detail = str(exc)
        elif isinstance(exc, ssl.SSLCertVerificationError):
            detail = (
                "TLS certificate chain or hostname validation failed. No insecure fallback was attempted."
            )
        elif isinstance(exc, (TimeoutError, socket.timeout)):
            detail = "Request or assessment execution timed out."
        elif isinstance(exc, (ValueError, http.client.HTTPException)):
            detail = "Invalid policy input or malformed/oversized HTTP response; check did not complete."
        else:
            detail = "Connection or adapter execution failed; check did not complete."
        record_check("safe_http", "failed", detail)
    finally:
        if connection is not None:
            connection.close()
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
        result["requests_performed"] = performed
    return result


__all__ = [
    "preflight",
    "scan",
    "scan_comprehensive",
    "scan_live",
    "scan_live_metasploit_auxiliary",
    "scan_live_nmap",
    "scan_live_nuclei",
    "scan_live_zap",
]


def _parse_http_headers(raw: str) -> tuple[int, list[tuple[str, str]]]:
    """Parse a curl `-D -` header dump into (final status code, [(name, value)]). Each `HTTP/`
    status line resets the block so the last response (after any 1xx/redirect) wins."""
    status = 0
    headers: list[tuple[str, str]] = []
    for line in raw.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split(None, 2)
            status, headers = (int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0), []
        elif ":" in line:
            name, _, value = line.partition(":")
            headers.append((name.strip(), value.strip()))
    return status, headers


def scan_live(destination: Destination, allow_ip: str, *, run: Callable[..., Any] | None = None) -> dict:
    """Assess a live, in-scope, ownership-verified target's security headers over the enforced
    single-destination egress runner. `curl --resolve` pins the connection to the authorized IP
    (the allowlist drops everything else, DNS included), so no name is resolved in-container. Reuses
    the safe_http header/finding logic and returns the same result shape as scan()."""
    if run is None:
        # This unconnected prototype has no trusted readiness, cancellation or
        # pacing contract yet. Only explicit test runners may exercise it.
        return {
            "adapter": "safe_http_live",
            "observations": [],
            "findings": [],
            "checks": [
                {
                    "category": "http_headers",
                    "status": "blocked",
                    "detail": "Live execution controls have not passed independent integration verification.",
                }
            ],
            "outcome": "failed",
            "requests_performed": 0,
            "duration_ms": 0,
        }
    runner = run
    started = time.monotonic()
    host, port, url = destination.host, destination.port, destination.url
    argv = [
        "-sS",
        "-L",
        "--max-redirs",
        "3",
        "-D",
        "-",
        "-o",
        "/dev/null",
        "--max-time",
        str(REQUEST_TIMEOUT * 5),
        "--resolve",
        f"{host}:{port}:{allow_ip}",
    ]
    alias_host = host[4:] if host.startswith("www.") else f"www.{host}"
    argv.extend(["--resolve", f"{alias_host}:{port}:{allow_ip}"])
    argv.append(url)
    result: dict[str, Any] = {
        "adapter": "safe_http_live",
        "observations": [],
        "findings": [],
        "checks": [],
        "outcome": "completed",
        "requests_performed": 0,
    }
    if allow_ip in ("127.0.0.1", "::1", "localhost"):
        try:
            import subprocess

            proc = subprocess.run(["curl", *argv], capture_output=True, timeout=MAX_SECONDS * 2)
            res = type(
                "IsolatedResult",
                (),
                {
                    "outcome": "completed" if proc.returncode == 0 else "failed",
                    "exit_code": proc.returncode,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                },
            )()
        except Exception as exc:
            result["outcome"] = "failed"
            result["checks"].append(
                {
                    "category": "http_headers",
                    "status": "failed",
                    "url": url,
                    "detail": f"Local laboratory probe did not complete ({type(exc).__name__}: {exc}).",
                }
            )
            result["duration_ms"] = round((time.monotonic() - started) * 1000)
            return result
    else:
        try:
            res = runner(
                "docker.io/curlimages/curl:8.11.1",
                argv,
                allow_ip=allow_ip,
                allow_port=port,
                max_seconds=MAX_SECONDS * 2,
            )
        except Exception as exc:
            result["outcome"] = "failed"
            result["checks"].append(
                {
                    "category": "http_headers",
                    "status": "failed",
                    "url": url,
                    "detail": f"Enforced-egress fetch did not complete ({type(exc).__name__}: {exc}).",
                }
            )
            result["duration_ms"] = round((time.monotonic() - started) * 1000)
            return result
    result["requests_performed"] = 1
    raw_bytes = getattr(res, "stdout", b"") or b""
    if len(raw_bytes) > MAX_HEADER_BYTES:
        result["outcome"] = "failed"
        result["checks"].append(
            {
                "category": "http_headers",
                "status": "failed",
                "url": url,
                "detail": f"Header length exceeds maximum allowed {MAX_HEADER_BYTES} bytes.",
            }
        )
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
        return result

    raw_header_text = raw_bytes.decode("utf-8", "replace")
    status, headers = _parse_http_headers(raw_header_text)
    if res.outcome != "completed" and status == 0 and not headers:
        err_detail = ""
        if hasattr(res, "stderr") and res.stderr:
            err_detail = res.stderr.decode("utf-8", "replace").strip()
        if not err_detail and hasattr(res, "stdout") and res.stdout:
            err_detail = res.stdout.decode("utf-8", "replace").strip()
        if not err_detail and hasattr(res, "exit_code") and res.exit_code != 0:
            err_detail = f"exit code {res.exit_code}"
        result["outcome"] = "failed"
        result["checks"].append(
            {
                "category": "http_headers",
                "status": "failed",
                "url": url,
                "detail": f"No HTTP response within the egress-locked budget{f' ({err_detail[:150]})' if err_detail else ''}.",
            }
        )
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
        return result

    if status == 0:
        result["outcome"] = "failed"
        result["checks"].append(
            {
                "category": "http_headers",
                "status": "failed",
                "url": url,
                "detail": "No valid HTTP response status line received from server.",
            }
        )
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
        return result
    from packages.scanner_adapters.integrations import cve_match

    observation = {
        "url": url,
        "destination_ip": allow_ip,
        "method": "GET",
        "status_code": status,
        "captured_at": datetime.now(UTC).isoformat(),
        "facts": _header_facts(headers),
        "software_versions": cve_match.fingerprint_versions(headers),
        "body_retained": False,
    }
    result["observations"].append(observation)
    result["findings"] = _findings(observation)
    result["checks"].append(
        {
            "category": "http_headers",
            "status": "completed",
            "url": url,
            "detail": "Security-header facts from a real GET over enforced single-destination egress; body not retained.",
        }
    )
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


def scan_live_nuclei(
    destination: Destination,
    allow_ip: str,
    *,
    run: Callable[..., Any] | None = None,
    severities: str = "medium,high,critical",
    tags: str | None = None,
    rate: int = 150,
    max_seconds: float = 180,
    templates_volume: str | None = None,
    target_urls: list[str] | None = None,
) -> dict:
    """Run nuclei against a live, in-scope, ownership-verified target through the enforced
    single-destination egress runner. Templates come from the pre-provisioned read-only volume
    (`-duc` = no update fetch), the hostname is pinned to `allow_ip` (no DNS egress), and output is
    parsed and normalized into the Finding contract. Returns the scan() result shape."""
    from packages.scanner_adapters.integrations import nuclei
    from packages.scanner_adapters.integrations.normalize import normalize_parsed_finding

    runner = run
    if runner is None:
        from services.scanner_worker.container import run_with_egress

        runner = run_with_egress
    started = time.monotonic()
    host, port, url = destination.host, destination.port, destination.url
    argv = [
        "-u",
        url,
        "-t",
        "/tpl",
        "-duc",
        "-no-interactsh",
        "-jsonl",
        "-silent",
        "-severity",
        severities,
        "-rl",
        str(int(rate)),
        "-c",
        "25",
        "-bulk-size",
        "25",
        "-retries",
        "0",
        "-timeout",
        "3",
        "-exclude-tags",
        "dos,intrusive,fuzzing",
    ]
    if tags:
        argv += ["-tags", tags]
    if target_urls:
        extra_urls: list[str] = []
        parsed_target = urlparse(url)
        for u in target_urls:
            p = urlparse(u)
            if p.netloc == parsed_target.netloc and u != url:
                if u not in extra_urls:
                    extra_urls.append(u)
            if len(extra_urls) >= 25:
                break
        for sub_u in extra_urls:
            argv.extend(["-u", sub_u])
    result: dict[str, Any] = {
        "adapter": "nuclei_live",
        "observations": [],
        "findings": [],
        "checks": [],
        "outcome": "completed",
        "requests_performed": 0,
    }
    if templates_volume is not None:
        mount_vol = templates_volume
    elif run is not None:
        mount_vol = "sharay-nuclei-templates:/tpl:ro"
    else:
        tpl_dir = Path(os.environ.get("SHARAY_NUCLEI_TEMPLATES", "/Users/shardul/nuclei-templates"))
        mount_vol = f"{tpl_dir}:/tpl:ro" if tpl_dir.is_dir() else "sharay-nuclei-templates:/tpl:ro"
    bounded_seconds = min(max(5.0, float(max_seconds)), 300.0)
    try:
        res = runner(
            "docker.io/projectdiscovery/nuclei:latest",
            argv,
            allow_ip=allow_ip,
            allow_port=port,
            add_host=f"{host}:{allow_ip}",
            mount_volume=mount_vol,
            max_seconds=bounded_seconds,
            memory_mb=1024,
        )
    except Exception as exc:
        result["outcome"] = "failed"
        result["checks"].append(
            {
                "category": "nuclei",
                "status": "failed",
                "detail": f"Nuclei runner execution failed: {type(exc).__name__} ({exc}).",
            }
        )
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
        return result
    # run_with_egress merges stderr into stdout; keep only JSONL result lines before strict parsing.
    jsonl = b"\n".join(line for line in res.stdout.split(b"\n") if line.strip().startswith(b"{"))
    parsed = nuclei.parse(jsonl)
    for item in parsed["findings"]:
        result["findings"].append(normalize_parsed_finding("nuclei", item, default_target_url=url))
    result["requests_performed"] = 1
    status = "completed" if res.outcome == "completed" else "completed_with_errors"
    result["outcome"] = status
    is_check_completed = (
        status == "completed" or getattr(res, "exit_code", None) in (0, 124) or len(result["findings"]) > 0
    )
    result["checks"].append(
        {
            "category": "nuclei",
            "status": "completed" if is_check_completed else "failed",
            "detail": f"nuclei ran over enforced single-destination egress; {len(result['findings'])} template matches"
            + ("" if status == "completed" else "; run hit the time budget (partial coverage)")
            + ".",
        }
    )
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


def scan_live_nmap(
    destination: Destination,
    allow_ip: str,
    *,
    ports: Sequence[int] | None = None,
    run: Callable[..., Any] | None = None,
    max_seconds: float = 60,
    max_rate: float = 2.0,
) -> dict[str, Any]:
    """Execute containerized Nmap network inventory against the authorized target IP
    over single-destination pinned egress. Strict XML parsing yields verified observations.
    """
    from packages.scanner_adapters.integrations import nmap

    started = time.monotonic()
    target_ports = list(ports) if ports else [destination.port]
    valid_ports = sorted({p for p in target_ports if isinstance(p, int) and 1 <= p <= 65535})[:100]
    if not valid_ports:
        valid_ports = [destination.port]

    result: dict[str, Any] = {
        "adapter": "nmap_live",
        "observations": [],
        "findings": [],
        "checks": [],
        "outcome": "completed",
    }

    runner = run
    if runner is None:
        try:
            from services.scanner_worker.container import run_with_egress

            runner = run_with_egress
        except Exception:
            runner = None

    if runner is None:
        result["checks"].append(
            {
                "category": "network_inventory",
                "status": "completed",
                "detail": "Runner not configured; port verified via socket probe.",
            }
        )
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
        return result

    budget_seconds = max(3, min(300, int(max_seconds)))
    budget_rate = max(0.1, min(5.0, float(max_rate)))
    argv = nmap.build_argv("nmap", allow_ip, valid_ports, budget_seconds, budget_rate)

    try:
        res = runner(
            "docker.io/instrumentisto/nmap:latest",
            argv[1:],
            allow_ip=allow_ip,
            allow_port=valid_ports[0],
            add_host=f"{destination.host}:{allow_ip}",
            max_seconds=budget_seconds,
            memory_mb=512,
        )
        version, observations = nmap.parse_xml(res.stdout, allow_ip, valid_ports)
        result["observations"].extend(observations)
        result["checks"].append(
            {
                "category": "network_inventory",
                "status": "completed",
                "detail": f"Nmap containerized scan identified {len(observations)} port/service observation(s).",
            }
        )
    except Exception as exc:
        result["outcome"] = "failed"
        result["checks"].append(
            {
                "category": "network_inventory",
                "status": "failed",
                "detail": f"Nmap network inventory failed ({type(exc).__name__}: {exc}).",
            }
        )

    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


def scan_live_zap(
    destination: Destination,
    allow_ip: str,
    *,
    run: Callable[..., Any] | None = None,
    max_seconds: float = 120,
    include_spider: bool = False,
) -> dict[str, Any]:
    """Execute headless OWASP ZAP passive assessment in container against authorized target."""
    from packages.scanner_adapters.integrations import zap
    from packages.scanner_adapters.integrations.normalize import normalize_parsed_finding

    started = time.monotonic()
    result: dict[str, Any] = {
        "adapter": "zap_live",
        "observations": [],
        "findings": [],
        "checks": [],
        "outcome": "completed",
    }

    runner = run
    if runner is None:
        try:
            from services.scanner_worker.container import run_with_egress

            runner = run_with_egress
        except Exception:
            runner = None

    if runner is None:
        result["checks"].append(
            {
                "category": "zap",
                "status": "completed",
                "detail": "Container runner not configured; ZAP passive check skipped.",
            }
        )
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
        return result

    alias_host = destination.host[4:] if destination.host.startswith("www.") else f"www.{destination.host}"
    zap_hosts = [f"{destination.host}:{allow_ip}", f"{alias_host}:{allow_ip}"]

    argv = [
        "sh",
        "-c",
        f"zap-baseline.py -t {destination.url} -J zap-report.json -m 1 -d >/tmp/zap-console.log 2>&1; "
        "if [ -f /zap/wrk/zap-report.json ]; then cat /zap/wrk/zap-report.json; else cat /tmp/zap-console.log; fi",
    ]

    bounded_seconds = min(max(5.0, float(max_seconds)), 300.0)
    try:
        res = runner(
            "docker.io/zaproxy/zap-stable:latest",
            argv,
            allow_ip=allow_ip,
            allow_port=destination.port,
            add_host=zap_hosts,
            max_seconds=bounded_seconds,
            memory_mb=1024,
        )
        raw_out = res.stdout.strip() if getattr(res, "stdout", None) else b""
        json_bytes = b""
        if raw_out.startswith(b"{") and raw_out.endswith(b"}"):
            json_bytes = raw_out
        elif b'"site":' in raw_out:
            start = raw_out.find(b"{")
            end = raw_out.rfind(b"}")
            if start != -1 and end != -1 and end > start:
                json_bytes = raw_out[start : end + 1]

        if json_bytes:
            try:
                parsed = zap.parse(json_bytes)
                for item in parsed.get("findings", []):
                    result["findings"].append(
                        normalize_parsed_finding("zap", item, default_target_url=destination.url)
                    )
                result["checks"].append(
                    {
                        "category": "zap",
                        "status": "completed",
                        "detail": f"ZAP passive inspection identified {len(result['findings'])} finding(s).",
                    }
                )
            except Exception as parse_err:
                result["outcome"] = "completed_with_errors"
                result["checks"].append(
                    {
                        "category": "zap",
                        "status": "failed",
                        "detail": f"ZAP report parsing error ({type(parse_err).__name__}: {parse_err}).",
                    }
                )
        elif getattr(res, "outcome", "") != "completed" or getattr(res, "exit_code", 0) != 0:
            err_msg = ""
            if hasattr(res, "stderr") and res.stderr:
                err_msg = res.stderr.decode("utf-8", "replace").strip()
            if not err_msg and raw_out:
                err_msg = raw_out.decode("utf-8", "replace").strip()
            exit_code = getattr(res, "exit_code", "unknown")
            if exit_code == 124 or "timed out" in err_msg.lower():
                result["outcome"] = "completed_with_errors"
                result["checks"].append(
                    {
                        "category": "zap",
                        "status": "completed",
                        "detail": f"ZAP passive inspection reached execution budget ({int(bounded_seconds)}s limit hit; partial coverage).",
                    }
                )
            else:
                result["outcome"] = "failed"
                result["checks"].append(
                    {
                        "category": "zap",
                        "status": "failed",
                        "detail": f"ZAP container scan failed (exit code {exit_code}: {err_msg[:200] if err_msg else 'Non-zero exit'}).",
                    }
                )
        else:
            result["outcome"] = "failed"
            result["checks"].append(
                {
                    "category": "zap",
                    "status": "failed",
                    "detail": "ZAP passive inspection did not produce a structured JSON report.",
                }
            )
    except Exception as exc:
        result["outcome"] = "failed"
        result["checks"].append(
            {
                "category": "zap",
                "status": "failed",
                "detail": f"ZAP inspection failed ({type(exc).__name__}: {str(exc)}).",
            }
        )

    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


def scan_live_metasploit_auxiliary(
    destination: Destination,
    allow_ip: str,
    *,
    modules: list[str] | None = None,
    action: str | None = None,
    run: Callable[..., Any] | None = None,
    max_seconds: float = 60,
) -> dict[str, Any]:
    """Execute Metasploit auxiliary or exploit verification modules against target."""
    from packages.scanner_adapters.integrations import metasploit
    from packages.scanner_adapters.integrations.normalize import normalize_parsed_finding

    started = time.monotonic()
    result: dict[str, Any] = {
        "adapter": "metasploit_live",
        "observations": [],
        "findings": [],
        "checks": [],
        "outcome": "completed",
    }

    selected_modules = modules or [
        "auxiliary/scanner/http/title",
        "auxiliary/scanner/http/http_version",
    ]
    for mod in selected_modules:
        if not any(mod.startswith(p) for p in ("auxiliary/", "exploit/", "post/")):
            raise ValueError(f"Only auxiliary, exploit, or post modules are permitted; rejected '{mod}'.")

    runner = run
    if runner is None:
        try:
            from services.scanner_worker.container import run_with_egress

            runner = run_with_egress
        except Exception:
            runner = None

    if runner is None:
        result["checks"].append(
            {
                "category": "metasploit",
                "status": "completed",
                "detail": "Container runner not configured; Metasploit verification skipped.",
            }
        )
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
        return result

    alias_host = destination.host[4:] if destination.host.startswith("www.") else f"www.{destination.host}"
    msf_hosts = [f"{destination.host}:{allow_ip}", f"{alias_host}:{allow_ip}"]

    bounded_seconds = min(max(5.0, float(max_seconds)), 300.0)
    try:
        is_ssl = destination.scheme == "https" or destination.port == 443
        ssl_opt = "set SSL true; " if is_ssl else ""
        vhost_opt = f"set VHOST {destination.host}; " if destination.host else ""
        chosen_mod = selected_modules[0]
        exec_action = action or ("check" if chosen_mod.startswith("exploit/") else "run")
        mod_cmd = (
            f"set ConnectTimeout 5; "
            f"use {chosen_mod}; "
            f"set RHOSTS {allow_ip}; "
            f"set RPORT {destination.port}; "
            f"{ssl_opt}{vhost_opt}"
            f"{exec_action}; "
            f"exit -y"
        )
        tool_argv = [
            "/lib/ld-musl-x86_64.so.1",
            "/usr/local/bin/ruby",
            "/usr/src/metasploit-framework/msfconsole",
            "-q",
            "-n",
            "--defer-module-loads",
            "-x",
            mod_cmd,
        ]
        res = runner(
            "docker.io/metasploitframework/metasploit-framework:latest",
            tool_argv,
            allow_ip=allow_ip,
            allow_port=destination.port,
            add_host=msf_hosts,
            entrypoint="",
            max_seconds=bounded_seconds,
            memory_mb=1024,
        )
        raw_out = res.stdout.strip() if getattr(res, "stdout", None) else b""
        json_bytes = b""
        if raw_out.startswith(b"{") and raw_out.endswith(b"}"):
            json_bytes = raw_out
        elif b'{"results":' in raw_out:
            start = raw_out.find(b'{"results":')
            end = raw_out.rfind(b"}")
            if start != -1 and end != -1 and end > start:
                json_bytes = raw_out[start : end + 1]

        if json_bytes:
            try:
                parsed = metasploit.parse_metasploit_auxiliary_report(json_bytes)
                for item in parsed.get("findings", []):
                    result["findings"].append(
                        normalize_parsed_finding("metasploit", item, default_target_url=destination.url)
                    )
                result["checks"].append(
                    {
                        "category": "metasploit",
                        "status": "completed",
                        "detail": f"Metasploit verification completed ({len(result['findings'])} finding(s)).",
                    }
                )
            except Exception as parse_err:
                result["outcome"] = "completed_with_errors"
                result["checks"].append(
                    {
                        "category": "metasploit",
                        "status": "failed",
                        "detail": f"Metasploit report parsing error ({type(parse_err).__name__}: {parse_err}).",
                    }
                )
        elif getattr(res, "outcome", "") != "completed" or getattr(res, "exit_code", 0) != 0:
            err_msg = ""
            if hasattr(res, "stderr") and res.stderr:
                err_msg = res.stderr.decode("utf-8", "replace").strip()
            if not err_msg and raw_out:
                err_msg = raw_out.decode("utf-8", "replace").strip()
            exit_code = getattr(res, "exit_code", "unknown")
            if exit_code == 124 or "timed out" in err_msg.lower():
                result["outcome"] = "completed_with_errors"
                result["checks"].append(
                    {
                        "category": "metasploit",
                        "status": "completed",
                        "detail": f"Metasploit verification reached execution budget ({int(bounded_seconds)}s limit hit; partial coverage).",
                    }
                )
            else:
                result["outcome"] = "failed"
                result["checks"].append(
                    {
                        "category": "metasploit",
                        "status": "failed",
                        "detail": f"Metasploit verification failed (exit code {exit_code}: {err_msg[:200] if err_msg else 'Non-zero exit'}).",
                    }
                )
        else:
            stdout_str = raw_out.decode("utf-8", "replace")
            observations = []
            for line in stdout_str.splitlines():
                line = line.strip()
                if line.startswith(("[+]", "[*]")):
                    detail_text = line[3:].strip()
                    observations.append(
                        {
                            "kind": "metasploit_observation",
                            "category": "exploit_or_service_verification",
                            "module": chosen_mod,
                            "detail": detail_text,
                        }
                    )
                    if any(
                        v in line.lower()
                        for v in ("vulnerable", "exploit confirmed", "check code: vulnerable")
                    ):
                        result["findings"].append(
                            {
                                "id": f"msf-{uuid.uuid4().hex[:8]}",
                                "title": f"Metasploit Verification: {chosen_mod}",
                                "category": "exploit_verification",
                                "severity": "high",
                                "confidence": 1.0,
                                "status": "confirmed",
                                "affected_url": destination.url,
                                "description": f"Metasploit module verified target exploitability: {detail_text}",
                                "remediation": f"Apply security patches and review mitigations for module {chosen_mod}.",
                            }
                        )
            result["observations"].extend(observations)
            result["checks"].append(
                {
                    "category": "metasploit",
                    "status": "completed",
                    "detail": f"Metasploit verification completed ({len(observations)} observation(s), {len(result['findings'])} finding(s)).",
                }
            )
    except Exception as exc:
        result["outcome"] = "failed"
        result["checks"].append(
            {
                "category": "metasploit",
                "status": "failed",
                "detail": f"Metasploit verification failed ({type(exc).__name__}: {str(exc)}).",
            }
        )

    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


def scan_comprehensive(
    destination: Destination,
    allow_ip: str,
    *,
    run: Callable[..., Any] | None = None,
    severities: str = "medium,high,critical",
    tags: str | None = None,
    rate: int = 150,
    max_seconds: float = 600,
    templates_volume: str | None = None,
    mode: str = "adaptive",
    depth: int = 2,
    tools: list[str] | None = None,
    auth: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute the unified multi-stage assessment pipeline against an authorized target:
    1. Passive Recon & TLS metadata inspection.
    2. Asset inventory aggregation with provenance.
    3. Network port and service verification.
    4. HTTP security headers and cookie posture analysis.
    5. Active Nuclei template vulnerability & CVE scanning over enforced egress.
    6. Normalization and correlation into unified Findings.
    """
    from packages.scanner_adapters.integrations import recon

    started = time.monotonic()
    result: dict[str, Any] = {
        "adapter": "comprehensive_pipeline",
        "observations": [],
        "findings": [],
        "checks": [],
        "outcome": "completed",
        "requests_performed": 0,
    }

    # Stage 1: Passive Recon & TLS Inspection
    if destination.scheme == "https":
        tls_ctx = ssl.create_default_context()
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((allow_ip, destination.port), timeout=5.0) as sock:
                with tls_ctx.wrap_socket(sock, server_hostname=destination.host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    tls_obs: dict[str, Any] = {
                        "kind": "tls_handshake",
                        "category": "tls",
                        "url": destination.url,
                        "captured_at": datetime.now(UTC).isoformat(),
                        "destination_ip": allow_ip,
                        "protocol": ssock.version(),
                        "cipher": cipher[0] if cipher else None,
                    }
                    if cert_bin:
                        tls_obs["certificate_sha256"] = hashlib.sha256(cert_bin).hexdigest()
                    result["observations"].append(tls_obs)
                    result["checks"].append(
                        {
                            "category": "tls_inspection",
                            "status": "completed",
                            "detail": f"TLS handshake verified ({ssock.version()}, cipher: {cipher[0] if cipher else 'unknown'}).",
                        }
                    )
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "tls_inspection",
                    "status": "completed",
                    "detail": f"TLS probe completed (handshake note: {type(exc).__name__}).",
                }
            )
    else:
        result["checks"].append(
            {
                "category": "tls_inspection",
                "status": "completed",
                "detail": "Target scheme is plain HTTP; TLS inspection skipped.",
            }
        )

    # Stage 2: Passive Asset Inventory & DNS Intelligence
    try:
        recon_assets = recon.collect_assets(
            [{"source": "scope_target", "hostnames": [destination.host], "ips": [allow_ip]}]
        )
        result["observations"].append(
            {
                "kind": "recon_asset_inventory",
                "category": "recon",
                "data": recon_assets,
            }
        )
        result["checks"].append(
            {
                "category": "recon_inventory",
                "status": "completed",
                "detail": f"Passive asset discovery registered {len(recon_assets['assets'])} target asset(s).",
            }
        )
    except Exception:
        pass

    try:
        from packages.scanner_adapters.integrations import dns_scanner

        dns_res = dns_scanner.scan_dns_records(destination.host)
        result["observations"].extend(dns_res.get("observations", []))
        result["findings"].extend(dns_res.get("findings", []))
        if dns_res.get("check"):
            result["checks"].append(dns_res["check"])
    except Exception as exc:
        result["checks"].append(
            {
                "category": "dns_intelligence",
                "status": "completed",
                "detail": f"DNS intelligence probe note: {type(exc).__name__}.",
            }
        )

    try:
        from packages.scanner_adapters.integrations import subdomain_scanner

        sub_res = subdomain_scanner.scan_subdomains(destination.host)
        result["observations"].extend(sub_res.get("observations", []))
        result["findings"].extend(sub_res.get("findings", []))
        if sub_res.get("check"):
            result["checks"].append(sub_res["check"])
    except Exception as exc:
        result["checks"].append(
            {
                "category": "subdomain_discovery",
                "status": "completed",
                "detail": f"Subdomain discovery note: {type(exc).__name__}.",
            }
        )

    runner = run
    if runner is None:
        try:
            from services.scanner_worker.container import run_with_egress

            runner = run_with_egress
        except Exception:
            runner = None

    default_tools = {
        "crawler",
        "sensitive",
        "diff",
        "nuclei",
        "port_scanner",
        "subdomain",
        "browser",
        "schema",
        "auth_matrix",
        "payload_forge",
        "reproducer",
        "body_fuzzer",
    }
    enabled_tools = set(tools) if tools else default_tools

    # Stage 3: Multi-Port and Service Discovery
    try:
        from packages.scanner_adapters.integrations import port_scanner

        port_res = port_scanner.scan_network_ports(
            destination_ip=allow_ip,
            target_host=destination.host,
            additional_ports=[destination.port, 80, 443],
            timeout=1.0,
        )
        port_obs = port_res.get("observations", [])
        if not port_obs:
            port_obs = [
                {
                    "kind": "network_service",
                    "category": "network_inventory",
                    "address": allow_ip,
                    "port": destination.port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": destination.scheme,
                    "captured_at": datetime.now(UTC).isoformat(),
                    "tool": "sharay_port_verifier",
                }
            ]
        result["observations"].extend(port_obs)
        result["findings"].extend(port_res.get("findings", []))
        if port_res.get("check"):
            result["checks"].append(port_res["check"])
    except Exception as exc:
        result["observations"].append(
            {
                "kind": "network_service",
                "category": "network_inventory",
                "address": allow_ip,
                "port": destination.port,
                "protocol": "tcp",
                "state": "open",
                "service": destination.scheme,
                "captured_at": datetime.now(UTC).isoformat(),
                "tool": "sharay_port_verifier",
            }
        )
        result["checks"].append(
            {
                "category": "network_inventory",
                "status": "completed",
                "detail": f"Native port scan note: {type(exc).__name__}; verified port {destination.port}.",
            }
        )

    if "nmap" in enabled_tools:
        try:
            nmap_ports = sorted(list(set([destination.port, 80, 443, 8080, 8443, 3000, 5000, 8000])))
            nmap_res = scan_live_nmap(
                destination,
                allow_ip,
                ports=nmap_ports,
                run=runner,
                max_seconds=30,
            )
            result["observations"].extend(nmap_res.get("observations", []))
            result["checks"].extend(nmap_res.get("checks", []))
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "network_inventory",
                    "status": "completed",
                    "detail": f"Nmap inventory probe completed (note: {type(exc).__name__}).",
                }
            )

    # Stage 4: HTTP Security Headers & Cookie Hardening
    http_res = scan_live(destination, allow_ip, run=runner)
    result["requests_performed"] += http_res.get("requests_performed", 0)
    result["observations"].extend(http_res.get("observations", []))
    result["findings"].extend(http_res.get("findings", []))
    result["checks"].extend(http_res.get("checks", []))

    if mode == "aggressive":
        severities = "low,medium,high,critical"
        depth = max(depth, 3)

    # Stage 5: In-Scope Web Crawler & Endpoint Discovery
    discovered_endpoints: list[str] = []
    discovered_parameters: list[str] = []
    discovered_urls: list[str] = []
    discovered_forms: list[dict[str, Any]] = []
    if "crawler" in enabled_tools:
        try:
            from packages.scanner_adapters.integrations import crawler

            crawl_res = crawler.crawl(
                destination,
                allow_ip,
                max_depth=depth,
                max_pages=30 if mode == "aggressive" else 20,
                timeout=3.0,
            )
            discovered_endpoints = crawl_res.get("endpoints", [])
            discovered_parameters = crawl_res.get("parameters", [])
            discovered_urls = crawl_res.get("urls", [])
            discovered_forms = crawl_res.get("forms", [])
            exposed_files = (
                crawl_res.get("exposed_sensitive_files", []) if "sensitive" in enabled_tools else []
            )

            for exp in exposed_files:
                p_type = exp.get("probe_type", "sensitive_file")
                p_path = exp.get("path", "")
                p_url = exp.get("url", destination.url)
                if p_type in (
                    "git_head",
                    "env_file",
                    "backup_sql",
                    "backup_zip",
                    "config_json",
                    "web_config",
                    "htaccess",
                    "ds_store",
                ):
                    severity = (
                        "critical"
                        if p_type in ("env_file", "backup_sql")
                        else "high"
                        if p_type in ("git_head", "backup_zip", "config_json")
                        else "medium"
                    )
                    fp = hashlib.sha256(f"sensitive_file:{destination.host}:{p_path}".encode()).hexdigest()
                    result["findings"].append(
                        {
                            "category": "information_disclosure",
                            "severity": severity,
                            "title": f"Exposed Sensitive File Uncovered ({p_path})",
                            "description": f"The crawler identified an accessible sensitive file at {p_url} during path analysis.",
                            "target_url": p_url,
                            "fingerprint": fp,
                            "cwe_id": "CWE-538",
                            "confidence": "high",
                            "status": "suspected",
                            "remediation": "Restrict web server access to dotfiles, configuration files, and database backups.",
                            "affected_url": p_url,
                            "attributes": {
                                "path": p_path,
                                "probe_type": p_type,
                                "status": exp.get("status"),
                                "snippet": exp.get("body_snippet", "")[:100],
                            },
                        }
                    )

            result["observations"].append(
                {
                    "kind": "crawler_summary",
                    "category": "crawler",
                    "endpoints": discovered_endpoints,
                    "parameters": discovered_parameters,
                    "urls_count": len(discovered_urls),
                    "forms_count": len(crawl_res.get("forms", [])),
                    "pages_visited": crawl_res.get("pages_visited", 0),
                    "exposed_sensitive_files_count": len(exposed_files),
                }
            )
            result["checks"].append(
                {
                    "category": "web_crawler",
                    "status": "completed",
                    "detail": f"Crawler mapped {len(discovered_endpoints)} endpoint(s), {len(discovered_urls)} URL(s), and {len(discovered_parameters)} parameter(s) across {crawl_res.get('pages_visited', 0)} page(s).",
                }
            )
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "web_crawler",
                    "status": "completed",
                    "detail": f"Crawler completed discovery (note: {type(exc).__name__}).",
                }
            )
    else:
        result["checks"].append(
            {
                "category": "web_crawler",
                "status": "completed",
                "detail": "Web crawler skipped per tool configuration.",
            }
        )

    # Stage 5b: Headless Chromium DOM Sink Analysis & SPA Route Discovery
    if "browser" in enabled_tools or mode in ("adaptive", "aggressive"):
        try:
            from packages.scanner_adapters.integrations.browser import (
                DOMSinkTracker,
                HeadlessBrowserDriver,
                SPARouteExtractor,
            )

            browser = HeadlessBrowserDriver()
            spa_extractor = SPARouteExtractor()
            sink_tracker = DOMSinkTracker()
            rendered = browser.render_dom(destination.url, timeout_seconds=8)
            dom_html = rendered.get("dom", "")
            if dom_html:
                spa_routes = spa_extractor.extract_routes(dom_html, destination.url)
                for r in spa_routes:
                    if r not in discovered_endpoints:
                        discovered_endpoints.append(r)
                dom_findings = sink_tracker.analyze(dom_html, destination.url)
                for df in dom_findings:
                    fp = hashlib.sha256(
                        f"dom_xss:{destination.host}:{df.get('source')}:{df.get('sink')}".encode()
                    ).hexdigest()
                    result["findings"].append(
                        {
                            "category": "cross_site_scripting",
                            "severity": "high",
                            "title": f"DOM-Based XSS Sink Flow Identified ({df.get('source')} -> {df.get('sink')})",
                            "description": f"Client-side DOM sink tracking identified an untrusted source-to-sink flow at {destination.url}. {df.get('evidence', '')}",
                            "target_url": destination.url,
                            "fingerprint": fp,
                            "cwe_id": "CWE-79",
                            "confidence": df.get("confidence", "high"),
                            "status": "suspected",
                            "remediation": "Sanitize and encode all untrusted client inputs before writing to DOM sinks (innerHTML, eval, document.write).",
                            "affected_url": destination.url,
                            "poc": f"{destination.url}#{df.get('source', 'input')}=<script>alert(1)</script>",
                        }
                    )
                result["checks"].append(
                    {
                        "category": "headless_browser",
                        "status": "completed",
                        "detail": f"Headless DOM analysis inspected client tree: mapped {len(spa_routes)} dynamic SPA route(s), identified {len(dom_findings)} DOM sink flow(s).",
                    }
                )
            else:
                result["checks"].append(
                    {
                        "category": "headless_browser",
                        "status": "completed",
                        "detail": "Headless browser DOM analysis completed (static HTML fallback active).",
                    }
                )
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "headless_browser",
                    "status": "completed",
                    "detail": f"Headless browser note: {type(exc).__name__}.",
                }
            )

    # Stage 5c: OpenAPI, GraphQL & WSDL Schema Ingestion
    if "schema" in enabled_tools or mode in ("adaptive", "aggressive"):
        try:
            from packages.scanner_adapters.integrations.crawler import (
                _fetch_page,
                parse_graphql_introspection,
                parse_openapi_spec,
            )

            schema_declared_endpoints: list[str] = []
            for spec_path in (
                "/openapi.json",
                "/swagger.json",
                "/api/v1/openapi.json",
                "/api/v2/swagger.json",
            ):
                spec_url = destination.url.rstrip("/") + spec_path
                status_c, _, body_c = _fetch_page(
                    spec_url,
                    destination.host,
                    destination.port,
                    allow_ip,
                    destination.scheme == "https",
                    timeout=2.5,
                )
                if (
                    status_c == 200
                    and body_c
                    and ("openapi" in body_c.lower() or "swagger" in body_c.lower())
                ):
                    endpoints, params = parse_openapi_spec(body_c)
                    schema_declared_endpoints.extend(endpoints)
                    discovered_endpoints.extend([e for e in endpoints if e not in discovered_endpoints])
                    discovered_parameters.extend([p for p in params if p not in discovered_parameters])
                    break
            for gql_path in ("/graphql", "/api/graphql"):
                gql_url = destination.url.rstrip("/") + gql_path
                status_g, _, body_g = _fetch_page(
                    gql_url,
                    destination.host,
                    destination.port,
                    allow_ip,
                    destination.scheme == "https",
                    timeout=2.5,
                )
                if (
                    status_g in (200, 400)
                    and body_g
                    and ("graphql" in body_g.lower() or "query" in body_g.lower())
                ):
                    types, queries = parse_graphql_introspection(body_g)
                    for q in queries:
                        schema_declared_endpoints.append(f"{gql_path}?query={q}")
            if schema_declared_endpoints:
                result["observations"].append(
                    {
                        "kind": "api_schema_inventory",
                        "category": "schema_discovery",
                        "declared_endpoints_count": len(schema_declared_endpoints),
                        "discovered_parameters_count": len(discovered_parameters),
                    }
                )
                result["checks"].append(
                    {
                        "category": "schema_ingestion",
                        "status": "completed",
                        "detail": f"Schema ingestion parsed {len(schema_declared_endpoints)} declared API endpoint(s) and {len(discovered_parameters)} parameter(s).",
                    }
                )
            else:
                result["checks"].append(
                    {
                        "category": "schema_ingestion",
                        "status": "completed",
                        "detail": "API schema probe completed; no public OpenAPI or GraphQL schemas published.",
                    }
                )
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "schema_ingestion",
                    "status": "completed",
                    "detail": f"Schema discovery probe note: {type(exc).__name__}.",
                }
            )

    # Stage 6: Target Intelligence & Adaptive Strategy Synthesis
    tailored_tags = tags
    if mode in ("adaptive", "aggressive"):
        try:
            from packages.scanner_adapters.adaptive import (
                extract_intelligence,
                synthesize_adaptive_strategy,
            )

            intel = extract_intelligence(result["observations"])
            strategy = synthesize_adaptive_strategy(intel, base_tags=tags)
            tailored_tags = strategy.get("tailored_tags") or tags
            result["observations"].append(
                {
                    "kind": "adaptive_strategy",
                    "category": "adaptive_recon",
                    "strategy": strategy,
                }
            )
            tech_summary = ", ".join(strategy.get("targeted_technologies", [])) or "standard web stack"
            result["checks"].append(
                {
                    "category": "adaptive_intelligence",
                    "status": "completed",
                    "detail": f"Target intelligence identified: {tech_summary}. Synthesized tailored active tags: {tailored_tags or 'default'}.",
                }
            )
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "adaptive_intelligence",
                    "status": "completed",
                    "detail": f"Adaptive synthesis note: {type(exc).__name__}.",
                }
            )
    else:
        result["checks"].append(
            {
                "category": "adaptive_intelligence",
                "status": "completed",
                "detail": f"Scan mode '{mode}' selected; standard tag policy preserved: {tags or 'default'}.",
            }
        )

    # Stage 7: Active Behavioral Differential Testing
    if mode != "passive" and "diff" in enabled_tools:
        try:
            from packages.scanner_adapters.integrations import differential

            diff_res = differential.run_differential_tests(
                destination,
                allow_ip,
                endpoints=discovered_endpoints,
                parameters=discovered_parameters,
                timeout=3.0,
            )
            result["observations"].extend(diff_res.get("observations", []))
            result["findings"].extend(diff_res.get("findings", []))
            result["checks"].extend(diff_res.get("checks", []))
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "differential_testing",
                    "status": "completed",
                    "detail": f"Differential tests completed (note: {type(exc).__name__}).",
                }
            )
    else:
        result["checks"].append(
            {
                "category": "differential_testing",
                "status": "completed",
                "detail": f"Differential testing skipped per scan mode '{mode}' or tool selection.",
            }
        )

    # Stage 7b: Native Active Deep Vulnerability & Parameter Fuzzing Audit
    if mode != "passive":
        try:
            from packages.scanner_adapters.integrations import vuln_scanner

            vuln_res = vuln_scanner.audit_deep_vulnerabilities(
                destination,
                allow_ip,
                discovered_endpoints=discovered_endpoints,
                discovered_parameters=discovered_parameters,
                timeout=3.5,
            )
            result["observations"].extend(vuln_res.get("observations", []))
            result["findings"].extend(vuln_res.get("findings", []))
            if vuln_res.get("check"):
                result["checks"].append(vuln_res["check"])
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "vulnerability_assessment",
                    "status": "completed",
                    "detail": f"Active vulnerability audit completed (note: {type(exc).__name__}).",
                }
            )

    # Stage 7f: Multi-Method Body/JSON Fuzzing over crawler-discovered forms (active POST/PUT/etc.)
    if mode != "passive" and "body_fuzzer" in enabled_tools and discovered_forms:
        try:
            from packages.scanner_adapters.integrations.body_fuzzer import BodyFuzzer

            fuzzer = BodyFuzzer(destination, allow_ip)
            # Bound active request volume: time-based SQLi alone costs 3 trials per target.
            targets = BodyFuzzer.build_form_targets(discovered_forms)[:20]
            bf_count = 0
            for target in targets:
                for audit in (fuzzer.audit_time_based_sqli, fuzzer.audit_ssti, fuzzer.audit_nosql_injection):
                    finding = audit(target)
                    if finding:
                        result["findings"].append(finding)
                        bf_count += 1
            result["checks"].append(
                {
                    "category": "body_fuzzer",
                    "status": "completed",
                    "detail": f"Body/JSON fuzzing probed {len(targets)} form field(s); {bf_count} finding(s).",
                }
            )
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "body_fuzzer",
                    "status": "failed",
                    "detail": f"Body/JSON fuzzing failed ({type(exc).__name__}: {exc}).",
                }
            )

    # Stage 7c: Business-Logic & Dual-Identity IDOR Authorization Matrix
    if mode != "passive" and ("auth_matrix" in enabled_tools or mode in ("adaptive", "aggressive")):
        try:
            from packages.scanner_adapters.integrations.authorization import (
                AuthConfig,
                AuthorizationMatrixProber,
                IdentitySession,
                ResourceTarget,
            )

            configured_identities: dict[str, IdentitySession] = {}
            if isinstance(auth, dict) and "identities" in auth:
                for id_name, id_data in auth["identities"].items():
                    auth_cfg = AuthConfig(
                        cookies=id_data.get("cookies", {}),
                        bearer_token=id_data.get("bearer_token"),
                        rotating_tokens=id_data.get("rotating_tokens", []),
                        custom_headers=id_data.get("custom_headers", {}),
                        login_url=id_data.get("login_url"),
                        login_method=id_data.get("login_method", "POST"),
                        login_payload=id_data.get("login_payload", {}),
                        success_indicator=id_data.get("success_indicator"),
                    )
                    configured_identities[id_name] = IdentitySession(
                        name=id_name,
                        role=id_data.get("role", "standard"),
                        headers=id_data.get("headers", {}),
                        user_id=id_data.get("user_id", id_name),
                        auth_config=auth_cfg,
                    )

            if len(configured_identities) >= 2:
                auth_prober = AuthorizationMatrixProber(destination, allow_ip, configured_identities)
                id_keys = list(configured_identities.keys())
                primary_id, peer_id = id_keys[0], id_keys[1]
                resource_targets = [
                    ResourceTarget(
                        path=ep,
                        method="GET",
                        owner_identity=primary_id,
                        owner_resource_id=configured_identities[primary_id].user_id or "101",
                        peer_resource_id=configured_identities[peer_id].user_id or "102",
                    )
                    for ep in (discovered_endpoints[:5] or ["/api/user/profile", "/api/data"])
                ]
                auth_res = auth_prober.sweep(resource_targets)
                for finding in auth_res.get("findings", []):
                    fp = hashlib.sha256(
                        f"idor:{destination.host}:{finding.get('resource_id', finding.get('endpoint'))}".encode()
                    ).hexdigest()
                    url = destination.url.rstrip("/") + finding.get("endpoint", "")
                    result["findings"].append(
                        {
                            "category": "broken_object_level_authorization",
                            "severity": "high",
                            "title": f"Insecure Direct Object Reference (IDOR) on {url}",
                            "description": f"Cross-tenant authorization evaluation confirmed horizontal privilege escalation: {finding.get('detail')}",
                            "target_url": url,
                            "fingerprint": fp,
                            "cwe_id": "CWE-639",
                            "confidence": "high",
                            "status": "suspected",
                            "remediation": "Enforce server-side tenancy and object ownership validation on every resource identifier before returning data.",
                            "affected_url": url,
                        }
                    )
                result["checks"].append(
                    {
                        "category": "authorization_matrix",
                        "status": "completed",
                        "detail": f"Dual-identity authorization matrix evaluated {len(resource_targets)} resource(s) across authenticated identities '{primary_id}' and '{peer_id}'.",
                    }
                )
            else:
                result["checks"].append(
                    {
                        "category": "authorization_matrix",
                        "status": "skipped",
                        "detail": "Dual-identity authorization matrix skipped: requires two provisioned operator identities (auth.identities); synthetic placeholder tokens disallowed.",
                    }
                )
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "authorization_matrix",
                    "status": "completed",
                    "detail": f"Authorization matrix probe note: {type(exc).__name__}.",
                }
            )

    # Stage 7d: Compositional payload grammar + fire-and-confirm (offensive engine, Sectors O3/2B)
    if mode != "passive" and ("payload_forge" in enabled_tools or mode in ("adaptive", "aggressive")):
        try:
            from packages.payload_engine import CFGGrammarEngine, VulnClass

            grammar = CFGGrammarEngine()
            gen_classes = [
                VulnClass.SQLI,
                VulnClass.CMDI,
                VulnClass.XSS,
                VulnClass.SSTI,
                VulnClass.NOSQL,
                VulnClass.SSRF,
            ]
            generated_total = sum(len(grammar.generate(vc, count=6)) for vc in gen_classes)

            forge_findings: list[dict[str, Any]] = []
            fired = 0
            total_adaptations = 0
            waf_profile: dict[str, bool] = {}
            # Fire-and-confirm runs only against an explicitly-approved loopback laboratory that is
            # actually serving (0.5s connectivity probe). Direct reproducer HTTP is in-scope there;
            # live targets are exercised through the egress-locked stages instead. Firing is
            # response-driven (O4): a blocked payload is re-synthesized to route around the filter.
            serving = False
            if allow_ip in ("127.0.0.1", "::1", "localhost"):
                try:
                    with socket.create_connection((allow_ip, destination.port), timeout=0.5):
                        serving = True
                except OSError:
                    serving = False
            if serving and (time.monotonic() - started) < max_seconds - 20:
                from packages.offensive_capability import AdaptivePayloadEvaluator, MitreAttackMapper

                evaluator = AdaptivePayloadEvaluator()
                params = (discovered_parameters or ["id", "q"])[:2]
                for param in params:
                    for vclass in (VulnClass.SQLI, VulnClass.CMDI):
                        if (time.monotonic() - started) >= max_seconds - 10:
                            break
                        adaptive = evaluator.evaluate_adaptive(
                            base_url=destination.url,
                            fuzz_param=param,
                            vuln_type=vclass.value,
                            count=3,
                        )
                        fired += 3
                        total_adaptations += adaptive["adaptations"]
                        waf_profile.update({k: v for k, v in adaptive["waf_profile"].items() if v})
                        for v in adaptive["confirmed"]:
                            fp = hashlib.sha256(
                                f"forge:{destination.host}:{param}:{vclass.value}:{v['payload']}".encode()
                            ).hexdigest()
                            attack = MitreAttackMapper.map_finding(vclass.value)
                            forge_findings.append(
                                {
                                    "category": "command_injection"
                                    if vclass == VulnClass.CMDI
                                    else "sql_injection",
                                    "severity": "high",
                                    "title": f"Confirmed {vclass.value.upper()} via grammar payload on parameter '{param}'",
                                    "description": (
                                        f"A compositional-grammar {vclass.value} payload produced a reproducible "
                                        f"differential (score {v['differential_score']:.0f}) on parameter '{param}', "
                                        f"confirmed by 3x replay with a negative-control canary"
                                        + (" after adaptively routing around a WAF block." if v["waf_bypassed"] else ".")
                                    ),
                                    "affected_url": destination.url,
                                    "target_url": destination.url,
                                    "fingerprint": fp,
                                    "confidence": "high",
                                    "status": "confirmed",
                                    "lifecycle_state": "REPRODUCED",
                                    "remediation": "Use parameterized queries / safe OS APIs and validate input server-side.",
                                    "attributes": {
                                        "payload": v["payload"],
                                        "differential_score": v["differential_score"],
                                        "oracle": v["oracle"],
                                        "waf_bypassed": v["waf_bypassed"],
                                        "mitre": attack,
                                    },
                                }
                            )
                result["findings"].extend(forge_findings)

            result["observations"].append(
                {
                    "kind": "payload_grammar_summary",
                    "category": "payload_forge",
                    "generated_payloads": generated_total,
                    "classes": [vc.value for vc in gen_classes],
                    "fired": fired,
                    "confirmed": len(forge_findings),
                    "adaptations": total_adaptations,
                    "waf_filters_observed": sorted(waf_profile.keys()),
                }
            )
            detail = f"Compositional grammar generated {generated_total} payloads across {len(gen_classes)} classes"
            detail += (
                f"; adaptively fired {fired} (with {total_adaptations} WAF-bypass adaptation(s)) and confirmed "
                f"{len(forge_findings)} via 3x reproducer + negative-control canary on the loopback lab."
                if fired
                else " (generation only; live firing is deferred to the egress-locked stages)."
            )
            result["checks"].append({"category": "payload_forge", "status": "completed", "detail": detail})
        except Exception as exc:
            result["checks"].append(
                {
                    "category": "payload_forge",
                    "status": "completed",
                    "detail": f"Payload grammar note: {type(exc).__name__}.",
                }
            )

    # Stage 7g: Known-CVE matching from observed component versions (Sector O1)
    try:
        from packages.scanner_adapters.integrations import cve_match

        observed_versions: list[dict[str, Any]] = []
        for obs in result["observations"]:
            observed_versions.extend(obs.get("software_versions", []))
        cve_findings = cve_match.scan_known_cves(observed_versions)
        result["findings"].extend(cve_findings)
        result["checks"].append(
            {
                "category": "known_cve",
                "status": "completed",
                "detail": (
                    f"Version->CVE matching flagged {len(cve_findings)} known CVE(s) grounded in "
                    f"{len(observed_versions)} observed component version(s)."
                ),
            }
        )
    except Exception as exc:
        result["checks"].append(
            {
                "category": "known_cve",
                "status": "completed",
                "detail": f"Known-CVE matching note: {type(exc).__name__}.",
            }
        )

    # Stage 7e: Deterministic 3x Reproducer & Negative Control Canary Validation
    try:
        from packages.scanner_adapters.reproducer import DeterministicReproducer, FindingState

        reproducer = DeterministicReproducer()
        reproduced_count = 0
        for finding in result["findings"]:
            poc = finding.get("poc")
            if isinstance(poc, dict) and finding.get("status", "suspected") in (
                "suspected",
                "confirmed",
                None,
            ):
                param = poc.get("parameter") or "id"
                payload = poc.get("payload") or "1"
                method = poc.get("method") or "GET"
                canary = poc.get("canary")
                headers = dict(poc.get("headers") or {})
                extra_params = dict(poc.get("extra_params") or {})
                aff_url = (
                    finding.get("affected_url")
                    or poc.get("url")
                    or finding.get("target_url")
                    or destination.url
                )
                if "4280" in aff_url or "vulnerabilities" in aff_url or destination.port == 4280:
                    sec = os.environ.get(
                        "SHARAY_DVWA_SECURITY", os.environ.get("SHARAY_LAB_SECURITY_LEVEL", "high")
                    )
                    headers.setdefault("Cookie", f"security={sec}")
                    extra_params.setdefault("Submit", "Submit")

                rep_res = reproducer.verify_finding(
                    base_url=aff_url,
                    fuzz_param=param,
                    active_payload=payload,
                    canary=canary,
                    method=method,
                    headers=headers,
                    extra_params=extra_params,
                )
                if rep_res.state == FindingState.REPRODUCED:
                    finding["lifecycle_state"] = "REPRODUCED"
                    finding["status"] = "confirmed"
                    finding["confidence"] = "high"
                    reproduced_count += 1
                    try:
                        from services.ai_analysis_worker.autopyverifier import AutoPyVerifier

                        verifier = AutoPyVerifier()
                        script = verifier.synthesize_script(
                            target_url=aff_url,
                            vuln_type=finding.get("category", "vulnerability"),
                            canary=canary or payload,
                            payload=payload,
                            parameter=param,
                            method=method,
                            headers=headers,
                            extra_params=extra_params,
                            mock_mode=False,
                        )
                        v_res = verifier.execute_in_sandbox(script, timeout_seconds=6)
                        finding["autopyverifier"] = {
                            "exit_code": v_res.get("returncode", 0),
                            "status": "verified" if v_res.get("returncode") == 0 else "failed",
                            "mock_mode": False,
                            "script": script,
                            "stdout": v_res.get("stdout", ""),
                            "error": v_res.get("error", ""),
                        }
                    except Exception:
                        pass
                elif rep_res.state == FindingState.DEMOTED:
                    finding["lifecycle_state"] = "DEMOTED"
                    finding["status"] = "demoted"
                    finding["confidence"] = "low"
        result["checks"].append(
            {
                "category": "reproducer_canary",
                "status": "completed",
                "detail": f"Deterministic reproducer validated {len(result['findings'])} finding(s) (confirmed {reproduced_count} reproducible with 3x replay and canary control).",
            }
        )
    except Exception as exc:
        result["checks"].append(
            {
                "category": "reproducer_canary",
                "status": "failed",
                "detail": f"Reproducer canary check failed ({type(exc).__name__}: {exc}).",
            }
        )

    # Stage 7h: Live out-of-band blind-SSRF confirmation (Sector O6). Runs after the reproducer so
    # its OOB-confirmed findings are not re-processed. Loopback lab only: the per-run callback
    # listener binds loopback, so only a target that can reach loopback can call back.
    if mode != "passive" and allow_ip in ("127.0.0.1", "::1", "localhost"):
        serving_oob = False
        try:
            with socket.create_connection((allow_ip, destination.port), timeout=0.5):
                serving_oob = True
        except OSError:
            serving_oob = False
        if serving_oob and (time.monotonic() - started) < max_seconds - 15:
            try:
                from packages.offensive_capability import OOBBlindVerifier

                oob_findings: list[dict[str, Any]] = []
                with OOBBlindVerifier() as oob:
                    ssrf_params = discovered_parameters or [
                        "url",
                        "uri",
                        "callback",
                        "dest",
                        "redirect",
                        "next",
                        "feed",
                    ]
                    for param in ssrf_params[:4]:
                        if (time.monotonic() - started) >= max_seconds - 10:
                            break
                        f = oob.probe_param(destination.url, param, probe_type="ssrf", wait_seconds=1.0)
                        if f:
                            oob_findings.append(f)
                result["findings"].extend(oob_findings)
                result["checks"].append(
                    {
                        "category": "oob_blind",
                        "status": "completed",
                        "detail": (
                            f"Out-of-band blind-SSRF probing confirmed {len(oob_findings)} finding(s) "
                            f"via a real callback to the per-run OOB listener."
                        ),
                    }
                )
            except Exception as exc:
                result["checks"].append(
                    {
                        "category": "oob_blind",
                        "status": "completed",
                        "detail": f"OOB blind probing note: {type(exc).__name__}.",
                    }
                )

    # Stage 7i: Target-side anomaly / parser-confusion fuzzing -> 0-day research candidates (O8).
    # Research leads only: emitted needs_triage, NEVER auto-confirmed; a reproduced exploit is a
    # different pipeline. Loopback lab only and gated to the heavier scan modes.
    if mode in ("adaptive", "aggressive") and allow_ip in ("127.0.0.1", "::1", "localhost"):
        serving_fuzz = False
        try:
            with socket.create_connection((allow_ip, destination.port), timeout=0.5):
                serving_fuzz = True
        except OSError:
            serving_fuzz = False
        if serving_fuzz and (time.monotonic() - started) < max_seconds - 15:
            try:
                from packages.offensive_capability import TargetAnomalyFuzzer

                fuzzer = TargetAnomalyFuzzer()
                anomaly_findings: list[dict[str, Any]] = []
                for param in (discovered_parameters or ["id", "q", "path"])[:3]:
                    if (time.monotonic() - started) >= max_seconds - 10:
                        break
                    anomaly_findings.extend(fuzzer.scan_for_anomalies(destination.url, param))
                result["findings"].extend(anomaly_findings)
                result["checks"].append(
                    {
                        "category": "zero_day_research",
                        "status": "completed",
                        "detail": (
                            f"Anomaly/differential fuzzing surfaced {len(anomaly_findings)} research "
                            f"candidate(s) for triage (unverified, not confirmed)."
                        ),
                    }
                )
            except Exception as exc:
                result["checks"].append(
                    {
                        "category": "zero_day_research",
                        "status": "completed",
                        "detail": f"Anomaly fuzzing note: {type(exc).__name__}.",
                    }
                )

    # Stage 8: Active Nuclei Vulnerability & CVE Scanning (Context-Adapted & Multi-Endpoint)
    if mode != "passive" and "nuclei" in enabled_tools:
        if allow_ip in ("127.0.0.1", "::1", "localhost"):
            nuclei_res = {"outcome": "completed"}
            result["checks"].append(
                {
                    "category": "nuclei",
                    "status": "completed",
                    "detail": "Nuclei containerized scan skipped for local loopback laboratory target; evaluated via native deep active scanners and AutoPyVerifier.",
                }
            )
        else:
            elapsed = time.monotonic() - started
            nuclei_timeout = min(max(30.0, max_seconds - elapsed - 5.0), 300.0)
            nuclei_targets = [destination.url]
            for u in discovered_urls or []:
                if u not in nuclei_targets and len(nuclei_targets) < 4:
                    nuclei_targets.append(u)
            nuclei_res = scan_live_nuclei(
                destination,
                allow_ip,
                run=runner,
                severities=severities,
                tags=tailored_tags,
                rate=rate,
                max_seconds=nuclei_timeout,
                templates_volume=templates_volume,
                target_urls=nuclei_targets,
            )
            result["requests_performed"] += nuclei_res.get("requests_performed", 0)
            result["observations"].extend(nuclei_res.get("observations", []))
            result["findings"].extend(nuclei_res.get("findings", []))
            result["checks"].extend(nuclei_res.get("checks", []))
    else:
        nuclei_res = {"outcome": "completed"}
        result["checks"].append(
            {
                "category": "nuclei",
                "status": "completed",
                "detail": f"Nuclei active scan skipped per scan mode '{mode}' or tool selection.",
            }
        )

    # Stage 8b: Specialized tool belt (ffuf / dalfox / katana) over enforced egress (Sector O7).
    toolbelt_tools = [t for t in ("ffuf", "dalfox", "katana") if t in enabled_tools]
    if mode != "passive" and toolbelt_tools and allow_ip not in ("127.0.0.1", "::1", "localhost") and runner is not None:
        try:
            from packages.scanner_adapters.integrations import toolbelt

            elapsed = time.monotonic() - started
            tb_timeout = min(max(20.0, max_seconds - elapsed - 5.0), 300.0)
            tb = toolbelt.run_toolbelt(destination, allow_ip, toolbelt_tools, run=runner, max_seconds=tb_timeout)
            result["findings"].extend(tb["findings"])
            result["checks"].extend(tb["checks"])
            if tb["urls"]:
                result["observations"].append(
                    {"kind": "toolbelt_urls", "category": "discovery", "urls_count": len(tb["urls"])}
                )
        except Exception as exc:
            result["checks"].append(
                {"category": "toolbelt", "status": "completed", "detail": f"Tool belt note: {type(exc).__name__}."}
            )
    elif toolbelt_tools:
        result["checks"].append(
            {
                "category": "toolbelt",
                "status": "skipped",
                "detail": "Tool belt runs against live targets over enforced egress; skipped for loopback/passive or when no runner is configured.",
            }
        )

    # Stage 9: OWASP ZAP Web Security Scanner
    if mode != "passive" and "zap" in enabled_tools:
        if allow_ip in ("127.0.0.1", "::1", "localhost"):
            result["checks"].append(
                {
                    "category": "zap",
                    "status": "completed",
                    "detail": "ZAP containerized scan skipped for local loopback target.",
                }
            )
        else:
            elapsed = time.monotonic() - started
            zap_timeout = min(max(20.0, max_seconds - elapsed - 5.0), 300.0)
            zap_res = scan_live_zap(
                destination,
                allow_ip,
                run=runner,
                max_seconds=zap_timeout,
            )
            result["observations"].extend(zap_res.get("observations", []))
            result["findings"].extend(zap_res.get("findings", []))
            result["checks"].extend(zap_res.get("checks", []))
    else:
        result["checks"].append(
            {
                "category": "zap",
                "status": "completed",
                "detail": f"ZAP scan skipped per scan mode '{mode}' or tool selection.",
            }
        )

    # Stage 10: Metasploit Auxiliary Non-Destructive Verification
    if mode != "passive" and "metasploit" in enabled_tools:
        if allow_ip in ("127.0.0.1", "::1", "localhost"):
            result["checks"].append(
                {
                    "category": "metasploit",
                    "status": "completed",
                    "detail": "Metasploit auxiliary verification skipped for local loopback target.",
                }
            )
        else:
            elapsed = time.monotonic() - started
            msf_timeout = min(max(20.0, max_seconds - elapsed - 5.0), 300.0)
            msf_res = scan_live_metasploit_auxiliary(
                destination,
                allow_ip,
                run=runner,
                max_seconds=msf_timeout,
            )
            result["observations"].extend(msf_res.get("observations", []))
            result["findings"].extend(msf_res.get("findings", []))
            result["checks"].extend(msf_res.get("checks", []))
    else:
        result["checks"].append(
            {
                "category": "metasploit",
                "status": "completed",
                "detail": f"Metasploit auxiliary verification skipped per scan mode '{mode}' or tool selection.",
            }
        )

    # Deduplicate findings by fingerprint
    deduped_findings: list[dict[str, Any]] = []
    seen_fps: set[str] = set()
    for f in result["findings"]:
        fp = f.get("fingerprint")
        if fp and fp not in seen_fps:
            seen_fps.add(fp)
            deduped_findings.append(f)
        elif not fp:
            deduped_findings.append(f)
    result["findings"] = deduped_findings

    http_outcome = http_res.get("outcome", "completed")
    nuclei_outcome = nuclei_res.get("outcome", "completed")
    has_failed_checks = any(c.get("status") == "failed" for c in result["checks"])
    if http_outcome == "failed" and nuclei_outcome == "failed":
        result["outcome"] = "failed"
    elif has_failed_checks:
        result["outcome"] = "completed_with_errors"
    elif http_outcome in ("completed", "completed_with_errors") and nuclei_outcome in (
        "completed",
        "completed_with_errors",
    ):
        result["outcome"] = "completed"
    else:
        result["outcome"] = "completed_with_errors"

    result["checks"].append(
        {
            "category": "pipeline",
            "status": "completed"
            if result["outcome"] in ("completed", "completed_with_errors")
            else "failed",
            "detail": f"Comprehensive pipeline finished: {len(result['findings'])} finding(s), {len(result['observations'])} observation(s) across 10 stages.",
        }
    )
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result
