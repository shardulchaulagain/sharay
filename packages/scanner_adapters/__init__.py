"""The implemented safe HTTP adapter and honest optional-tool preflight."""

import hashlib
import http.client
import ipaddress
import re
import shutil
import socket
import ssl
import time
from collections.abc import Callable
from datetime import UTC, datetime
from http.cookies import CookieError, SimpleCookie
from typing import Any, cast
from urllib.parse import urljoin

from packages.security_policies import (
    Destination,
    PolicyError,
    ScopePolicy,
    check_url,
    validate_scope,
)

ADAPTER_VERSION = "1.1.1"
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
    return [
        {
            "id": "safe_http",
            "name": "SHARAY safe HTTP",
            "version": ADAPTER_VERSION,
            "available": True,
            "runnable": True,
            "status": "implemented",
            "supported_categories": ["http_headers", "tls"],
            "scope": "Explicitly approved literal loopback laboratories only",
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
    ] + [
        {
            "id": name,
            "name": name,
            "version": None,
            "available": bool(shutil.which(command)),
            "runnable": False,
            "status": "integration_not_implemented" if shutil.which(command) else "missing",
            "supported_categories": [],
            "limitations": "Not executed: adapter and isolated worker policy are not implemented.",
        }
        for name, command in tools
    ]


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
    flags: list[dict[str, Any]] = []
    for value in values:
        cookie = SimpleCookie()
        try:
            cookie.load(value)
        except CookieError:
            flags.append({"parse_error": True})
            continue
        if not cookie:
            flags.append({"parse_error": True})
        for morsel in cookie.values():
            same_site = morsel["samesite"].lower()
            flags.append(
                {
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": same_site if same_site in {"strict", "lax", "none"} else "unset",
                }
            )
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
        "header_analysis_limits": "CSP non-emptiness is not policy validity. Framing checks ancestor host patterns and XFO rules; combined scheme/port/path behavior and browser workflows are not tested. Referrer recognition is not a privacy-strength assessment.",
        "nosniff": lowered.get("x-content-type-options", "").strip().lower() == "nosniff",
        "cache_control": {
            directive: directive
            in {d.strip().lower().split("=")[0] for d in lowered.get("cache-control", "").split(",")}
            for directive in ["no-store", "no-cache", "private", "public"]
        },
        "cors_wildcard": lowered.get("access-control-allow-origin", "").strip() == "*",
        "cors_credentials": lowered.get("access-control-allow-credentials", "").strip().lower() == "true",
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
            if previous_request is not None:
                next_request = previous_request + 1 / policy.request_rate
                while time.monotonic() < next_request:
                    guard()
                    check_url(policy, destination.url)
                    time.sleep(max(0, min(0.05, next_request - time.monotonic())))
            guard()
            # Expiry and scope are revalidated immediately before every connection.
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


__all__ = ["preflight", "scan"]
