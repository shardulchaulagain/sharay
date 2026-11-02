"""Interactive Verification & Command Runner Workspace for SHARAY.

Enables scoped operator takeover for testing, command execution verification,
and custom payload iteration on detected endpoints within approved policy boundaries.
"""

from __future__ import annotations

import hashlib
import http.client
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from packages.security_policies import (
    Destination,
    PolicyError,
    ScopePolicy,
    check_execution_url,
)

ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_TIMEOUT_SECONDS = 15.0
MAX_BODY_BYTES = 64 * 1024  # 64 KB display budget
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
    }
)


@dataclass(frozen=True)
class WorkspaceResult:
    """Telemetry and output from an interactive workspace execution."""

    target_url: str
    method: str
    status_code: int
    duration_ms: float
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    response_body: str
    extracted_output: str
    timestamp: str
    fingerprint: str
    output_truncated: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "method": self.method,
            "status_code": self.status_code,
            "duration_ms": self.duration_ms,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "extracted_output": self.extracted_output,
            "timestamp": self.timestamp,
            "fingerprint": self.fingerprint,
            "output_truncated": self.output_truncated,
            "metadata": self.metadata,
        }


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive authorization or cookie tokens in telemetry."""
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


class InteractiveWorkspace:
    """Manages scoped interactive request replay, command extraction, and live probe sessions."""

    def __init__(self, default_timeout: float = 10.0):
        self.default_timeout = min(default_timeout, MAX_TIMEOUT_SECONDS)

    def execute_probe(
        self,
        scope: ScopePolicy | dict[str, Any],
        target_url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        query_params: dict[str, str] | None = None,
        body: str | bytes | None = None,
        timeout: float | None = None,
        output_prefix: str | None = None,
        output_suffix: str | None = None,
        cancelled: Callable[[], bool] | None = None,
        pacing: dict[str, tuple[float, float]] | None = None,
        owned: bool = False,
    ) -> WorkspaceResult:
        """Execute a live interactive probe against an approved target endpoint within scope.

        The workspace is a live-execution path, so it enforces the SAME destination policy as the
        scan worker (`check_execution_url`): an approved loopback lab, or an owned public target --
        never a private/internal address. `owned` mirrors the target's operator-authorization, so a
        destination the worker would reject is rejected here too (F01/E07)."""
        if cancelled and cancelled():
            raise PolicyError("Operator cancellation requested.")

        # Method validation
        norm_method = method.upper()
        if norm_method not in ALLOWED_METHODS:
            raise PolicyError(f"HTTP method '{method}' is not in approved methods: {sorted(ALLOWED_METHODS)}")

        # Scope and destination validation -- identical contract to execution (no weaker path).
        policy = scope if isinstance(scope, ScopePolicy) else ScopePolicy.model_validate(scope)
        check_execution_url(policy, target_url, owned=owned)
        if not policy.intrusive:
            if norm_method in {"POST", "PUT", "DELETE", "PATCH"}:
                raise PolicyError(
                    f"State-changing method '{norm_method}' requires intrusive=True in scope policy."
                )
            if headers and any(k.lower() in {"authorization", "proxy-authorization"} for k in headers):
                raise PolicyError("Authentication headers require intrusive=True in scope policy.")
        destination: Destination = check_execution_url(policy, target_url, owned=owned)

        # Merge or format query parameters while preserving path scope
        final_url = destination.url
        if query_params:
            parsed = urlsplit(destination.url)
            existing_query = parse_qsl(parsed.query)
            merged_query = dict(existing_query)
            merged_query.update(query_params)
            new_query_str = urlencode(merged_query)
            final_url = urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path or "/", new_query_str, parsed.fragment)
            )
            # Revalidate with merged query (same execution contract).
            destination = check_execution_url(policy, final_url, owned=owned)

        if cancelled and cancelled():
            raise PolicyError("Operator cancellation requested.")

        # Rate pacing check
        if pacing is not None and policy.request_rate > 0:
            interval = 1.0 / policy.request_rate
            prior = pacing.get(destination.origin)
            if prior is not None:
                next_allowed = max(prior[0] + prior[1], prior[0] + interval)
                while time.monotonic() < next_allowed:
                    if cancelled and cancelled():
                        raise PolicyError("Operator cancellation requested.")
                    time.sleep(max(0.0, min(0.05, next_allowed - time.monotonic())))
            pacing[destination.origin] = (time.monotonic(), interval)

        # Timeout clamping
        effective_timeout = min(timeout or self.default_timeout, MAX_TIMEOUT_SECONDS)
        if effective_timeout <= 0:
            raise PolicyError("Timeout must be greater than zero.")

        # Headers and privacy
        raw_headers = dict(headers or {})
        if "User-Agent" not in raw_headers:
            raw_headers["User-Agent"] = "SHARAY-InteractiveWorkspace/1.0"
        if "Accept" not in raw_headers:
            raw_headers["Accept"] = "*/*"

        encoded_body: bytes | None = None
        if body is not None:
            if isinstance(body, str):
                encoded_body = body.encode("utf-8")
            else:
                encoded_body = body
            if "Content-Length" not in raw_headers:
                raw_headers["Content-Length"] = str(len(encoded_body))

        started = time.monotonic()
        conn: http.client.HTTPConnection | http.client.HTTPSConnection

        tls_verified: bool | None = None
        if destination.scheme == "https":
            # This probe ASSESSES an authorized target, so the target's certificate validity is an
            # observation, not a precondition: a self-signed, expired or mismatched cert must not
            # abort the probe (that is exactly the kind of box an operator needs to inspect). Connect
            # without verification and record that the cert was not trusted, matching the scanner's
            # TLS inspection. Certificate posture is reported separately, never as a connection error.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_verified = False
            conn = http.client.HTTPSConnection(
                destination.host, destination.port, timeout=effective_timeout, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(destination.host, destination.port, timeout=effective_timeout)

        try:
            req_path = destination.path
            parsed_final = urlsplit(destination.url)
            if parsed_final.query:
                req_path = f"{req_path}?{parsed_final.query}"

            conn.request(norm_method, req_path, body=encoded_body, headers=raw_headers)
            response = conn.getresponse()
            duration_ms = round((time.monotonic() - started) * 1000, 2)

            resp_headers = {k: v for k, v in response.getheaders()}
            raw_bytes = response.read(MAX_BODY_BYTES + 1)
            truncated = len(raw_bytes) > MAX_BODY_BYTES
            display_bytes = raw_bytes[:MAX_BODY_BYTES]
            response_text = display_bytes.decode("utf-8", errors="replace")

            extracted = self._extract_output(response_text, output_prefix, output_suffix)
            timestamp = datetime.now(UTC).isoformat()
            fingerprint = hashlib.sha256(
                f"{destination.url}|{norm_method}|{response.status}|{timestamp}".encode()
            ).hexdigest()

            return WorkspaceResult(
                target_url=destination.url,
                method=norm_method,
                status_code=response.status,
                duration_ms=duration_ms,
                request_headers=_redact_headers(raw_headers),
                response_headers=_redact_headers(resp_headers),
                response_body=response_text,
                extracted_output=extracted,
                timestamp=timestamp,
                fingerprint=fingerprint,
                output_truncated=truncated,
                metadata={
                    "scheme": destination.scheme,
                    "host": destination.host,
                    "port": destination.port,
                    "origin": destination.origin,
                    "path": req_path,
                    "tls_verified": tls_verified,
                },
            )
        finally:
            conn.close()

    def _extract_output(
        self,
        raw_text: str,
        prefix: str | None = None,
        suffix: str | None = None,
    ) -> str:
        """Extract isolated command output from response body when markers are present."""
        if not raw_text:
            return ""

        if prefix and prefix in raw_text:
            _, _, after = raw_text.partition(prefix)
            if suffix and suffix in after:
                extracted, _, _ = after.partition(suffix)
                return extracted.strip()
            return after.strip()

        return raw_text.strip()
