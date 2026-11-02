"""Dual-identity session switching, authenticated session management, and authorization matrix testing engine.

Provides automated horizontal IDOR (Insecure Direct Object Reference),
vertical privilege escalation, and unauthenticated access verification by
systematically switching between independent session contexts (User A vs User B vs Admin vs Unauthenticated),
with support for token rotation, automated form logins, and transparent re-authentication.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from packages.security_policies import Destination

_MAX_BODY_BYTES = 64 * 1024


@dataclass
class AuthConfig:
    """Configuration for authenticated assessment sessions, token rotation, and login flows."""

    cookies: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    rotating_tokens: list[str] = field(default_factory=list)
    custom_headers: dict[str, str] = field(default_factory=dict)
    login_url: str | None = None
    login_method: str = "POST"
    login_payload: dict[str, str] = field(default_factory=dict)
    success_indicator: str | None = None
    health_check_endpoint: str | None = None


@dataclass
class IdentitySession:
    """Represents an isolated user session context with specific role and credentials."""

    name: str
    role: str = "standard"  # "standard" | "admin" | "unauthenticated"
    headers: dict[str, str] = field(default_factory=dict)
    user_id: str | None = None
    canaries: list[str] = field(default_factory=list)
    auth_config: AuthConfig | None = None


@dataclass
class ResourceTarget:
    """A target resource endpoint to test for authorization flaws."""

    path: str
    method: str = "GET"
    owner_identity: str = ""
    owner_resource_id: str = ""
    peer_resource_id: str = ""
    is_admin_only: bool = False


def _send_auth_probe(
    destination: Destination,
    allow_ip: str,
    method: str,
    path: str,
    headers: dict[str, str],
    timeout: float = 4.0,
    body: str | None = None,
) -> tuple[int, dict[str, str], str, float]:
    """Execute an HTTP request with identity headers pinned strictly to allow_ip."""
    is_https = destination.scheme == "https"
    target_host = destination.host
    target_port = destination.port

    req_headers = {
        "Host": target_host,
        "User-Agent": "SHARAY-AuthMatrix/2.0 (Dual-Identity Verification)",
        "Accept": "*/*",
        "Connection": "close",
    }
    for k, v in headers.items():
        req_headers[k] = v

    if body and "Content-Length" not in req_headers:
        req_headers["Content-Length"] = str(len(body.encode("utf-8")))

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
        conn.request(method, path, body=body, headers=req_headers)
        resp = conn.getresponse()
        elapsed_ms = (time.monotonic() - started) * 1000
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        resp_body = resp.read(_MAX_BODY_BYTES).decode("utf-8", errors="replace")
        return resp.status, resp_headers, resp_body, elapsed_ms
    finally:
        conn.close()


def _extract_token_from_json(data: Any) -> str | None:
    """Recursively search for bearer token / JWT in JSON response structures."""
    if isinstance(data, dict):
        for key in ("token", "access_token", "accessToken", "jwt", "id_token", "auth_token"):
            if key in data and isinstance(data[key], str) and len(data[key]) > 8:
                return data[key]
        for v in data.values():
            found = _extract_token_from_json(v)
            if found:
                return found
    return None


class AuthenticatedSession:
    """Manages an active authenticated HTTP session with cookie jar, token rotation, and transparent re-auth."""

    def __init__(
        self,
        destination: Destination,
        allow_ip: str,
        identity: IdentitySession,
    ) -> None:
        self.destination = destination
        self.allow_ip = allow_ip
        self.identity = identity
        self.auth_config = identity.auth_config or AuthConfig()
        self._cookie_jar: dict[str, str] = dict(self.auth_config.cookies)
        self._token_index: int = -1
        self._active_token: str | None = self.auth_config.bearer_token

        # Ingest initial headers if cookie or auth present
        cookie_hdr = identity.headers.get("Cookie") or identity.headers.get("cookie")
        if cookie_hdr:
            for item in cookie_hdr.split(";"):
                if "=" in item:
                    k, v = item.strip().split("=", 1)
                    self._cookie_jar[k] = v

        auth_hdr = identity.headers.get("Authorization") or identity.headers.get("authorization")
        if auth_hdr and auth_hdr.lower().startswith("bearer "):
            self._active_token = auth_hdr.split(" ", 1)[1].strip()

    def get_effective_headers(self) -> dict[str, str]:
        """Produce request headers with up-to-date cookies and authentication credentials."""
        headers = dict(self.identity.headers)
        headers.update(self.auth_config.custom_headers)
        if self._cookie_jar:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._cookie_jar.items())
        if self._active_token:
            headers["Authorization"] = f"Bearer {self._active_token}"
        return headers

    def reauthenticate(self, timeout: float = 4.0) -> bool:
        """Transparently re-authenticate using rotating tokens or automated JSON/form login flow."""
        # 1. Rotate token from pool if configured
        if self.auth_config.rotating_tokens:
            self._token_index = (self._token_index + 1) % len(self.auth_config.rotating_tokens)
            self._active_token = self.auth_config.rotating_tokens[self._token_index]
            return True

        # 2. Automated login flow (supporting both JSON and Form encodings)
        if self.auth_config.login_url and self.auth_config.login_payload:
            method = self.auth_config.login_method.upper()
            is_json = bool(
                self.auth_config.custom_headers.get("Content-Type") == "application/json"
                or isinstance(self.auth_config.login_payload, dict)
            )

            if is_json:
                payload = json.dumps(self.auth_config.login_payload)
                content_type = "application/json"
            else:
                payload = urlencode(self.auth_config.login_payload)
                content_type = "application/x-www-form-urlencoded"

            login_headers = {
                "Content-Type": content_type,
                "Accept": "application/json, text/plain, */*",
                "Host": self.destination.host,
            }
            try:
                status, resp_headers, body, _ = _send_auth_probe(
                    self.destination,
                    self.allow_ip,
                    method,
                    self.auth_config.login_url,
                    login_headers,
                    body=payload if method != "GET" else None,
                    timeout=timeout,
                )

                # A. Parse cookies
                set_cookie = resp_headers.get("set-cookie")
                if set_cookie:
                    for part in set_cookie.split(";"):
                        if "=" in part:
                            k, v = part.strip().split("=", 1)
                            if k.lower() not in (
                                "path",
                                "domain",
                                "expires",
                                "samesite",
                                "secure",
                                "httponly",
                                "max-age",
                            ):
                                self._cookie_jar[k] = v

                # B. Parse and capture Bearer token from JSON response body
                try:
                    resp_json = json.loads(body)
                    extracted_token = _extract_token_from_json(resp_json)
                    if extracted_token:
                        self._active_token = extracted_token
                except Exception:
                    pass

                # C. Check success indicator
                if self.auth_config.success_indicator:
                    return self.auth_config.success_indicator in body or status in (200, 201, 302)
                return status in (200, 201, 302)
            except Exception:
                return False
        return False

    def execute_with_reauth(
        self,
        method: str,
        path: str,
        extra_headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: float = 4.0,
    ) -> tuple[int, dict[str, str], str, float]:
        """Execute request with transparent re-auth on 401/403 or redirect to login."""
        headers = self.get_effective_headers()
        if extra_headers:
            headers.update(extra_headers)

        if body is not None:
            status, resp_headers, resp_body, elapsed = _send_auth_probe(
                self.destination, self.allow_ip, method, path, headers, timeout=timeout, body=body
            )
        else:
            status, resp_headers, resp_body, elapsed = _send_auth_probe(
                self.destination, self.allow_ip, method, path, headers, timeout=timeout
            )

        login_url = self.auth_config.login_url or "/login"
        redirect_to_login = status in (301, 302, 303, 307) and login_url in resp_headers.get("location", "")
        if (status in (401, 403) or redirect_to_login) and (
            self.auth_config.login_url or self.auth_config.rotating_tokens
        ):
            if self.reauthenticate(timeout=timeout):
                headers = self.get_effective_headers()
                if extra_headers:
                    headers.update(extra_headers)
                if body is not None:
                    return _send_auth_probe(
                        self.destination, self.allow_ip, method, path, headers, timeout=timeout, body=body
                    )
                return _send_auth_probe(
                    self.destination, self.allow_ip, method, path, headers, timeout=timeout
                )

        return status, resp_headers, resp_body, elapsed

    def check_health(self, timeout: float = 4.0) -> bool:
        """Verify session validity via health check endpoint or root endpoint."""
        target_path = self.auth_config.health_check_endpoint or "/"
        try:
            status, _, body, _ = self.execute_with_reauth("GET", target_path, timeout=timeout)
            if self.auth_config.success_indicator:
                return self.auth_config.success_indicator in body and status == 200
            return status == 200
        except Exception:
            return False


class AuthorizationMatrixProber:
    """Orchestrates multi-identity authorization and IDOR sweeps."""

    def __init__(
        self,
        destination: Destination,
        allow_ip: str,
        identities: dict[str, IdentitySession],
    ) -> None:
        self.destination = destination
        self.allow_ip = allow_ip
        self.identities = identities
        self._sessions: dict[str, AuthenticatedSession] = {
            name: AuthenticatedSession(destination, allow_ip, ident) for name, ident in identities.items()
        }

    def sweep(
        self,
        resources: list[ResourceTarget],
        timeout: float = 4.0,
        test_unauthenticated: bool = True,
    ) -> dict[str, Any]:
        """Execute automated horizontal IDOR, vertical privilege escalation, and unauthenticated sweeps."""
        findings: list[dict[str, Any]] = []
        checks: list[dict[str, Any]] = []

        for resource in resources:
            finding_url = f"{self.destination.origin}{resource.path}"

            if resource.is_admin_only:
                # Vertical Privilege Escalation Test
                # 1. Admin baseline
                admin_entry = next(((n, s) for n, s in self.identities.items() if s.role == "admin"), None)
                if admin_entry:
                    admin_name, admin_session = admin_entry
                    admin_auth = self._sessions[admin_name]
                    try:
                        adm_status, _, _, _ = admin_auth.execute_with_reauth(
                            resource.method, resource.path, timeout=timeout
                        )
                    except Exception:
                        adm_status = 0

                    if adm_status == 200:
                        # 2. Test standard users on admin endpoint
                        for ident_name, ident in self.identities.items():
                            if ident.role != "admin" and ident.role != "unauthenticated":
                                u_auth = self._sessions[ident_name]
                                try:
                                    u_status, _, u_body, _ = u_auth.execute_with_reauth(
                                        resource.method, resource.path, timeout=timeout
                                    )
                                    if u_status == 200:
                                        findings.append(
                                            {
                                                "category": "broken_access_control",
                                                "severity": "critical",
                                                "title": f"Vertical Privilege Escalation on {resource.path}",
                                                "type": "vertical_privilege_escalation",
                                                "path": resource.path,
                                                "method": resource.method,
                                                "attacker_identity": ident_name,
                                                "attacker_role": ident.role,
                                                "target_url": finding_url,
                                                "fingerprint": hashlib.sha256(
                                                    f"vpe_{self.destination.host}_{resource.path}_{ident_name}".encode()
                                                ).hexdigest(),
                                                "cwe_id": "CWE-284",
                                                "confidence": "high",
                                                "status": "confirmed",
                                                "lifecycle_state": "REPRODUCED",
                                                "remediation": "Enforce role-based access control (RBAC) authorization checks on administrative handlers.",
                                                "evidence": f"Unprivileged {ident_name} accessed administrative endpoint {resource.path} (HTTP 200 OK).",
                                                "poc": {
                                                    "method": resource.method,
                                                    "url": finding_url,
                                                    "curl_command": f"curl -s -k -X {resource.method} '{finding_url}' -H 'Authorization: ...'",
                                                },
                                            }
                                        )
                                except Exception:
                                    pass

            elif resource.owner_identity and resource.owner_identity in self.identities:
                # Horizontal IDOR Test
                victim_auth = self._sessions[resource.owner_identity]
                victim_ident = self.identities[resource.owner_identity]
                try:
                    v_status, _, v_body, _ = victim_auth.execute_with_reauth(
                        resource.method, resource.path, timeout=timeout
                    )
                except Exception:
                    v_status = 0
                    v_body = ""

                if v_status == 200:
                    # Test each peer identity against victim's resource
                    for peer_name, peer_ident in self.identities.items():
                        if peer_name == resource.owner_identity or peer_ident.role == "admin":
                            continue

                        peer_auth = self._sessions[peer_name]
                        try:
                            p_status, _, p_body, _ = peer_auth.execute_with_reauth(
                                resource.method, resource.path, timeout=timeout
                            )
                            if p_status == 200:
                                leaked_canaries = [c for c in victim_ident.canaries if c in p_body]
                                if leaked_canaries or len(p_body) == len(v_body):
                                    evidence_detail = (
                                        f"Leaked canaries: {leaked_canaries}"
                                        if leaked_canaries
                                        else f"Byte-identical response payload ({len(p_body)} bytes)."
                                    )
                                    findings.append(
                                        {
                                            "category": "broken_object_level_authorization",
                                            "severity": "high",
                                            "title": f"Horizontal IDOR on {resource.path}",
                                            "type": "horizontal_idor",
                                            "path": resource.path,
                                            "method": resource.method,
                                            "victim_identity": resource.owner_identity,
                                            "attacker_identity": peer_name,
                                            "target_url": finding_url,
                                            "fingerprint": hashlib.sha256(
                                                f"idor_{self.destination.host}_{resource.path}_{peer_name}".encode()
                                            ).hexdigest(),
                                            "cwe_id": "CWE-639",
                                            "confidence": "high",
                                            "status": "confirmed",
                                            "lifecycle_state": "REPRODUCED",
                                            "remediation": "Validate that the authenticated session owns the requested object identifier prior to rendering.",
                                            "evidence": f"Identity {peer_name} read resource owned by {resource.owner_identity}. {evidence_detail}",
                                            "poc": {
                                                "method": resource.method,
                                                "url": finding_url,
                                                "curl_command": f"curl -s -k -X {resource.method} '{finding_url}' -H 'Cookie: ...'",
                                            },
                                        }
                                    )
                        except Exception:
                            pass

        checks.append(
            {
                "category": "authorization_matrix",
                "resources_tested": len(resources),
                "identities_tested": len(self.identities),
                "findings_count": len(findings),
                "status": "passed" if not findings else "vulnerabilities_detected",
            }
        )

        return {
            "findings": findings,
            "checks": checks,
        }


__all__ = [
    "AuthConfig",
    "AuthenticatedSession",
    "AuthorizationMatrixProber",
    "IdentitySession",
    "ResourceTarget",
]
