"""Reference implementation of Real Credential-Provisioning & JSON Token Capture (Phase 0, Sector 2 - P0).

Enhances AuthenticatedSession to:
1. Support JSON login payloads (application/json) alongside form-urlencoded.
2. Dynamically extract bearer tokens from JSON response bodies (token, access_token, jwt, authentication.token).
3. Seamlessly manage cookies and bearer tokens across tenant sessions for genuine IDOR/BOLA matrix auditing.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode

from packages.scanner_adapters.integrations.authorization import (
    AuthConfig,
    IdentitySession,
    _send_auth_probe,
)
from packages.security_policies import Destination


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


class EnhancedAuthenticatedSession:
    """Manages an active authenticated HTTP session with JSON token capture, cookies, and re-auth."""

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
            is_json = bool(self.auth_config.custom_headers.get("Content-Type") == "application/json" or isinstance(self.auth_config.login_payload, dict))
            
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
                                "path", "domain", "expires", "samesite", "secure", "httponly", "max-age"
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

        status, resp_headers, resp_body, elapsed = _send_auth_probe(
            self.destination, self.allow_ip, method, path, headers, timeout=timeout, body=body
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
                return _send_auth_probe(
                    self.destination, self.allow_ip, method, path, headers, timeout=timeout, body=body
                )

        return status, resp_headers, resp_body, elapsed
