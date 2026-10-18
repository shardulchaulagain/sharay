"""Unshackled, developer-grade scope and target validation policy.

Replaces artificial literal-loopback and compliance restrictions with an open,
developer-first security policy supporting:
1. Any target destination: hostnames, domains, IPv4/IPv6, localhost, private LAN,
   cloud VPS, and remote staging/production servers.
2. Standard HTTP and HTTPS schemes across any valid TCP port (1-65535).
3. Flexible pacing: request rates up to 100 rps and concurrency up to 10.
4. Authenticated & intrusive profiles for authorized penetration tests.
5. Zero DNS TXT or recurring ownership hurdle loops.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_DOMAIN_OR_HOST = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


class PolicyError(ValueError):
    """The proposed action or URL format is invalid."""


def sanitize_path(value: str) -> str:
    """Sanitize and normalize an HTTP path, preventing CRLF and control injection."""
    if not value.startswith("/"):
        value = "/" + value
    if any(c in value for c in "\r\n\t\x00"):
        raise PolicyError("Paths cannot contain control characters or newlines.")
    decoded = unquote(value, errors="replace")
    return quote(decoded, safe="/-._~:@!$&'()*+,=;?")


def normalize_url(value: str, *, allow_any_host: bool = True) -> str:
    """Normalize any HTTP(S) URL for scanning.

    Supports:
    - Hostnames (e.g. shardulchaulagain.com, api.internal.corp, localhost)
    - IPv4 addresses (127.0.0.1, 192.168.1.50, 10.0.0.1, public IPs)
    - IPv6 addresses ([::1], [2001:db8::1])
    - Custom ports (1-65535)
    """
    if not isinstance(value, str) or len(value) > 4096:
        raise PolicyError("A URL string of at most 4096 characters is required.")
    clean = value.strip()
    if _CONTROL.search(clean) or "\\" in clean:
        raise PolicyError("URL whitespace, control characters and backslashes are forbidden.")

    parsed = urlsplit(clean)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise PolicyError("Only HTTP and HTTPS targets are supported.")
    if not parsed.netloc:
        raise PolicyError("URL must contain a valid host location.")

    host = parsed.hostname or ""
    if not host:
        raise PolicyError("URL must contain a valid hostname or IP address.")

    # Validate IP or Hostname format
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    if not is_ip:
        if host != "localhost" and not _DOMAIN_OR_HOST.match(host):
            raise PolicyError(f"Invalid target hostname format: '{host}'")

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if not (1 <= port <= 65535):
        raise PolicyError(f"Invalid target port: {port}. Must be 1-65535.")

    default_port = 443 if parsed.scheme.lower() == "https" else 80
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port != default_port:
        authority = f"{authority}:{port}"

    clean_path = sanitize_path(parsed.path or "/")
    return urlunsplit((parsed.scheme.lower(), authority, clean_path, parsed.query, ""))


TestCategory = Literal[
    "http_headers",
    "tls",
    "dns",
    "recon",
    "sqli",
    "xss",
    "ssrf",
    "xxe",
    "cmdi",
    "auth_bypass",
    "idor",
    "server_side",
    "client_side",
    "api_vulnerability",
    "path_traversal",
    "request_smuggling",
    "prototype_pollution",
]


class UnshackledScopePolicy(BaseModel):
    """Developer-grade scope policy with operator-defined depth and zero loopback locks."""

    model_config = ConfigDict(extra="ignore")

    hosts: list[str] = Field(min_length=1)
    allowed_origins: list[str] = Field(min_length=1)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"])
    excluded_paths: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=lambda: ["http_headers", "tls", "dns"])
    authenticated: bool = False
    intrusive: bool = False
    request_rate: float = Field(default=10.0, gt=0, le=200.0)
    max_concurrency: int = Field(default=5, ge=1, le=50)
    starts_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None

    @field_validator("allowed_origins")
    @classmethod
    def validate_origins(cls, values: list[str]) -> list[str]:
        cleaned = []
        for val in values:
            norm = normalize_url(val)
            parsed = urlsplit(norm)
            cleaned.append(f"{parsed.scheme}://{parsed.netloc}")
        return sorted(set(cleaned))

    @field_validator("hosts")
    @classmethod
    def validate_hosts(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip().lower() for v in values if v.strip()]
        if not cleaned:
            raise ValueError("At least one target host is required.")
        return sorted(set(cleaned))
