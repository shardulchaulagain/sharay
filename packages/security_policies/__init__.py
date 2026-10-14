"""Deterministic scope registration and the independently checked execution boundary."""

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class PolicyError(ValueError):
    """The proposed action is outside the implemented authorization boundary."""


def _host(value: str) -> str:
    """Canonical IPs or ASCII DNS names; never a resolver's alternate numeric spelling."""
    if not value or len(value) > 253 or "%" in value:
        raise PolicyError("Use a canonical IP address or ASCII hostname without a zone identifier.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        labels = value.split(".")
        if (
            not value.isascii()
            or value != value.lower()
            or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", value)
            or any(len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels)
            or not re.search(r"[a-z]", labels[-1])
            or re.fullmatch(r"0x[0-9a-f]+", labels[-1])
        ):
            raise PolicyError("Use a canonical lowercase ASCII hostname (punycode for international names).")
    else:
        if str(address) != value or (address.version == 6 and address.ipv4_mapped is not None):
            raise PolicyError("Use a canonical IP address without an IPv4-mapped representation.")
    return value


def _path(value: str) -> str:
    if not value.startswith("/") or any(c in value for c in "?#\\"):
        raise PolicyError("Paths must be absolute URL paths without queries or fragments.")
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise PolicyError("Malformed path encoding.")
    decoded = unquote(value, errors="strict")
    # Routing layers may strip semicolon parameters before matching paths.
    if ";" in decoded:
        raise PolicyError("Semicolon path parameters are not permitted.")
    if "%" in decoded or "\\" in decoded or "//" in decoded:
        raise PolicyError("Ambiguous path encoding or separators are not permitted.")
    if any(ord(c) < 32 or ord(c) == 127 for c in decoded):
        raise PolicyError("Control characters are not permitted.")
    if any(part in {".", ".."} for part in decoded.split("/")):
        raise PolicyError("Path traversal is not permitted.")
    # Encoded separators can have a different meaning in target routing layers.
    if re.search(r"%(?:2f|5c)", value, re.IGNORECASE):
        raise PolicyError("Encoded path separators are not permitted.")
    return quote(decoded, safe="/-._~:@!$&'()*+,=")


def normalize_url(value: str) -> str:
    """Normalize an explicit HTTP(S) target without resolving or contacting it."""
    if not isinstance(value, str) or len(value) > 2048:
        raise PolicyError("A URL string of at most 2048 characters is required.")
    if any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise PolicyError("URL whitespace, control characters and backslashes are forbidden.")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise PolicyError("Only HTTP and HTTPS targets are supported.")
        if parsed.username is not None or parsed.password is not None:
            raise PolicyError("Credentials in URLs are forbidden.")
        if parsed.query or parsed.fragment or "?" in value or "#" in value:
            raise PolicyError("Query strings and fragments are unavailable in the safe profile.")
        host = _host(parsed.hostname or "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise PolicyError("Invalid target port.")
        # Reject alternate authority representations, trailing colons and port zero.
        authority_host = f"[{host}]" if ":" in host else host
        default_port = 443 if parsed.scheme == "https" else 80
        expected = authority_host + (f":{parsed.port}" if parsed.port is not None else "")
        if parsed.netloc != expected or parsed.port == 0:
            raise PolicyError("The URL authority must use its canonical representation.")
        authority = authority_host + (f":{port}" if port != default_port else "")
        return urlunsplit((parsed.scheme, authority, _path(parsed.path or "/"), "", ""))
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("Invalid URL or target address.") from exc


StopCondition = Literal["operator_cancel", "scope_expired", "policy_violation"]
TestCategory = Literal["http_headers", "tls", "dns"]
StrictString = Annotated[str, Field(strict=True, min_length=1, max_length=2048)]


def _default_categories() -> list[TestCategory]:
    return ["http_headers"]


def _stop_conditions() -> list[StopCondition]:
    return ["operator_cancel", "scope_expired", "policy_violation"]


class ScopePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hosts: list[StrictString] = Field(min_length=1, max_length=32)
    allowed_origins: list[StrictString] = Field(min_length=1, max_length=64)
    allowed_paths: list[StrictString] = Field(default_factory=lambda: ["/"], min_length=1, max_length=32)
    excluded_paths: list[StrictString] = Field(default_factory=list, max_length=32)
    allowed_cidrs: list[StrictString] = Field(default_factory=list, max_length=32)
    categories: list[TestCategory] = Field(default_factory=_default_categories, min_length=1, max_length=3)
    authenticated: Literal[False] = False
    credential_refs: list[StrictString] = Field(default_factory=list, max_length=0)
    request_rate: Annotated[float, Field(strict=True, gt=0, le=10)] = 1
    max_concurrency: Annotated[int, Field(strict=True, ge=1, le=5)] = 1
    starts_at: datetime
    expires_at: datetime
    intrusive: Literal[False] = False
    approval_required: Literal[True] = True
    emergency_stop_conditions: list[StopCondition] = Field(
        default_factory=_stop_conditions,
        min_length=3,
        max_length=3,
    )

    @field_validator("authenticated", "intrusive", "approval_required", mode="before")
    @classmethod
    def strict_booleans(cls, value):
        if type(value) is not bool:
            raise ValueError("Policy permission flags must be booleans.")
        return value

    @field_validator("max_concurrency", mode="before")
    @classmethod
    def strict_concurrency(cls, value):
        if type(value) is not int:
            raise ValueError("Concurrency must be an integer.")
        return value

    @field_validator("hosts")
    @classmethod
    def canonical_hosts(cls, values: list[str]) -> list[str]:
        for value in values:
            _host(value)
        if len(values) != len(set(values)):
            raise ValueError("Hosts must be unique.")
        return values

    @field_validator("allowed_origins")
    @classmethod
    def origins(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            url = normalize_url(value)
            parsed = urlsplit(url)
            if parsed.path != "/":
                raise ValueError("Allowed origins cannot contain an application path.")
            normalized.append(f"{parsed.scheme}://{parsed.netloc}")
        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate origins are not permitted.")
        return normalized

    @field_validator("allowed_paths", "excluded_paths")
    @classmethod
    def paths(cls, values: list[str]) -> list[str]:
        return [_path(value) for value in values]

    @field_validator("allowed_cidrs")
    @classmethod
    def cidrs(cls, values: list[str]) -> list[str]:
        for value in values:
            network = ipaddress.ip_network(value, strict=True)
            if str(network) != value or "%" in value:
                raise ValueError("Address ranges must use canonical network CIDR notation.")
            if network.version == 6 and network.overlaps(ipaddress.ip_network("::ffff:0:0/96")):
                raise ValueError("IPv4-mapped address ranges are not permitted.")
        if len(values) != len(set(values)):
            raise ValueError("Duplicate address ranges are not permitted.")
        return values

    @field_validator("starts_at", "expires_at")
    @classmethod
    def aware_dates(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Scope times must include a UTC offset.")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def coherent(self):
        if self.expires_at <= self.starts_at:
            raise ValueError("Scope expiry must follow its start.")
        if (self.expires_at - self.starts_at).total_seconds() > 86400:
            raise ValueError("Scopes have a maximum duration of 24 hours.")
        if set(self.emergency_stop_conditions) != {
            "operator_cancel",
            "scope_expired",
            "policy_violation",
        }:
            raise ValueError("All fixed emergency stop conditions are required.")
        if len(self.categories) != len(set(self.categories)):
            raise ValueError("Duplicate test categories are not permitted.")
        for origin in self.allowed_origins:
            host = urlsplit(origin).hostname
            if host not in self.hosts:
                raise ValueError("Every origin must have an explicitly authorized host.")
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                continue  # Registration does not resolve hostnames or establish execution readiness.
            if self.allowed_cidrs and not any(
                address in ipaddress.ip_network(cidr) for cidr in self.allowed_cidrs
            ):
                raise ValueError("Every literal origin must belong to the authorized address ranges.")
        return self


@dataclass(frozen=True)
class Destination:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    origin: str
    ip: str


def _matches(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/")


def check_url(scope: ScopePolicy | dict, url: str) -> Destination:
    policy = scope if isinstance(scope, ScopePolicy) else ScopePolicy.model_validate(scope)
    now = datetime.now(UTC)
    if now < policy.starts_at:
        raise PolicyError("The assessment scope has not started.")
    if now >= policy.expires_at:
        raise PolicyError("The assessment scope has expired.")
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.hostname
    if origin not in policy.allowed_origins or host not in policy.hosts:
        raise PolicyError("The destination origin is outside the approved scope.")
    if not any(_matches(parsed.path, path) for path in policy.allowed_paths):
        raise PolicyError("The destination path is outside the approved scope.")
    if any(_matches(parsed.path, path) for path in policy.excluded_paths):
        raise PolicyError("The destination path is explicitly excluded.")
    return Destination(
        normalized,
        parsed.scheme,
        host,
        parsed.port or (443 if parsed.scheme == "https" else 80),
        parsed.path,
        origin,
        host,
    )


def validate_scope(scope: ScopePolicy | dict, target_url: str) -> ScopePolicy:
    policy = scope if isinstance(scope, ScopePolicy) else ScopePolicy.model_validate(scope)
    check_url(policy, target_url)
    return policy


def check_execution_url(scope: ScopePolicy | dict, url: str) -> Destination:
    """The current executor is separately verified for exact literal loopback labs."""
    policy = scope if isinstance(scope, ScopePolicy) else ScopePolicy.model_validate(scope)
    destination = check_url(policy, url)
    required_cidr = {"127.0.0.1": "127.0.0.1/32", "::1": "::1/128"}.get(destination.host)
    if required_cidr is None:
        raise PolicyError(
            "Target registered; execution requires verified target ownership, bounded DNS pinning "
            "and enforced destination egress. These live-target controls are not connected yet. "
            "Use an explicitly approved 127.0.0.1 or ::1 laboratory for the current safe HTTP profile."
        )
    if required_cidr not in policy.allowed_cidrs:
        raise PolicyError(f"The safe HTTP laboratory profile requires explicit {required_cidr} approval.")
    return destination


def validate_execution_scope(scope: ScopePolicy | dict, target_url: str) -> ScopePolicy:
    policy = scope if isinstance(scope, ScopePolicy) else ScopePolicy.model_validate(scope)
    check_execution_url(policy, target_url)
    return policy


__all__ = [
    "Destination",
    "PolicyError",
    "ScopePolicy",
    "check_url",
    "check_execution_url",
    "normalize_url",
    "validate_scope",
    "validate_execution_scope",
]
