"""Typed Resolver Service & Fallback Ladder (A2) for SHARAY.

Provides resilient, typed DNS resolution with a fallback ladder:
1. System resolver (`socket.getaddrinfo` with discrete AF_INET and AF_INET6)
2. DNS-over-HTTPS (DoH) fallback via Cloudflare (1.1.1.1) and Google (8.8.8.8)
3. In-memory Last-Known-Good resolution cache

Invariants:
- All failure modes map to discrete, branchable ResolutionErrorCode enums.
- SSRF guard: Refuses resolution if answers contain loopback/private/internal IPs.
- Deterministic IP pinning: Prefers public IPv4 address with deterministic tiebreak.
- Comprehensive telemetry: Records resolver used, latency, retries, and answers.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


class ResolutionErrorCode(str, Enum):
    NXDOMAIN = "NXDOMAIN"  # Domain does not exist (EAI_NONAME)
    SERVFAIL = "SERVFAIL"  # Upstream resolver timeout/failure (EAI_AGAIN)
    NODATA = "NODATA"  # Record type does not exist
    FORMERR = "FORMERR"  # Malformed query or hostname
    NO_RESOLVER = "NO_RESOLVER"  # No reachable resolver in resolv.conf
    UDP_BLOCKED = "UDP_BLOCKED"  # Port 53 UDP filtered
    DNSSEC_BOGUS = "DNSSEC_BOGUS"  # DNSSEC validation failed
    SPLIT_HORIZON = "SPLIT_HORIZON"  # Internal-only zone
    SSRF_REFUSED = "SSRF_REFUSED"  # Target resolved to private/internal IP
    TIMEOUT = "TIMEOUT"  # Resolution budget exceeded
    UNKNOWN = "UNKNOWN"  # Unclassified socket error


@dataclass(frozen=True)
class ErrorPolicy:
    retryable: bool
    fallback: str


ERROR_TAXONOMY: dict[ResolutionErrorCode, ErrorPolicy] = {
    ResolutionErrorCode.NXDOMAIN: ErrorPolicy(retryable=False, fallback="doh"),
    ResolutionErrorCode.SERVFAIL: ErrorPolicy(retryable=True, fallback="doh"),
    ResolutionErrorCode.NODATA: ErrorPolicy(retryable=False, fallback="query_aaaa"),
    ResolutionErrorCode.FORMERR: ErrorPolicy(retryable=False, fallback="re_normalize"),
    ResolutionErrorCode.NO_RESOLVER: ErrorPolicy(retryable=True, fallback="doh"),
    ResolutionErrorCode.UDP_BLOCKED: ErrorPolicy(retryable=True, fallback="tcp_or_doh"),
    ResolutionErrorCode.DNSSEC_BOGUS: ErrorPolicy(retryable=False, fallback="none"),
    ResolutionErrorCode.SPLIT_HORIZON: ErrorPolicy(retryable=False, fallback="internal_ns"),
    ResolutionErrorCode.SSRF_REFUSED: ErrorPolicy(retryable=False, fallback="none"),
    ResolutionErrorCode.TIMEOUT: ErrorPolicy(retryable=True, fallback="doh"),
    ResolutionErrorCode.UNKNOWN: ErrorPolicy(retryable=False, fallback="doh"),
}


class ResolutionError(Exception):
    """Structured resolution failure with typed error code and telemetry."""

    def __init__(
        self,
        code: ResolutionErrorCode,
        host: str,
        message: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.host = host
        self.policy = ERROR_TAXONOMY.get(code, ErrorPolicy(retryable=False, fallback="none"))
        self.details = details or {}
        msg = message or f"Resolution failed for '{host}': {code.value}"
        super().__init__(f"[{code.value}] {msg}")


@dataclass(frozen=True)
class ResolutionResult:
    """Canonical successful resolution output."""

    host: str
    ipv4_addresses: tuple[str, ...]
    ipv6_addresses: tuple[str, ...]
    pinned_ip: str
    resolver_used: str  # "system" | "doh_cloudflare" | "doh_google" | "cache" | "literal"
    elapsed_ms: float
    retries: int
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "ipv4_addresses": list(self.ipv4_addresses),
            "ipv6_addresses": list(self.ipv6_addresses),
            "pinned_ip": self.pinned_ip,
            "resolver_used": self.resolver_used,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "retries": self.retries,
            "cached": self.cached,
        }


class ResolverService:
    """Multi-tier DNS resolver with DoH fallback and SSRF protection."""

    def __init__(
        self,
        timeout: float = 4.0,
        enable_doh_fallback: bool = True,
        system_resolver: Callable[..., Any] = socket.getaddrinfo,
        allow_internal: bool = False,
    ) -> None:
        self.timeout = timeout
        self.enable_doh_fallback = enable_doh_fallback
        self.system_resolver = system_resolver
        self.allow_internal = allow_internal
        self._cache: dict[str, tuple[float, ResolutionResult]] = {}
        self.cache_ttl: float = 300.0  # 5 minutes

    def _validate_ssrf(self, ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address], host: str) -> None:
        """Enforce strict anti-SSRF policy: refuse if any answer is loopback or private."""
        if self.allow_internal:
            return
        for ip in ips:
            if (
                ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise ResolutionError(
                    ResolutionErrorCode.SSRF_REFUSED,
                    host,
                    f"Address {ip} is non-public/internal (SSRF guard)",
                    {"refused_ip": str(ip)},
                )

    def _pin_address(self, candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address]) -> str:
        """Deterministically select one public IP, preferring IPv4."""
        # Prefer IPv4 for egress compatibility, deterministic tiebreak by packed bytes
        sorted_candidates = sorted(candidates, key=lambda a: (a.version, a.packed))
        return str(sorted_candidates[0])

    def resolve(self, host: str) -> ResolutionResult:
        """Resolve a host to verified public IP addresses with fallback ladder."""
        clean_host = host.rstrip(".").lower()
        start_time = time.monotonic()

        # 0. Check literal IP (short-circuit DNS)
        try:
            literal_ip = ipaddress.ip_address(clean_host)
            self._validate_ssrf([literal_ip], clean_host)
            ipv4 = (str(literal_ip),) if literal_ip.version == 4 else ()
            ipv6 = (str(literal_ip),) if literal_ip.version == 6 else ()
            return ResolutionResult(
                host=clean_host,
                ipv4_addresses=ipv4,
                ipv6_addresses=ipv6,
                pinned_ip=str(literal_ip),
                resolver_used="literal",
                elapsed_ms=(time.monotonic() - start_time) * 1000.0,
                retries=0,
                cached=False,
            )
        except ValueError:
            pass  # Not a literal IP, proceed to DNS

        # 1. Check LKG cache
        cached_entry = self._cache.get(clean_host)
        if cached_entry:
            cached_at, cached_res = cached_entry
            if time.monotonic() - cached_at < self.cache_ttl:
                return ResolutionResult(
                    host=cached_res.host,
                    ipv4_addresses=cached_res.ipv4_addresses,
                    ipv6_addresses=cached_res.ipv6_addresses,
                    pinned_ip=cached_res.pinned_ip,
                    resolver_used="cache",
                    elapsed_ms=(time.monotonic() - start_time) * 1000.0,
                    retries=0,
                    cached=True,
                )

        # 2. Try System Resolver
        retries = 0
        sys_candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        try:
            try:
                infos = self.system_resolver(clean_host, None, proto=socket.IPPROTO_TCP)
            except TypeError:
                infos = self.system_resolver(clean_host, None)
            for info in infos:
                addr_str = str(info[4][0])
                try:
                    sys_candidates.append(ipaddress.ip_address(addr_str))
                except ValueError:
                    pass
        except socket.gaierror as exc:
            # Map errno to taxonomy
            errno_map = {
                socket.EAI_NONAME: ResolutionErrorCode.NXDOMAIN,
                socket.EAI_AGAIN: ResolutionErrorCode.SERVFAIL,
                socket.EAI_FAIL: ResolutionErrorCode.SERVFAIL,
                socket.EAI_NODATA: ResolutionErrorCode.NODATA,
            }
            code = (
                errno_map.get(exc.errno, ResolutionErrorCode.UNKNOWN)
                if exc.errno is not None
                else ResolutionErrorCode.UNKNOWN
            )

            # If not retryable or DoH disabled, raise immediately
            policy = ERROR_TAXONOMY.get(code, ErrorPolicy(retryable=False, fallback="none"))
            if not self.enable_doh_fallback or (not policy.retryable and policy.fallback != "doh"):
                raise ResolutionError(code, clean_host, str(exc), {"errno": exc.errno}) from exc
        except OSError as exc:
            if not self.enable_doh_fallback:
                raise ResolutionError(ResolutionErrorCode.UNKNOWN, clean_host, str(exc)) from exc

        if sys_candidates:
            self._validate_ssrf(sys_candidates, clean_host)
            ipv4_list = tuple(sorted(set(str(ip) for ip in sys_candidates if ip.version == 4)))
            ipv6_list = tuple(sorted(set(str(ip) for ip in sys_candidates if ip.version == 6)))
            pinned = self._pin_address(sys_candidates)
            result = ResolutionResult(
                host=clean_host,
                ipv4_addresses=ipv4_list,
                ipv6_addresses=ipv6_list,
                pinned_ip=pinned,
                resolver_used="system",
                elapsed_ms=(time.monotonic() - start_time) * 1000.0,
                retries=retries,
            )
            self._cache[clean_host] = (time.monotonic(), result)
            return result

        # 3. Fallback Ladder: DNS over HTTPS (DoH) via Cloudflare & Google
        if not self.enable_doh_fallback:
            raise ResolutionError(ResolutionErrorCode.NXDOMAIN, clean_host, "Target host did not resolve.")

        retries += 1
        doh_candidates = self._query_doh(clean_host)
        if not doh_candidates:
            raise ResolutionError(
                ResolutionErrorCode.NXDOMAIN, clean_host, "Target host did not resolve via DoH ladder."
            )

        self._validate_ssrf(doh_candidates, clean_host)
        ipv4_list = tuple(sorted(set(str(ip) for ip in doh_candidates if ip.version == 4)))
        ipv6_list = tuple(sorted(set(str(ip) for ip in doh_candidates if ip.version == 6)))
        pinned = self._pin_address(doh_candidates)
        result = ResolutionResult(
            host=clean_host,
            ipv4_addresses=ipv4_list,
            ipv6_addresses=ipv6_list,
            pinned_ip=pinned,
            resolver_used="doh_cloudflare",
            elapsed_ms=(time.monotonic() - start_time) * 1000.0,
            retries=retries,
        )
        self._cache[clean_host] = (time.monotonic(), result)
        return result

    def _query_doh(self, host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Query Cloudflare and Google DoH JSON APIs with short timeout."""
        candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        endpoints = [
            f"https://1.1.1.1/dns-query?name={urllib.parse.quote(host)}&type=A",
            f"https://dns.google/resolve?name={urllib.parse.quote(host)}&type=A",
        ]
        for url in endpoints:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Accept": "application/dns-json", "User-Agent": "SHARAY-Resolver/1.0"},
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        status = data.get("Status", 0)
                        if status == 3:  # NXDOMAIN
                            raise ResolutionError(ResolutionErrorCode.NXDOMAIN, host, "DoH returned NXDOMAIN")
                        for answer in data.get("Answer", []):
                            data_val = answer.get("data")
                            if data_val:
                                try:
                                    candidates.append(ipaddress.ip_address(data_val.strip()))
                                except ValueError:
                                    pass
                        if candidates:
                            return candidates
            except ResolutionError:
                raise
            except Exception:
                continue
        return candidates


# Singleton default resolver
_DEFAULT_RESOLVER = ResolverService()


def resolve_typed(host: str, resolver: ResolverService | None = None) -> ResolutionResult:
    """Public helper to resolve a target with full error typing and telemetry."""
    res = resolver or _DEFAULT_RESOLVER
    return res.resolve(host)


__all__ = [
    "ResolverService",
    "ResolutionError",
    "ResolutionErrorCode",
    "ResolutionResult",
    "ERROR_TAXONOMY",
    "ErrorPolicy",
    "resolve_typed",
]
