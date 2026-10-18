"""Anti-SSRF and DNS-Pinned Socket Egress Engine for Live Assessments (L1/C4).

Author: Gemini (Principal Architect, Debugger & Helper)
Status: Draft module under drafts/gemini/ for Claude and Codex review.

Addresses Live Execution Readiness Gate 2 (docs/LIVE_SCOPE_PLAN.md):
"URL/DNS/address/redirect policy. Canonical origins/paths/exclusions,
resolution/rebinding and actual-peer checks, explicit private-network policy,
metadata denial."

Key Defenses:
1. Multi-Family IP Classification:
   - Denies RFC 1918 (private networks), RFC 3927 (link-local), RFC 6598 (CGNAT),
     loopback (127/8, ::1), cloud metadata (169.254.169.254, fd00:ec2::254),
     multicast, broadcast, unspecified (0.0.0.0/8).
   - Unwraps and inspects IPv4-mapped IPv6 addresses (::ffff:127.0.0.1).
   - Denies known cloud metadata domain names (metadata.google.internal, instance-data).
2. All-Record DNS Resolution Check:
   - Resolves hostnames using getaddrinfo; fails closed if ANY resolved address is denied.
3. Socket Pinning (DNS Rebinding Immunity):
   - Binds the outgoing TCP socket directly to the validated IP literal.
   - For HTTPS, provides TLS SNI and server certificate verification matching the original hostname.
4. Safe Redirect Evaluator:
   - Every HTTP 3xx redirect destination must pass full re-validation.
   - Disallows HTTPS -> HTTP downgrades.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit, urlunsplit


class SSRFPolicyError(ValueError):
    """The target URL, resolved IP, or redirect breaches egress security policy."""


@dataclass(frozen=True)
class TargetAddress:
    hostname: str
    port: int
    scheme: Literal["http", "https"]
    pinned_ip: str
    ip_version: int


# Denied IPv4 CIDR blocks
_DENIED_IPV4_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),  # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),  # Private network (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),  # Shared Address Space / CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud Metadata (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),  # Private network (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),  # Private network (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved for future use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"),  # Limited broadcast
)

# Denied IPv6 CIDR blocks
_DENIED_IPV6_NETWORKS = (
    ipaddress.ip_network("::/128"),  # Unspecified address
    ipaddress.ip_network("::1/128"),  # Loopback address
    ipaddress.ip_network("100::/64"),  # Discard-only prefix (RFC 6666)
    ipaddress.ip_network("2001:db8::/32"),  # Documentation prefix (RFC 3849)
    ipaddress.ip_network("fc00::/7"),  # Unique Local Addresses (ULA)
    ipaddress.ip_network("fe80::/10"),  # Link-local unicast
    ipaddress.ip_network("ff00::/8"),  # Multicast
)

# Cloud metadata special names
_BLOCKED_METADATA_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.internal",
        "instance-data",
        "169.254.169.254",
    }
)


def classify_ip_address(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_loopback_lab: bool = False,
    allow_private_rfc1918: bool = False,
) -> tuple[bool, str]:
    """Audit an IP address against security egress rules.

    Returns (is_allowed, reason).
    """
    # 1. Handle IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    # 2. Check Loopback
    if ip.is_loopback:
        if allow_loopback_lab:
            return True, "permitted loopback laboratory target"
        return False, "loopback destinations are prohibited"

    # 3. Check IPv4 networks
    if isinstance(ip, ipaddress.IPv4Address):
        # Cloud metadata explicit check
        if str(ip) == "169.254.169.254":
            return False, "cloud metadata service (169.254.169.254) is prohibited"

        # Link-local
        if ip.is_link_local:
            return False, "link-local addresses are prohibited"

        # Private RFC 1918
        if ip.is_private:
            if allow_private_rfc1918:
                return True, "explicitly authorized private network destination"
            return False, "private RFC 1918 networks are prohibited"

        for net in _DENIED_IPV4_NETWORKS:
            if ip in net:
                return False, f"destination IP falls in reserved/denied network {net}"

    # 4. Check IPv6 networks
    elif isinstance(ip, ipaddress.IPv6Address):
        if ip.is_link_local:
            return False, "IPv6 link-local addresses are prohibited"

        if ip.is_private:
            if allow_private_rfc1918:
                return True, "explicitly authorized private network destination"
            return False, "IPv6 Unique Local Addresses (fc00::/7) are prohibited"

        for net in _DENIED_IPV6_NETWORKS:
            if ip in net:
                return False, f"destination IPv6 falls in reserved/denied network {net}"

    return True, "public routable address permitted"


def resolve_and_validate_target(
    url: str,
    *,
    allow_loopback_lab: bool = False,
    allow_private_rfc1918: bool = False,
    dns_resolver: object | None = None,
) -> TargetAddress:
    """Parse a URL, resolve its host, audit all IPs against anti-SSRF rules, and pin the address."""
    if not isinstance(url, str) or len(url) > 2048:
        raise SSRFPolicyError("URL must be a string up to 2048 characters.")

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SSRFPolicyError("Scheme must be http or https.")
    if not parts.hostname:
        raise SSRFPolicyError("URL authority is missing a valid hostname.")
    if parts.username or parts.password:
        raise SSRFPolicyError("User credentials in URL authority are prohibited.")

    hostname = parts.hostname.strip().lower().rstrip(".")
    if hostname in _BLOCKED_METADATA_HOSTNAMES:
        raise SSRFPolicyError(f"Target hostname '{hostname}' is a reserved metadata endpoint.")

    scheme: Literal["http", "https"] = "https" if parts.scheme == "https" else "http"
    port = parts.port or (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise SSRFPolicyError("Port number must be between 1 and 65535.")

    # Check if hostname is already a literal IP
    try:
        literal_ip = ipaddress.ip_address(hostname)
        allowed, reason = classify_ip_address(
            literal_ip,
            allow_loopback_lab=allow_loopback_lab,
            allow_private_rfc1918=allow_private_rfc1918,
        )
        if not allowed:
            raise SSRFPolicyError(f"Target IP {literal_ip} rejected: {reason}")
        return TargetAddress(
            hostname=hostname,
            port=port,
            scheme=scheme,
            pinned_ip=str(literal_ip),
            ip_version=literal_ip.version,
        )
    except ValueError:
        pass  # Hostname is a domain name, proceed to DNS resolution

    # Resolve hostname via getaddrinfo
    try:
        # Resolve both IPv4 and IPv6 stream sockets
        addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFPolicyError(f"DNS resolution failed for {hostname}: {exc}") from exc

    if not addr_info:
        raise SSRFPolicyError(f"DNS resolution returned no addresses for {hostname}.")

    # Multi-address audit: ALL resolved IPs must be clean
    validated_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        ip_obj = ipaddress.ip_address(ip_str)
        allowed, reason = classify_ip_address(
            ip_obj,
            allow_loopback_lab=allow_loopback_lab,
            allow_private_rfc1918=allow_private_rfc1918,
        )
        if not allowed:
            raise SSRFPolicyError(f"DNS for {hostname} resolved to denied IP {ip_str}: {reason}")
        validated_ips.append(ip_obj)

    # Pin the first validated IP address (prefer IPv4 if available)
    ipv4_candidates = [ip for ip in validated_ips if ip.version == 4]
    chosen_ip = ipv4_candidates[0] if ipv4_candidates else validated_ips[0]

    return TargetAddress(
        hostname=hostname,
        port=port,
        scheme=scheme,
        pinned_ip=str(chosen_ip),
        ip_version=chosen_ip.version,
    )


def create_pinned_socket(
    target: TargetAddress,
    *,
    timeout: float = 5.0,
    ssl_context: ssl.SSLContext | None = None,
) -> socket.socket | ssl.SSLSocket:
    """Establish a direct TCP (or TLS) connection bound directly to the pinned IP.

    Prevents DNS rebinding by sending packets only to the pinned IP while preserving
    correct TLS SNI and server certificate validation for the original hostname.
    """
    family = socket.AF_INET if target.ip_version == 4 else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target.pinned_ip, target.port))
        if target.scheme == "https":
            ctx = ssl_context or ssl.create_default_context()
            tls_sock = ctx.wrap_socket(sock, server_hostname=target.hostname)
            return tls_sock
        return sock
    except Exception:
        sock.close()
        raise


def validate_redirect_location(
    current_url: str,
    redirect_location: str,
    *,
    allow_loopback_lab: bool = False,
    allow_private_rfc1918: bool = False,
) -> TargetAddress:
    """Validate an HTTP 3xx redirect location before following it.

    Ensures that a public endpoint cannot redirect an assessment worker to an internal
    cloud metadata or private address.
    """
    current_parts = urlsplit(current_url)

    # Handle relative redirects
    if redirect_location.startswith("/"):
        reconstructed = urlunsplit(
            (
                current_parts.scheme,
                current_parts.netloc,
                redirect_location,
                "",
                "",
            )
        )
    elif not redirect_location.startswith(("http://", "https://")):
        # Resolve against current path base
        base_path = current_parts.path.rsplit("/", 1)[0]
        reconstructed = urlunsplit(
            (
                current_parts.scheme,
                current_parts.netloc,
                f"{base_path}/{redirect_location}",
                "",
                "",
            )
        )
    else:
        reconstructed = redirect_location

    new_parts = urlsplit(reconstructed)

    # Disallow HTTPS -> HTTP downgrades
    if current_parts.scheme == "https" and new_parts.scheme == "http":
        raise SSRFPolicyError("Insecure redirect downgrade from HTTPS to HTTP is prohibited.")

    return resolve_and_validate_target(
        reconstructed,
        allow_loopback_lab=allow_loopback_lab,
        allow_private_rfc1918=allow_private_rfc1918,
    )


__all__ = [
    "SSRFPolicyError",
    "TargetAddress",
    "classify_ip_address",
    "create_pinned_socket",
    "resolve_and_validate_target",
    "validate_redirect_location",
]
