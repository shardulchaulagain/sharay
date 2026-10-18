"""Target Normalizer (A1) for SHARAY.

Pure, deterministic, and idempotent pre-resolution stage.
Transforms raw, untrusted target strings into canonical NormalizedTarget objects.

Invariants:
- Strips schemes, credentials, ports, paths, queries, and fragments cleanly.
- Scrubs whitespace, CRLF, zero-width characters, non-breaking spaces, and en-dashes.
- Punycodes Internationalized Domain Names (IDN).
- Detects literal IPv4 and IPv6 addresses via inet_pton / ipaddress to skip DNS.
- Expands CIDR blocks and IP ranges into discrete target representations with bounds.
- Never raises uncaught exceptions on malformed input; raises typed NormalizationError.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass

try:
    import idna
except ImportError:
    idna = None  # type: ignore[assignment]


class NormalizationError(ValueError):
    """Raised when an input cannot be parsed or normalized into a valid target."""

    def __init__(self, code: str, message: str, raw_input: str) -> None:
        super().__init__(f"[{code}] {message} (raw: {raw_input!r})")
        self.code = code
        self.message = message
        self.raw_input = raw_input


@dataclass(frozen=True)
class NormalizedTarget:
    """Canonical representation of an assessment destination."""

    original: str
    host: str
    port: int | None
    scheme: str
    path: str
    is_literal_ip: bool
    is_ipv6: bool

    @property
    def url(self) -> str:
        """Reconstruct canonical base URL."""
        port_suffix = f":{self.port}" if self.port is not None else ""
        host_repr = f"[{self.host}]" if self.is_ipv6 else self.host
        clean_path = self.path if self.path.startswith("/") else f"/{self.path}"
        return f"{self.scheme}://{host_repr}{port_suffix}{clean_path}"

    @property
    def origin(self) -> str:
        """Origin representation (scheme + host + port)."""
        port_suffix = f":{self.port}" if self.port is not None else ""
        host_repr = f"[{self.host}]" if self.is_ipv6 else self.host
        return f"{self.scheme}://{host_repr}{port_suffix}"

    def to_dict(self) -> dict[str, str | int | bool | None]:
        return {
            "original": self.original,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "path": self.path,
            "is_literal_ip": self.is_literal_ip,
            "is_ipv6": self.is_ipv6,
            "url": self.url,
            "origin": self.origin,
        }


# Zero-width spaces, byte order marks, directional marks, non-breaking spaces
_ZERO_WIDTH_CHARS = re.compile(r"[\u200b\u200c\u200d\ufeff\u200e\u200f\u202a-\u202e]")
_EN_EM_DASHES = re.compile(r"[\u2010\u2011\u2012\u2013\u2014\u2015]")
_VALID_HOSTNAME = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_IP_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
MAX_EXPANSION_LIMIT = 1024


class TargetNormaliser:
    """Pure idempotent target pre-processing engine."""

    @staticmethod
    def scrub(raw: str) -> str:
        """Scrub hidden unicode characters, normalize dashes, and trim whitespace."""
        if not isinstance(raw, str):
            raise NormalizationError("INVALID_TYPE", "Target input must be a string", str(raw))

        # 1. Strip zero-width and directional marks
        cleaned = _ZERO_WIDTH_CHARS.sub("", raw)

        # 2. Convert non-breaking spaces to standard space
        cleaned = cleaned.replace("\u00a0", " ")

        # 3. Normalize typographic dashes to ASCII hyphen
        cleaned = _EN_EM_DASHES.sub("-", cleaned)

        # 4. Strip CRLF, tabs, and standard leading/trailing whitespace
        cleaned = cleaned.strip(" \t\r\n\0")
        return cleaned

    @classmethod
    def _punycode_host(cls, host: str, original: str) -> str:
        """Punycode an Internationalized Domain Name (IDN)."""
        host = host.rstrip(".").lower()
        if not host:
            raise NormalizationError("EMPTY_HOST", "Hostname cannot be empty", original)

        # Fast path for ASCII hostnames
        try:
            host.encode("ascii")
            return host
        except UnicodeEncodeError:
            pass

        if idna is not None:
            try:
                return idna.encode(host, uts46=True).decode("ascii").lower()
            except Exception as exc:
                raise NormalizationError(
                    "IDN_ENCODE_FAILED", f"Failed to punycode internationalized domain: {exc}", original
                ) from exc
        else:
            try:
                import encodings.idna

                parts = [encodings.idna.ToASCII(label).decode("ascii") for label in host.split(".")]
                return ".".join(parts).lower()
            except Exception as exc:
                raise NormalizationError(
                    "IDN_ENCODE_FAILED", f"Failed to punycode internationalized domain: {exc}", original
                ) from exc

    @classmethod
    def normalize_single(cls, raw: str, default_scheme: str = "https") -> NormalizedTarget:
        """Normalize a single target string (host, URL, or literal IP)."""
        cleaned = cls.scrub(raw)
        if not cleaned:
            raise NormalizationError("EMPTY_TARGET", "Target cannot be empty", raw)

        scheme = default_scheme
        port: int | None = None
        path = "/"

        # Check if full URL provided
        if "://" in cleaned:
            parsed = urllib.parse.urlsplit(cleaned)
            scheme = parsed.scheme.lower() or default_scheme
            if scheme not in ("http", "https"):
                raise NormalizationError("UNSUPPORTED_SCHEME", f"Unsupported scheme: {scheme}", raw)

            # Strip userinfo (user:pass@host)
            netloc = parsed.netloc
            if "@" in netloc:
                netloc = netloc.split("@")[-1]

            # Parse host and port
            if netloc.startswith("["):
                # IPv6 literal with brackets
                bracket_end = netloc.find("]")
                if bracket_end == -1:
                    raise NormalizationError("MALFORMED_IPV6", "Malformed IPv6 address brackets", raw)
                host_part = netloc[1:bracket_end]
                port_part = netloc[bracket_end + 1 :]
                if port_part.startswith(":"):
                    try:
                        port = int(port_part[1:])
                    except ValueError:
                        raise NormalizationError("INVALID_PORT", f"Invalid port: {port_part}", raw)
            elif ":" in netloc:
                host_part, port_str = netloc.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    raise NormalizationError("INVALID_PORT", f"Invalid port: {port_str}", raw)
            else:
                host_part = netloc

            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        else:
            # Bare host:port, bare IPv6, or bare host
            # Check for bracketed IPv6
            if cleaned.startswith("["):
                bracket_end = cleaned.find("]")
                if bracket_end == -1:
                    raise NormalizationError("MALFORMED_IPV6", "Malformed IPv6 address brackets", raw)
                host_part = cleaned[1:bracket_end]
                port_part = cleaned[bracket_end + 1 :]
                if port_part.startswith(":"):
                    try:
                        port = int(port_part[1:])
                    except ValueError:
                        raise NormalizationError("INVALID_PORT", f"Invalid port: {port_part}", raw)
            elif "/" in cleaned and not cleaned.startswith("/"):
                # host/path without scheme
                host_part, _, path_part = cleaned.partition("/")
                path = f"/{path_part}"
                if ":" in host_part:
                    host_part, port_str = host_part.rsplit(":", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        raise NormalizationError("INVALID_PORT", f"Invalid port: {host_part}:{port_str}", raw)
            elif ":" in cleaned and not cleaned.count(":") > 1:
                # host:port (single colon, not IPv6)
                host_part, port_str = cleaned.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    raise NormalizationError("INVALID_PORT", f"Invalid port: {port_str}", raw)
            else:
                host_part = cleaned

        # Validate port range
        if port is not None and not (1 <= port <= 65535):
            raise NormalizationError("PORT_OUT_OF_RANGE", f"Port must be between 1 and 65535: {port}", raw)

        # Check if literal IP
        is_literal_ip = False
        is_ipv6 = False
        try:
            ip_obj = ipaddress.ip_address(host_part)
            is_literal_ip = True
            is_ipv6 = ip_obj.version == 6
            host_final = str(ip_obj)
        except ValueError:
            # Punycode and validate hostname
            host_final = cls._punycode_host(host_part, raw)
            if not _VALID_HOSTNAME.match(host_final):
                raise NormalizationError("INVALID_HOSTNAME", f"Invalid hostname syntax: {host_final}", raw)

        return NormalizedTarget(
            original=raw,
            host=host_final,
            port=port,
            scheme=scheme,
            path=path,
            is_literal_ip=is_literal_ip,
            is_ipv6=is_ipv6,
        )

    @classmethod
    def normalize(
        cls,
        raw: str,
        default_scheme: str = "https",
        max_expansion: int = MAX_EXPANSION_LIMIT,
    ) -> list[NormalizedTarget]:
        """Normalize raw input, expanding CIDRs and IP ranges if present."""
        cleaned = cls.scrub(raw)
        if not cleaned:
            raise NormalizationError("EMPTY_TARGET", "Target cannot be empty", raw)

        # 1. Check for CIDR block (e.g. 192.168.1.0/29 or 2001:db8::/126)
        if "/" in cleaned and not cleaned.startswith("/") and "://" not in cleaned:
            prefix, _, mask = cleaned.partition("/")
            if mask.isdigit():
                try:
                    network = ipaddress.ip_network(cleaned, strict=False)
                    num_addrs = network.num_addresses
                    if num_addrs > max_expansion:
                        raise NormalizationError(
                            "CIDR_TOO_LARGE",
                            f"CIDR block expands to {num_addrs} hosts (limit is {max_expansion})",
                            raw,
                        )
                    hosts = list(network)
                    return [
                        NormalizedTarget(
                            original=raw,
                            host=str(ip),
                            port=None,
                            scheme=default_scheme,
                            path="/",
                            is_literal_ip=True,
                            is_ipv6=ip.version == 6,
                        )
                        for ip in hosts
                    ]
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                    pass  # Not a valid CIDR network; fall through to single normalizer

        # 2. Check for hyphenated IPv4 range (e.g. 10.0.0.1-4)
        range_match = _IP_RANGE.match(cleaned)
        if range_match:
            subnet_prefix = range_match.group(1)
            start_num = int(range_match.group(2))
            end_num = int(range_match.group(3))
            if start_num > end_num:
                start_num, end_num = end_num, start_num
            count = end_num - start_num + 1
            if count > max_expansion:
                raise NormalizationError(
                    "RANGE_TOO_LARGE",
                    f"IP range expands to {count} hosts (limit is {max_expansion})",
                    raw,
                )
            results: list[NormalizedTarget] = []
            for num in range(start_num, end_num + 1):
                ip_str = f"{subnet_prefix}{num}"
                # Validate valid octet
                try:
                    ipaddress.IPv4Address(ip_str)
                    results.append(
                        NormalizedTarget(
                            original=raw,
                            host=ip_str,
                            port=None,
                            scheme=default_scheme,
                            path="/",
                            is_literal_ip=True,
                            is_ipv6=False,
                        )
                    )
                except ValueError as exc:
                    raise NormalizationError(
                        "INVALID_IP_RANGE", f"Invalid IP in range: {ip_str}", raw
                    ) from exc
            return results

        # Single target
        return [cls.normalize_single(cleaned, default_scheme=default_scheme)]


__all__ = ["TargetNormaliser", "NormalizedTarget", "NormalizationError", "MAX_EXPANSION_LIMIT"]
