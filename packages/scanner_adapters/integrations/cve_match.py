"""Sector O1: live-target component fingerprinting -> grounded version->CVE matching.

Extracts concrete product versions observed in HTTP responses (Server, X-Powered-By,
X-AspNet-Version, X-Generator) and matches them against advisory records that carry affected
version ranges. Every CVE claim is therefore grounded in an *observed version* that falls inside
an affected range -- never a bare banner substring ("apache present" is not a finding; "Apache
2.4.49, which is in the affected range of CVE-2021-41773" is).

Advisory sources are injectable: a bundled curated set of real, high-signal web-stack CVEs is the
default; a live OSV/NVD source can be supplied for full coverage. Findings are emitted as
`suspected` (a version match is strong evidence of exposure, but not exploit-verified).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Protocol

# product/version pairs inside a header value, e.g. "Apache/2.4.49 (Unix) OpenSSL/3.0.1 PHP/8.1.2"
_PAIR = re.compile(r"([A-Za-z][A-Za-z0-9_+-]*)/(\d+(?:\.\d+){1,3})")
# normalise the many spellings of a product to one key
_PRODUCT_ALIASES = {
    "apache": "apache_http_server",
    "httpd": "apache_http_server",
    "nginx": "nginx",
    "openssl": "openssl",
    "php": "php",
    "microsoft-iis": "iis",
    "iis": "iis",
}


def parse_version(value: str) -> tuple[int, ...]:
    """Numeric version tuple, e.g. '2.4.49' -> (2, 4, 49). Non-numeric suffixes are dropped."""
    return tuple(int(p) for p in re.findall(r"\d+", value)) or (0,)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    a2 = a + (0,) * (width - len(a))
    b2 = b + (0,) * (width - len(b))
    return (a2 > b2) - (a2 < b2)


def version_in_range(version: str, introduced: str, fixed: str | None) -> bool:
    """True when introduced <= version < fixed (fixed=None means all versions >= introduced)."""
    v = parse_version(version)
    if _cmp(v, parse_version(introduced)) < 0:
        return False
    if fixed is not None and _cmp(v, parse_version(fixed)) >= 0:
        return False
    return True


@dataclass(frozen=True)
class Advisory:
    cve: str
    product: str  # normalised product key (see _PRODUCT_ALIASES values)
    introduced: str  # inclusive lower bound
    fixed: str | None  # exclusive upper bound; None = unbounded above
    severity: str
    cwe: str
    title: str


class AdvisorySource(Protocol):
    def for_product(self, product: str) -> list[Advisory]:
        ...


# A small, curated set of real, header-observable web-stack CVEs with correct affected ranges.
# This is honest ground truth, not an exhaustive feed; a live OSV/NVD source plugs in via the
# AdvisorySource protocol for full coverage.
BUNDLED_ADVISORIES: list[Advisory] = [
    Advisory("CVE-2021-41773", "apache_http_server", "2.4.49", "2.4.50", "critical", "CWE-22",
             "Apache HTTP Server path traversal and RCE"),
    Advisory("CVE-2021-42013", "apache_http_server", "2.4.49", "2.4.51", "critical", "CWE-22",
             "Apache HTTP Server path traversal/RCE (incomplete fix for CVE-2021-41773)"),
    Advisory("CVE-2019-20372", "nginx", "0.7.12", "1.17.7", "medium", "CWE-444",
             "nginx error_page request smuggling"),
    Advisory("CVE-2022-3786", "openssl", "3.0.0", "3.0.7", "high", "CWE-787",
             "OpenSSL X.509 punycode buffer overflow"),
    Advisory("CVE-2024-4577", "php", "8.1.0", "8.1.29", "critical", "CWE-78",
             "PHP-CGI Windows argument injection RCE"),
    Advisory("CVE-2024-4577", "php", "8.2.0", "8.2.20", "critical", "CWE-78",
             "PHP-CGI Windows argument injection RCE"),
    Advisory("CVE-2024-4577", "php", "8.3.0", "8.3.8", "critical", "CWE-78",
             "PHP-CGI Windows argument injection RCE"),
]


@dataclass
class StaticAdvisorySource:
    advisories: list[Advisory] = field(default_factory=lambda: list(BUNDLED_ADVISORIES))

    def for_product(self, product: str) -> list[Advisory]:
        return [a for a in self.advisories if a.product == product]


def fingerprint_versions(headers: list[tuple[str, str]]) -> list[dict[str, str]]:
    """Extract concrete (product, version) pairs observed in response headers.

    Only headers that legitimately carry software versions are read; only numeric versions are kept.
    """
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for name, value in headers:
        lname = name.lower()
        if lname in ("server", "x-powered-by", "x-generator", "x-backend-server"):
            for raw_product, version in _PAIR.findall(value):
                product = _PRODUCT_ALIASES.get(raw_product.lower(), raw_product.lower())
                key = (product, version)
                if key not in seen:
                    seen.add(key)
                    found.append({"product": product, "version": version, "source": lname})
        elif lname == "x-aspnet-version" and re.fullmatch(r"\d+(?:\.\d+){1,3}", value.strip()):
            key = ("asp.net", value.strip())
            if key not in seen:
                seen.add(key)
                found.append({"product": "asp.net", "version": value.strip(), "source": lname})
    return found


def match_product(product: str, version: str, source: AdvisorySource | None = None) -> list[Advisory]:
    src = source or StaticAdvisorySource()
    return [a for a in src.for_product(product) if version_in_range(version, a.introduced, a.fixed)]


def scan_known_cves(
    observed_versions: list[dict[str, str]], source: AdvisorySource | None = None
) -> list[dict[str, object]]:
    """Grounded CVE findings for observed component versions. Deduplicated by (product, version, cve)."""
    src = source or StaticAdvisorySource()
    findings: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in observed_versions:
        product, version = item.get("product", ""), item.get("version", "")
        src_header = item.get("source", "response header")
        if not product or not version:
            continue
        for adv in match_product(product, version, src):
            key = f"{product}:{version}:{adv.cve}"
            if key in seen:
                continue
            seen.add(key)
            fp = hashlib.sha256(f"known_cve:{key}".encode()).hexdigest()
            findings.append(
                {
                    "category": "known_vulnerable_component",
                    "severity": adv.severity,
                    "title": f"{adv.cve}: {adv.title} (observed {product} {version})",
                    "description": (
                        f"The observed component {product} {version} (from the {src_header} header) "
                        f"falls within the affected range of {adv.cve} "
                        f"[{adv.introduced} <= version < {adv.fixed or 'any'}]. This is a version-based "
                        f"match grounded in an observed version, not an exploit-verified finding."
                    ),
                    "remediation": f"Upgrade {product} to a version at or above {adv.fixed or 'the fixed release'}.",
                    "fingerprint": fp,
                    "confidence": "medium",
                    "status": "suspected",
                    "cwe_id": adv.cwe,
                    "cve_id": adv.cve,
                    "attributes": {
                        "product": product,
                        "version": version,
                        "cve": adv.cve,
                        "affected_range": f"[{adv.introduced}, {adv.fixed or 'inf'})",
                        "source_header": src_header,
                    },
                }
            )
    return findings


__all__ = [
    "Advisory",
    "AdvisorySource",
    "StaticAdvisorySource",
    "BUNDLED_ADVISORIES",
    "parse_version",
    "version_in_range",
    "fingerprint_versions",
    "match_product",
    "scan_known_cves",
]
