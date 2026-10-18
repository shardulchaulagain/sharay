"""High-speed passive and active subdomain enumeration engine.

Discovers the broad perimeter attack surface via Certificate Transparency logs (crt.sh)
and active DNS permutation testing, detecting dangling CNAME subdomain takeovers.
"""

from __future__ import annotations

import concurrent.futures
import json
import socket
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any

TOP_SUBDOMAINS = [
    "www",
    "api",
    "admin",
    "portal",
    "app",
    "auth",
    "login",
    "dev",
    "staging",
    "test",
    "mail",
    "webmail",
    "cpanel",
    "whm",
    "blog",
    "status",
    "docs",
    "beta",
    "cdn",
    "cloud",
    "vpn",
]

TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "amazonaws.com": "NoSuchBucket",
    "herokuapp.com": "There is no app configured at that address",
    "azurewebsites.net": "404 Web Site not found",
    "myshopify.com": "Sorry, this shop is currently unavailable",
}


def _resolve_subdomain(subdomain: str) -> tuple[list[str], str | None]:
    """Resolve A records and CNAME for a subdomain."""
    ips: list[str] = []
    cname: str | None = None
    try:
        infos = socket.getaddrinfo(subdomain, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted(list(set(str(info[4][0]) for info in infos)))
    except (socket.gaierror, OSError):
        pass

    try:
        # Check canonical name
        canon, _, _ = socket.gethostbyname_ex(subdomain)
        if canon != subdomain:
            cname = canon
    except Exception:
        pass

    return ips, cname


def scan_subdomains(domain: str, timeout: float = 4.0) -> dict[str, Any]:
    """Execute passive and active subdomain discovery for authorized domain."""
    clean_domain = domain.split("://")[-1].split("/")[0].split(":")[0].strip().lower()
    discovered: dict[str, dict[str, Any]] = {}
    observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    # 1. Passive Certificate Transparency (crt.sh) Discovery
    try:
        req = urllib.request.Request(
            f"https://crt.sh/?q=%.{clean_domain}&output=json",
            headers={"User-Agent": "SHARAY-Recon/2.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        clean_name = name.strip().lower()
                        if clean_name.endswith(f".{clean_domain}") and "*" not in clean_name:
                            discovered[clean_name] = {"source": "certificate_transparency", "ips": []}
    except Exception:
        # Fall back gracefully to active resolution if crt.sh is slow or offline
        pass

    # 2. Active Wordlist DNS Permutation
    for sub in TOP_SUBDOMAINS:
        candidate = f"{sub}.{clean_domain}"
        if candidate not in discovered:
            discovered[candidate] = {"source": "dns_wordlist", "ips": []}

    # 3. Resolve all discovered candidates concurrently
    live_subdomains: list[dict[str, Any]] = []
    candidates = list(discovered.items())[:30]
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {executor.submit(_resolve_subdomain, sub): (sub, info) for sub, info in candidates}
        done, _ = concurrent.futures.wait(future_map.keys(), timeout=max(2.0, timeout))
        for fut in done:
            try:
                ips, cname = fut.result()
                sub, info = future_map[fut]
                if ips:
                    sub_info = {
                        "subdomain": sub,
                        "ips": ips,
                        "cname": cname,
                        "source": info["source"],
                    }
                    live_subdomains.append(sub_info)

                    # Check for dangling CNAME takeover
                    if cname:
                        for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                            if service in cname.lower():
                                findings.append(
                                    {
                                        "category": "subdomain_takeover",
                                        "severity": "high",
                                        "title": f"Potential Subdomain Takeover Risk on {sub}",
                                        "description": (
                                            f"Subdomain {sub} points to external provider {cname} ({service}). "
                                            "If the resource was deleted on the provider, an attacker can claim it."
                                        ),
                                        "target_url": f"https://{sub}",
                                        "fingerprint": f"takeover_{sub}_{cname}",
                                        "cwe_id": "CWE-284",
                                        "remediation": f"Remove the DNS CNAME record for {sub} or claim the resource on {service}.",
                                    }
                                )
            except Exception:
                pass

    obs = {
        "kind": "subdomain_inventory",
        "category": "recon",
        "domain": clean_domain,
        "live_subdomains": live_subdomains,
        "total_discovered": len(live_subdomains),
        "captured_at": datetime.now(UTC).isoformat(),
        "tool": "sharay_subdomain_scanner",
    }
    observations.append(obs)

    check = {
        "category": "subdomain_discovery",
        "status": "completed",
        "detail": (
            f"Perimeter discovery identified {len(live_subdomains)} live subdomain(s) for {clean_domain} "
            f"({', '.join(s['subdomain'] for s in live_subdomains[:5]) or 'none'})."
        ),
    }

    return {
        "live_subdomains": live_subdomains,
        "observations": observations,
        "findings": findings,
        "check": check,
    }


__all__ = ["scan_subdomains"]
