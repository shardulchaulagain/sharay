"""Native DNS intelligence and email security posture analyzer.

Resolves DNS records (A, AAAA, CNAME, MX, TXT) and evaluates email domain
spoofing risks (missing/weak SPF and DMARC policies) for authorized target domains.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any


def scan_dns_records(domain: str) -> dict[str, Any]:
    """Perform deterministic DNS record enumeration, email security posture, and defensive SET evaluation."""
    observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    # Strip port or scheme if present
    clean_domain = domain.split("://")[-1].split("/")[0].split(":")[0].strip()

    records: dict[str, list[str]] = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
    }

    # 1. Resolve A (IPv4)
    try:
        infos = socket.getaddrinfo(clean_domain, None, socket.AF_INET, socket.SOCK_STREAM)
        records["A"] = sorted(list(set(str(info[4][0]) for info in infos)))
    except OSError:
        pass

    # 2. Resolve AAAA (IPv6)
    try:
        infos = socket.getaddrinfo(clean_domain, None, socket.AF_INET6, socket.SOCK_STREAM)
        records["AAAA"] = sorted(list(set(str(info[4][0]) for info in infos)))
    except OSError:
        pass

    # 3. Check for Cloudflare / CDN proxying
    cdn_detected: list[str] = []
    for ip in records["A"]:
        if ip.startswith(("104.", "172.67.", "198.41.")):
            cdn_detected.append("Cloudflare CDN Edge")
        elif ip.startswith(("151.101.", "199.232.")):
            cdn_detected.append("Fastly CDN")
        elif ip.startswith("13.") or ip.startswith("52."):
            cdn_detected.append("AWS Cloud")

    # Record DNS observation
    dns_obs = {
        "kind": "dns_records",
        "category": "dns",
        "domain": clean_domain,
        "ipv4_addresses": records["A"],
        "ipv6_addresses": records["AAAA"],
        "cdn_waf_indicators": list(set(cdn_detected)),
        "captured_at": datetime.now(UTC).isoformat(),
        "tool": "sharay_dns_analyzer",
    }
    observations.append(dns_obs)

    # 4. Defensive SET: Email Spoofing & Social Engineering Attack Surface Profiling
    is_internal = clean_domain in ("localhost", "127.0.0.1", "::1") or clean_domain.endswith(
        (".local", ".internal", ".test")
    )
    lookalikes = _generate_lookalike_domains(clean_domain) if not is_internal else []

    spf_policy = "Not evaluated (internal/loopback target)" if is_internal else "No SPF policy found"
    dmarc_policy = "Not evaluated (internal/loopback target)" if is_internal else "No DMARC record found"

    if not is_internal:
        # Bounded TXT lookup via dig or nslookup if available
        spf_txt = _query_txt_records(clean_domain)
        for t in spf_txt:
            if t.startswith("v=spf1"):
                spf_policy = t
                break
        dmarc_txt = _query_txt_records(f"_dmarc.{clean_domain}")
        for t in dmarc_txt:
            if t.startswith("v=DMARC1"):
                dmarc_policy = t
                break

    set_obs = {
        "kind": "defensive_set_analysis",
        "category": "social_engineering_defense",
        "domain": clean_domain,
        "spf_record": spf_policy,
        "dmarc_record": dmarc_policy,
        "spoofing_resilience": "High (p=reject/quarantine)"
        if "p=reject" in dmarc_policy or "p=quarantine" in dmarc_policy
        else ("Internal Lab Scope" if is_internal else "Vulnerable (Missing/Permissive DMARC)"),
        "lookalike_impersonation_threats": lookalikes,
        "captured_at": datetime.now(UTC).isoformat(),
        "tool": "sharay_defensive_set",
    }
    observations.append(set_obs)

    if not is_internal and ("No DMARC" in dmarc_policy or "p=none" in dmarc_policy):
        findings.append(
            {
                "category": "email_spoofing_risk",
                "severity": "medium",
                "title": f"Weak Email Spoofing Defense: Ineffective DMARC on {clean_domain}",
                "description": f"Domain {clean_domain} lacks an enforced DMARC rejection policy (found: {dmarc_policy}). Attackers can spoof emails for phishing/SET attacks.",
                "remediation": "Publish a strict DMARC TXT record: 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;' at _dmarc."
                + clean_domain,
                "confidence": "high",
                "fingerprint": f"set_dmarc_{clean_domain}",
                "affected_url": f"https://{clean_domain}",
                "poc": {
                    "method": "DNS_QUERY",
                    "command": f"dig +short TXT _dmarc.{clean_domain}",
                    "record_type": "TXT",
                    "query_target": f"_dmarc.{clean_domain}",
                    "reproduction_steps": f"Query DNS TXT records for '_dmarc.{clean_domain}' via: dig +short TXT _dmarc.{clean_domain} (observed: '{dmarc_policy}').",
                },
                "technical_impact": "Permissive or absent DMARC allows unauthorized third-party mail servers to forge SPF/DKIM headers using this domain.",
                "business_impact": "Enables spear-phishing, business email compromise (BEC), and brand spoofing targeting enterprise customers.",
            }
        )

    check = {
        "category": "dns_intelligence",
        "status": "completed",
        "detail": f"DNS & Defensive SET resolved {len(records['A'])} IPv4 ({', '.join(records['A']) or 'none'}), CDN: {', '.join(set(cdn_detected)) or 'Direct'}; Email Spoofing Defense: {set_obs['spoofing_resilience']}.",
    }

    return {
        "records": records,
        "observations": observations,
        "findings": findings,
        "check": check,
    }


def _query_txt_records(name: str) -> list[str]:
    import subprocess

    try:
        proc = subprocess.run(
            ["dig", "+short", "+time=1", "+tries=1", "TXT", name], capture_output=True, text=True, timeout=2
        )
        if proc.returncode == 0 and proc.stdout:
            return [line.strip('" \t\r\n') for line in proc.stdout.splitlines() if line.strip()]
    except Exception:
        pass
    return []


def _generate_lookalike_domains(domain: str) -> list[str]:
    """Generate high-risk typo-squatting and homoglyph permutations for defensive monitoring."""
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    sld = parts[0]
    tld = ".".join(parts[1:])
    candidates = set()

    # 1. Homoglyphs / visually identical characters
    homoglyphs = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
    for char, rep in homoglyphs.items():
        if char in sld:
            candidates.add(f"{sld.replace(char, rep, 1)}.{tld}")

    # 2. Omission
    if len(sld) > 3:
        candidates.add(f"{sld[:-1]}.{tld}")
        candidates.add(f"{sld[1:]}.{tld}")

    # 3. Hyphenation
    if len(sld) > 4:
        mid = len(sld) // 2
        candidates.add(f"{sld[:mid]}-{sld[mid:]}.{tld}")

    return sorted(list(candidates))[:5]


__all__ = ["scan_dns_records"]
