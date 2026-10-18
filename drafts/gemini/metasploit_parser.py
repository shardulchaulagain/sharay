"""Metasploit structured auxiliary and validation output parser (L4).

Strict parser for structured Metasploit auxiliary scan and bounded validation output.
Never executes console commands, never launches exploits, and never retains memory
dumps, raw packet captures or un-sanitized credentials.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from packages.scanner_adapters.integrations._parsing import (
    MAX_FINDINGS,
    MAX_REPORT_BYTES,
    fingerprint,
    label,
    load_json,
    shown,
    text,
)

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,7}$", re.IGNORECASE)
_MODULE_RE = re.compile(r"^(?:auxiliary|exploit|post)/[A-Za-z0-9_/-]{3,150}$")


def _validate_host(value: object) -> str:
    raw = text(value, "Metasploit host", 253)
    try:
        ip = ipaddress.ip_address(raw)
        return f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        if not _HOST_RE.match(raw) or raw.startswith("-"):
            raise ValueError("Metasploit host is not a valid IP or hostname.")
        return raw


def _validate_port(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Metasploit port is not an integer in 1-65535.")
    return value


def _validate_proto(value: object) -> str:
    raw = str(value).lower().strip()
    if raw not in ("tcp", "udp"):
        raise ValueError("Metasploit protocol must be 'tcp' or 'udp'.")
    return raw


def _clean_cves(raw_cves: object) -> list[str]:
    if not isinstance(raw_cves, (list, tuple)):
        return []
    cleaned: list[str] = []
    for item in raw_cves:
        if isinstance(item, str) and _CVE_RE.match(item.strip()):
            cleaned.append(item.strip().upper())
    return sorted(set(cleaned))


def parse(data: bytes) -> dict[str, Any]:
    """Parse Metasploit structured JSON report; return {'findings': [...], 'truncated': bool}."""
    if not isinstance(data, bytes) or len(data) > MAX_REPORT_BYTES:
        raise ValueError("Metasploit output is not bytes within the parsing budget.")

    root = load_json(data, "Metasploit report")
    if not isinstance(root, dict):
        raise ValueError("Metasploit report root is not an object.")

    module_name = text(root.get("module", "auxiliary/scanner/generic"), "Metasploit module", 150)
    if not _MODULE_RE.match(module_name):
        raise ValueError("Metasploit module name is not a valid module path.")

    results = root.get("results")
    if not isinstance(results, list):
        raise ValueError("Metasploit report 'results' is not a list.")

    findings: list[dict[str, Any]] = []

    for item in results:
        if not isinstance(item, dict):
            raise ValueError("Metasploit result entry is not an object.")

        host = _validate_host(item.get("host"))
        port = _validate_port(item.get("port"))
        proto = _validate_proto(item.get("proto", "tcp"))
        matched_at = f"{host}:{port}/{proto}"

        vulnerable = bool(item.get("vulnerable", False))
        service_name = str(item.get("service_name", "unknown")).lower().strip()
        service = text(service_name, "Metasploit service name", 50) if service_name else "unknown"

        info_raw = item.get("info", "")
        info_label = label(info_raw, 250) or module_name

        cves = _clean_cves(item.get("cve"))

        # Severity classification:
        # If explicitly confirmed vulnerable with CVE -> high
        # If vulnerable without CVE -> medium
        # If open service indicator / banner -> info
        if vulnerable:
            severity = "high" if cves else "medium"
            confidence = "high"
        else:
            severity = "info"
            confidence = "high"

        if len(findings) < MAX_FINDINGS:
            findings.append(
                {
                    "module": shown(module_name),
                    "name": info_label,
                    "severity": severity,
                    "confidence": confidence,
                    "matched_at": matched_at,
                    "service": shown(service),
                    "vulnerable": vulnerable,
                    "cve": cves,
                    "fingerprint": fingerprint("msf", module_name, host, port, proto),
                }
            )

    return {
        "findings": findings,
        "truncated": len(results) > MAX_FINDINGS,
    }


__all__ = ["parse"]
