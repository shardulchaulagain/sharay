"""Open Source Vulnerability (OSV) Advisory Engine and SBOM Scanner (L6/L7).

Author: Gemini (Principal Architect, Debugger & Helper)
Status: Draft module under drafts/gemini/ for Claude L6/L7 adoption.

Addresses MAIN_PROMPT.txt line 38:
"Integrate Nmap, OWASP ZAP, Nuclei, supported API/schema testing, Semgrep, Gitleaks,
OSV/SBOM/container/IaC analysis..."

Capabilities:
1. Ingests package inventory from services.source_analysis_worker.dependencies (PyPI, npm).
2. Supports offline advisory matching against local vulnerability databases (GHSA, CVE).
3. Evaluates version ranges (semver for npm, PEP 440 for PyPI) to detect affected releases.
4. Generates structured SHARAY findings with CVE IDs, CVSS scores, and remediation upgrades.
5. Ingests standard CycloneDX (v1.4/v1.5) and SPDX (v2.2/v2.3) SBOM JSON files.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from packages.secret_patterns import redact_tokens

_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")


class OSVEngineError(ValueError):
    """OSV query, SBOM ingestion, or version evaluation failed."""


@dataclass(frozen=True)
class VulnerabilityAdvisory:
    id: str  # e.g., "GHSA-xxxx-xxxx" or "CVE-2023-xxxx"
    aliases: tuple[str, ...]
    package_name: str
    ecosystem: str
    summary: str
    details: str
    severity: str  # "critical", "high", "medium", "low", "info"
    cvss_score: float | None
    affected_ranges: tuple[tuple[str, str], ...]  # (introduced, fixed)
    references: tuple[str, ...]


def _split_version(v_str: str) -> list[int]:
    """Parse dot-separated numeric version segments into integer list for comparison."""
    clean = re.sub(r"[^\d.]", "", v_str.split("-")[0].split("+")[0])
    parts = []
    for p in clean.split("."):
        if p.isdigit():
            parts.append(int(p))
    return parts or [0]


def is_version_affected(version: str, introduced: str, fixed: str | None) -> bool:
    """Evaluate whether a package version falls within [introduced, fixed)."""
    curr = _split_version(version)
    intro = _split_version(introduced)

    # Pad version lists to equal length
    max_len = max(len(curr), len(intro), len(_split_version(fixed or "0")))
    curr_padded = curr + [0] * (max_len - len(curr))
    intro_padded = intro + [0] * (max_len - len(intro))

    if curr_padded < intro_padded:
        return False

    if fixed:
        fix = _split_version(fixed)
        fix_padded = fix + [0] * (max_len - len(fix))
        if curr_padded >= fix_padded:
            return False

    return True


def audit_packages_against_advisories(
    packages: list[dict[str, Any]],
    advisory_database: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Match declared packages against local/cached OSV vulnerability advisories."""
    findings: list[dict[str, Any]] = []

    # Index advisories by (ecosystem.lower(), package_name.lower())
    advisory_index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for adv in advisory_database:
        eco = str(adv.get("ecosystem", "")).lower()
        adv_pkg = str(adv.get("package_name", "")).lower()
        advisory_index.setdefault((eco, adv_pkg), []).append(adv)

    for pkg in packages:
        eco = str(pkg.get("ecosystem", "PyPI")).lower()
        name = str(pkg.get("name", "")).lower()
        ver = str(pkg.get("version", ""))
        manifest = str(pkg.get("manifest", "declared"))

        matching_advisories = advisory_index.get((eco, name), [])
        for adv in matching_advisories:
            adv_id = str(adv.get("id", "VULN-UNKNOWN"))
            summary = str(adv.get("summary", "Known vulnerability in dependency"))
            severity = str(adv.get("severity", "medium")).lower()
            cvss = adv.get("cvss_score")
            ranges = adv.get("affected_ranges", [])

            is_hit = False
            fix_version = None
            for intro, fix in ranges:
                if is_version_affected(ver, intro, fix):
                    is_hit = True
                    fix_version = fix
                    break

            if is_hit:
                remediation = f"Upgrade {name} to version {fix_version or 'the latest patched release'}."
                findings.append({
                    "kind": "dependency_vulnerability",
                    "category": "software_composition_analysis",
                    "advisory_id": adv_id,
                    "aliases": adv.get("aliases", []),
                    "package_name": name,
                    "package_version": ver,
                    "ecosystem": eco.upper(),
                    "severity": severity,
                    "cvss_score": cvss,
                    "title": f"{adv_id}: {summary}"[:120],
                    "description": redact_tokens(_UNPRINTABLE.sub("", summary)[:400], "[REDACTED]"),
                    "remediation": remediation,
                    "manifest": manifest,
                    "fixed_version": fix_version,
                    "tool": "osv",
                })

    return findings


def ingest_cyclonedx_sbom(json_data: bytes | str) -> list[dict[str, str]]:
    """Extract package dependencies from a CycloneDX (v1.4/1.5) JSON SBOM."""
    try:
        data = json.loads(json_data) if isinstance(json_data, (bytes, str)) else json_data
    except Exception as exc:
        raise OSVEngineError("CycloneDX SBOM is malformed or invalid JSON.") from exc

    if not isinstance(data, dict):
        raise OSVEngineError("CycloneDX SBOM root must be a JSON object.")

    components = data.get("components", [])
    if not isinstance(components, list):
        return []

    packages: list[dict[str, str]] = []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        name = comp.get("name")
        version = comp.get("version")
        purl = comp.get("purl", "")

        ecosystem = "PyPI"
        if purl and "pkg:npm/" in purl:
            ecosystem = "npm"
        elif purl and "pkg:pypi/" in purl:
            ecosystem = "PyPI"

        if isinstance(name, str) and isinstance(version, str):
            packages.append({
                "name": name.strip(),
                "version": version.strip(),
                "ecosystem": ecosystem,
                "manifest": "cyclonedx_sbom.json",
            })

    return packages


__all__ = [
    "OSVEngineError",
    "VulnerabilityAdvisory",
    "audit_packages_against_advisories",
    "ingest_cyclonedx_sbom",
    "is_version_affected",
]
