"""Open Source Vulnerability (OSV) advisory ingestion and matching engine (L6).

Parses OpenSSF OSV Schema v1.6 JSON records and evaluates declared dependencies
(from requirements.txt and package-lock.json) against advisory ranges.
Pure standard library: strictly bounded, no network queries, no unvalidated regexes.
"""

from __future__ import annotations

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

_VERSION_SPLIT = re.compile(r"[-_.]+")


def _parse_version_tuple(v_str: str) -> tuple[int | str, ...]:
    """Parse version string into comparable tuple of integers and string segments."""
    parts: list[int | str] = []
    for token in _VERSION_SPLIT.split(v_str.strip()):
        if not token:
            continue
        if token.isdigit():
            parts.append(int(token))
        else:
            parts.append(token.lower())
    return tuple(parts)


def _version_compare(v1: str, v2: str) -> int:
    """Return -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2 (standard numeric/lexical tuple)."""
    t1 = _parse_version_tuple(v1)
    t2 = _parse_version_tuple(v2)
    min_len = min(len(t1), len(t2))
    for i in range(min_len):
        p1, p2 = t1[i], t2[i]
        if isinstance(p1, int) and isinstance(p2, int):
            if p1 < p2:
                return -1
            if p1 > p2:
                return 1
        elif isinstance(p1, str) and isinstance(p2, str):
            if p1 < p2:
                return -1
            if p1 > p2:
                return 1
        elif isinstance(p1, int) and isinstance(p2, str):
            # Numeric segment takes precedence over string segment (e.g. 1.0 > 1.0-alpha)
            return 1
        elif isinstance(p1, str) and isinstance(p2, int):
            return -1
    if len(t1) < len(t2):
        if isinstance(t2[min_len], str):
            return 1
        return -1
    if len(t1) > len(t2):
        if isinstance(t1[min_len], str):
            return -1
        return 1
    return 0


def is_version_vulnerable(version: str, affected_block: dict[str, Any]) -> tuple[bool, str | None]:
    """Check if version is within affected ranges. Returns (is_vulnerable, fixed_version)."""
    # 1. Direct explicit versions list
    explicit_versions = affected_block.get("versions")
    if isinstance(explicit_versions, list) and version in explicit_versions:
        return True, None

    # 2. Range events evaluation
    ranges = affected_block.get("ranges")
    if not isinstance(ranges, list):
        return False, None

    for r in ranges:
        if not isinstance(r, dict):
            continue
        events = r.get("events")
        if not isinstance(events, list):
            continue

        introduced: str | None = None
        fixed: str | None = None
        last_affected: str | None = None

        for event in events:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                introduced = str(event["introduced"]).strip()
            elif "fixed" in event:
                fixed = str(event["fixed"]).strip()
            elif "last_affected" in event:
                last_affected = str(event["last_affected"]).strip()

        # Check introduced constraint
        intro_met = False
        if introduced is None or introduced == "0":
            intro_met = True
        elif _version_compare(version, introduced) >= 0:
            intro_met = True

        if not intro_met:
            continue

        # Check fixed constraint (fixed is strictly upper bound: version < fixed)
        if fixed is not None:
            if _version_compare(version, fixed) < 0:
                return True, fixed
        elif last_affected is not None:
            if _version_compare(version, last_affected) <= 0:
                return True, None
        else:
            # No upper bound specified; open-ended vulnerability
            return True, None

    return False, None


def _extract_cve_ids(advisory: dict[str, Any]) -> list[str]:
    cves: set[str] = set()
    adv_id = str(advisory.get("id", "")).upper()
    if adv_id.startswith("CVE-"):
        cves.add(adv_id)
    aliases = advisory.get("aliases")
    if isinstance(aliases, list):
        for a in aliases:
            if isinstance(a, str) and a.upper().startswith("CVE-"):
                cves.add(a.upper().strip())
    return sorted(cves)


def match_advisories(
    advisories: list[dict[str, Any]],
    declared_dependencies: list[dict[str, str]],
) -> dict[str, Any]:
    """Match a collection of OSV advisories against declared dependencies."""
    findings: list[dict[str, Any]] = []

    # Map (ecosystem.lower(), package.lower()) -> list of declared deps
    dep_map: dict[tuple[str, str], list[dict[str, str]]] = {}
    for dep in declared_dependencies:
        eco = str(dep.get("ecosystem", "")).lower().strip()
        name = str(dep.get("name", "")).lower().strip()
        if eco and name and "version" in dep:
            dep_map.setdefault((eco, name), []).append(dep)

    for adv in advisories:
        if not isinstance(adv, dict):
            continue

        adv_id = text(adv.get("id", "UNKNOWN"), "OSV advisory ID", 100)
        summary = label(adv.get("summary", adv.get("details", adv_id)), 300) or adv_id
        cves = _extract_cve_ids(adv)

        # Map database specific severity
        db_spec = adv.get("database_specific", {})
        sev_raw = ""
        if isinstance(db_spec, dict):
            sev_raw = str(db_spec.get("severity", "")).lower()
        if not sev_raw and isinstance(adv.get("severity"), list):
            sev_raw = "high"  # CVSS present
        severity = sev_raw if sev_raw in ("critical", "high", "medium", "low") else "medium"

        affected = adv.get("affected", [])
        if not isinstance(affected, list):
            continue

        for aff in affected:
            if not isinstance(aff, dict):
                continue
            pkg = aff.get("package", {})
            if not isinstance(pkg, dict):
                continue

            eco = str(pkg.get("ecosystem", "")).strip()
            pkg_name = str(pkg.get("name", "")).strip()
            key = (eco.lower(), pkg_name.lower())

            matching_deps = dep_map.get(key, [])
            for dep in matching_deps:
                dep_ver = dep["version"]
                vulnerable, fixed_ver = is_version_vulnerable(dep_ver, aff)
                if vulnerable and len(findings) < MAX_FINDINGS:
                    manifest = dep.get("manifest", "declared")
                    findings.append(
                        {
                            "advisory_id": shown(adv_id),
                            "name": summary,
                            "severity": severity,
                            "package": shown(pkg_name),
                            "ecosystem": shown(eco),
                            "installed_version": shown(dep_ver),
                            "fixed_version": shown(fixed_ver) if fixed_ver else None,
                            "manifest": shown(manifest),
                            "cve": cves,
                            "fingerprint": fingerprint("osv", adv_id, eco, pkg_name, dep_ver),
                        }
                    )

    return {
        "findings": findings,
        "truncated": len(findings) >= MAX_FINDINGS,
    }


def parse_and_match(
    advisory_data: bytes,
    declared_dependencies: list[dict[str, str]],
) -> dict[str, Any]:
    """Parse OSV JSON bytes and match against declared dependencies."""
    if not isinstance(advisory_data, bytes) or len(advisory_data) > MAX_REPORT_BYTES:
        raise ValueError("OSV data is not bytes within the parsing budget.")

    root = load_json(advisory_data, "OSV advisory")
    advisories = [root] if isinstance(root, dict) else root
    if not isinstance(advisories, list):
        raise ValueError("OSV report is neither an advisory object nor a list.")

    return match_advisories(advisories, declared_dependencies)


__all__ = ["is_version_vulnerable", "match_advisories", "parse_and_match"]
