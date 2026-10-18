"""OSV advisory matcher (L6): evaluate offline OSV records against declared package inventory.

Follows the OSV schema evaluation algorithm (https://ossf.github.io/osv-schema/#evaluation),
PEP 440 ordering (`packaging.version.Version`) for PyPI and strict SemVer 2.0.0 ordering
for npm, with PEP 503 package name normalization for PyPI and exact names for npm.
Makes no network calls, never guesses severity from CVSS vectors, ignores withdrawn
advisories, and lists un-evaluatable advisories for installed packages in `not_evaluated`.
"""

import re
from typing import Any

from packaging.version import InvalidVersion, Version

from packages.scanner_adapters.integrations._parsing import (
    MAX_FINDINGS,
    fingerprint,
    label,
    load_json,
    shown,
    text,
)

_PEP503 = re.compile(r"[-_.]+")
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_EVENT_ORDER = {"introduced": 0, "fixed": 1, "limit": 2, "last_affected": 3}
_ALLOWED_RANGES = {"PyPI": ("ECOSYSTEM",), "npm": ("SEMVER", "ECOSYSTEM")}


class _Unevaluatable(Exception):
    """Raised when an advisory affecting an installed package cannot be evaluated safely."""


def _name_key(ecosystem: str, name: str) -> str:
    return _PEP503.sub("-", name).lower() if ecosystem == "PyPI" else name


def _version_key(ecosystem: str, raw: object, *, allow_zero: bool = False) -> tuple[Any, ...]:
    if not isinstance(raw, str) or not raw or not raw.isprintable():
        raise _Unevaluatable("version bound is missing or not printable text")
    if allow_zero and raw == "0":
        return (0,)
    if ecosystem == "PyPI":
        try:
            return (1, Version(raw))
        except InvalidVersion:
            raise _Unevaluatable("version is not a valid PEP 440 version") from None
    match = _SEMVER.match(raw) if ecosystem == "npm" else None
    if not match:
        raise _Unevaluatable("version is not a valid SemVer 2.0.0 version")
    release = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    prerelease = match.group(4)
    if prerelease is None:
        return (1, release, (1, ()))
    parts = tuple((0, int(part)) if part.isdigit() else (1, part) for part in prerelease.split("."))
    return (1, release, (0, parts))


def _parse_range(ecosystem: str, range_obj: object) -> list[tuple[tuple[Any, ...], int, str, str]]:
    if not isinstance(range_obj, dict) or range_obj.get("type") not in _ALLOWED_RANGES.get(ecosystem, ()):
        raise _Unevaluatable("range type cannot be evaluated for this ecosystem")
    events = range_obj.get("events")
    if not isinstance(events, list) or not events:
        raise _Unevaluatable("range has no events list")
    parsed: list[tuple[tuple[Any, ...], int, str, str]] = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise _Unevaluatable("range event is not a single-key object")
        ((kind, raw_bound),) = event.items()
        if kind not in _EVENT_ORDER:
            raise _Unevaluatable("range event type is not recognised")
        bound_key = _version_key(ecosystem, raw_bound, allow_zero=(kind == "introduced"))
        assert isinstance(raw_bound, str)
        parsed.append((bound_key, _EVENT_ORDER[kind], kind, raw_bound))
    if not any(kind == "introduced" for _key, _order, kind, _raw in parsed):
        raise _Unevaluatable("range has no introduced event")
    parsed.sort(key=lambda item: (item[0], item[1]))
    return parsed


def _check_range(
    events: list[tuple[tuple[Any, ...], int, str, str]], pkg_key: tuple[Any, ...]
) -> tuple[bool, str | None]:
    affected = False
    intro_index = -1
    for index, (bound_key, _order, kind, _raw) in enumerate(events):
        if kind == "introduced" and pkg_key >= bound_key:
            affected = True
            intro_index = index
        elif kind in ("fixed", "limit") and pkg_key >= bound_key:
            affected = False
        elif kind == "last_affected" and pkg_key > bound_key:
            affected = False
    if not affected:
        return False, None
    fixed = next((raw for _k, _o, kind, raw in events[intro_index + 1 :] if kind == "fixed"), None)
    return True, fixed


def _severity(record: dict[str, Any]) -> str:
    db_specific = record.get("database_specific")
    raw = db_specific.get("severity") if isinstance(db_specific, dict) else None
    level = raw.lower() if isinstance(raw, str) else ""
    return level if level in _SEVERITIES else "unknown"


def match(advisories: bytes, packages: list[dict]) -> dict:
    """Match offline OSV advisories against declared packages without network access."""
    loaded = load_json(advisories, "OSV advisories")
    records = [loaded] if isinstance(loaded, dict) else loaded
    if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
        raise ValueError("OSV advisories is not an object or list of objects.")
    if not isinstance(packages, list) or not all(isinstance(pkg, dict) for pkg in packages):
        raise ValueError("Package inventory is not a list of objects.")

    indexed = [
        (
            pkg["ecosystem"],
            _name_key(pkg["ecosystem"], pkg["name"]),
            pkg["name"],
            pkg["version"],
            pkg.get("manifest", ""),
            _version_key(pkg["ecosystem"], pkg["version"]),
        )
        for pkg in packages
        if pkg.get("ecosystem") in ("PyPI", "npm")
        and isinstance(pkg.get("name"), str)
        and isinstance(pkg.get("version"), str)
    ]

    findings: list[dict[str, Any]] = []
    not_evaluated: list[dict[str, str]] = []
    total_findings = 0
    total_skipped = 0

    for record in records:
        advisory_id = text(record.get("id"), "OSV advisory id")
        if record.get("withdrawn") is not None:
            continue
        raw_aliases = record.get("aliases", [])
        if not isinstance(raw_aliases, list):
            raise ValueError("OSV aliases is not a list.")
        aliases = [shown(text(alias, "OSV alias")) for alias in raw_aliases]
        affected_list = record.get("affected", [])
        if not isinstance(affected_list, list) or not all(isinstance(a, dict) for a in affected_list):
            total_skipped += 1
            if len(not_evaluated) < MAX_FINDINGS:
                not_evaluated.append({"advisory": shown(advisory_id), "reason": "affected is not a list"})
            continue

        severity = _severity(record)
        summary = label(record.get("summary"), 300)

        for affected in affected_list:
            pkg_obj = affected.get("package")
            ecosystem = pkg_obj.get("ecosystem") if isinstance(pkg_obj, dict) else None
            pkg_name = pkg_obj.get("name") if isinstance(pkg_obj, dict) else None
            if ecosystem not in ("PyPI", "npm") or not isinstance(pkg_name, str):
                continue
            target_key = _name_key(ecosystem, pkg_name)
            installed = [item for item in indexed if item[0] == ecosystem and item[1] == target_key]
            if not installed:
                continue
            try:
                raw_ranges = affected.get("ranges", [])
                raw_versions = affected.get("versions", [])
                if not isinstance(raw_ranges, list) or not isinstance(raw_versions, list):
                    raise _Unevaluatable("ranges or versions is not a list")
                if not raw_ranges and not raw_versions:
                    raise _Unevaluatable("no ranges or versions to evaluate")
                parsed_ranges = [_parse_range(ecosystem, r) for r in raw_ranges]
                exact_versions = {v for v in raw_versions if _version_key(ecosystem, v)}
            except _Unevaluatable as skip:
                total_skipped += 1
                if len(not_evaluated) < MAX_FINDINGS:
                    not_evaluated.append({"advisory": shown(advisory_id), "reason": str(skip)})
                break

            for _eco, norm_name, inst_name, inst_version, inst_manifest, inst_key in installed:
                matched = False
                fixed_ver: str | None = None
                for events in parsed_ranges:
                    hit_range, candidate_fix = _check_range(events, inst_key)
                    if hit_range:
                        matched = True
                        fixed_ver = candidate_fix
                        break
                if not matched and inst_version in exact_versions:
                    matched = True
                if matched:
                    total_findings += 1
                    if len(findings) < MAX_FINDINGS:
                        findings.append(
                            {
                                "advisory": shown(advisory_id),
                                "aliases": aliases,
                                "summary": summary,
                                "severity": severity,
                                "ecosystem": ecosystem,
                                "package": shown(inst_name),
                                "version": shown(inst_version),
                                "fixed": shown(fixed_ver) if fixed_ver is not None else None,
                                "manifest": shown(inst_manifest),
                                "fingerprint": fingerprint(
                                    "osv", advisory_id, ecosystem, norm_name, inst_version
                                ),
                            }
                        )

    return {
        "findings": findings,
        "not_evaluated": not_evaluated,
        "truncated": total_findings > MAX_FINDINGS or total_skipped > MAX_FINDINGS,
    }


__all__ = ["match"]
