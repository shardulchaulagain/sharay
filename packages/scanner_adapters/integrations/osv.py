"""OSV advisory matcher (L6): which declared packages fall inside a published advisory's ranges.

No network and no advisory data ships with this: the caller supplies OSV records as bytes.
Follows the OSV schema's evaluation algorithm (https://ossf.github.io/osv-schema/#evaluation),
PEP 440 ordering (`packaging.version.Version`) for PyPI and SemVer 2.0.0 ordering for npm,
PEP 503 name normalisation for PyPI and exact names for npm. A match is a statement about a
DECLARED version and a published range; it is not evidence that the flaw is reachable.
Severity is never derived from a CVSS vector, withdrawn advisories report nothing, and what
cannot be evaluated for a declared package is listed in `not_evaluated`, never dropped.
Implementation by Gemini against Claude's acceptance tests, then reviewed and reworked.
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


def _parse_range(ecosystem: str, range_obj: dict) -> list[tuple[tuple[Any, ...], int, str, str]]:
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


def _aliases(record: dict[str, Any]) -> list[str]:
    raw = record.get("aliases", [])
    try:
        if not isinstance(raw, list):
            raise ValueError
        return [shown(text(alias, "OSV alias")) for alias in raw]
    except ValueError:
        raise _Unevaluatable("aliases are malformed") from None


def _affected(ecosystem: str, affected: dict[str, Any]) -> tuple[list, set]:
    """The comparable ranges and exact versions of one `affected` entry."""
    raw_ranges, raw_versions = affected.get("ranges", []), affected.get("versions", [])
    if not isinstance(raw_ranges, list) or not isinstance(raw_versions, list):
        raise _Unevaluatable("ranges or versions is not a list")
    if not all(isinstance(item, dict) for item in raw_ranges):
        raise _Unevaluatable("a range is not an object")
    # A GIT (commit) range says nothing about a declared version; records usually carry a
    # version range beside it, so it is passed over rather than failing the whole entry.
    comparable = [item for item in raw_ranges if item.get("type") in _ALLOWED_RANGES[ecosystem]]
    if not comparable and not raw_versions:
        raise _Unevaluatable("no version range or version list that can be compared")
    exact = set()
    for listed in raw_versions:
        if not isinstance(listed, str):
            raise _Unevaluatable("a listed version is not text")
        try:
            # By ordering key, so 1.0 equals 1.0.0 where the ecosystem says so.
            exact.add(_version_key(ecosystem, listed))
        except _Unevaluatable:
            pass  # not a version of this ecosystem, so it cannot equal a declared one
    return [_parse_range(ecosystem, item) for item in comparable], exact


def match(advisories: bytes, packages: list[dict]) -> dict:
    """Return {"findings", "not_evaluated", "truncated"} for declared packages against OSV records."""
    loaded = load_json(advisories, "OSV advisories")
    records = [loaded] if isinstance(loaded, dict) else loaded
    if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
        raise ValueError("OSV advisories is not an object or list of objects.")
    if not isinstance(packages, list) or not all(isinstance(item, dict) for item in packages):
        raise ValueError("Package inventory is not a list of objects.")
    findings: list[dict[str, Any]] = []
    not_evaluated: list[dict[str, str]] = []
    totals = {"findings": 0, "not_evaluated": 0}

    def skipped(item: dict[str, str]) -> None:
        totals["not_evaluated"] += 1
        if len(not_evaluated) < MAX_FINDINGS:
            not_evaluated.append(item)

    declared: dict[tuple[str, str], list[tuple[str, str, str, tuple]]] = {}
    for item in packages:
        ecosystem, name, version = item.get("ecosystem"), item.get("name"), item.get("version")
        if ecosystem not in _ALLOWED_RANGES:
            continue  # only PyPI and npm are matched here
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("Package inventory entry has no name and version text.")
        try:
            key = _version_key(ecosystem, version)
        except _Unevaluatable:
            # One odd declared version must not stop every other package from being checked.
            skipped({"package": shown(name), "reason": "declared version cannot be ordered"})
            continue
        manifest = item.get("manifest")
        entry = (name, version, manifest if isinstance(manifest, str) else "", key)
        declared.setdefault((ecosystem, _name_key(ecosystem, name)), []).append(entry)

    seen: set[str] = set()
    for record in records:
        advisory = text(record.get("id"), "OSV advisory id")
        if record.get("withdrawn") is not None:
            continue
        entries = record.get("affected", [])
        problem = None if isinstance(entries, list) else "affected is not a list"
        for affected in entries if isinstance(entries, list) else []:
            package = affected.get("package") if isinstance(affected, dict) else None
            ecosystem = package.get("ecosystem") if isinstance(package, dict) else None
            name = package.get("name") if isinstance(package, dict) else None
            if not isinstance(affected, dict):
                problem = problem or "an affected entry is not an object"
                continue
            if ecosystem not in _ALLOWED_RANGES or not isinstance(name, str):
                continue
            targets = declared.get((ecosystem, _name_key(ecosystem, name)))
            if not targets:
                continue  # about a package that is not declared: irrelevant, however odd
            try:
                ranges, exact = _affected(ecosystem, affected)
                aliases = _aliases(record)
            except _Unevaluatable as reason:
                problem = problem or str(reason)
                continue  # other entries of this advisory may still be evaluable
            for declared_name, version, manifest, key in targets:
                fixed, hit = None, key in exact
                for events in ranges:
                    in_range, candidate = _check_range(events, key)
                    if in_range:
                        fixed, hit = candidate, True
                        break
                identity = fingerprint("osv", advisory, ecosystem, _name_key(ecosystem, name), version)
                if not hit or identity in seen:
                    continue  # several entries of one advisory can name the same package
                seen.add(identity)
                totals["findings"] += 1
                if len(findings) < MAX_FINDINGS:
                    findings.append(
                        {
                            "advisory": shown(advisory),
                            "aliases": aliases,
                            "summary": label(record.get("summary"), 300),
                            "severity": _severity(record),
                            "ecosystem": ecosystem,
                            "package": shown(declared_name),
                            "version": shown(version),
                            "fixed": shown(fixed) if fixed is not None else None,
                            "manifest": shown(manifest),
                            "fingerprint": identity,
                        }
                    )
        if problem:
            skipped({"advisory": shown(advisory), "reason": problem})
    return {
        "findings": findings,
        "not_evaluated": not_evaluated,
        "truncated": totals["findings"] > MAX_FINDINGS or totals["not_evaluated"] > MAX_FINDINGS,
    }


__all__ = ["match"]
