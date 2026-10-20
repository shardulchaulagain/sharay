"""Source-analysis assessment (native, no binary or container): the product entry point.

The HTTP pipeline takes a URL; this takes an operator-authorized directory and runs the
built-in detectors (`secrets.detect`, `dependencies.inventory`) on it. Everything here is
in-process Python, so it works with no scanner binary, no container and no network.

The one trust boundary is the path: the operator names a directory, so `resolve_within`
confines every request to a single configured root (`Settings.source_root`), collapsing
symlinks and `..` with `realpath` and rejecting anything that resolves outside it. The
detectors themselves never follow directory symlinks while walking.
"""

import os
from pathlib import Path
from typing import Any

from services.source_analysis_worker.dependencies import inventory
from services.source_analysis_worker.secrets import detect


class SourceAnalysisError(ValueError):
    """The requested path is not an analyzable directory inside the authorized root."""


def resolve_within(requested: str, root: Path) -> Path:
    """Return the real directory for `requested`, or raise if it escapes `root`.

    A relative request is taken under `root`; an absolute one must still resolve inside it.
    realpath collapses `..` and resolves every symlink, so a link pointing out of the root is
    rejected rather than followed.
    """
    if not isinstance(requested, str) or not requested.strip():
        raise SourceAnalysisError("A source path is required.")
    root_real = Path(os.path.realpath(root))
    candidate = Path(requested)
    base = candidate if candidate.is_absolute() else root_real / candidate
    target = Path(os.path.realpath(base))
    if target != root_real and root_real not in target.parents:
        raise SourceAnalysisError("The source path is outside the authorized analysis root.")
    if not target.is_dir():
        raise SourceAnalysisError("The source path is not an existing directory.")
    return target


def _secret_finding(match: dict[str, Any]) -> dict[str, Any]:
    """One normalized Finding from a native secret match, honest that no external scanner ran."""
    rule, where, line = match["rule"], match["file"], match["line"]
    return {
        "fingerprint": f"sharay_secret:{match['fingerprint']}",
        "title": f"Secret-shaped value matched built-in rule {rule}"[:250],
        "category": "secret_exposure",
        "severity": "high",
        "confidence": "medium",
        "status": "suspected",
        "description": f"Built-in secret pattern '{rule}' matched in {where} at line {line} (not verified live).",
        "remediation": "Rotate the value if it is a real credential and remove it from source control.",
        "affected_url": f"file://{where}#L{line}",
        "recommended_validations": [],
    }


def analyze_source_tree(root: Path) -> dict[str, Any]:
    """Run the native detectors over a confined tree and return normalized findings and inventory."""
    secret_report = detect(root)
    dependency_report = inventory(root)
    findings = [_secret_finding(match) for match in secret_report["matches"]]
    checks = [
        {
            "category": "secret_detection",
            "status": "completed",
            "detail": (
                f"Scanned {secret_report['files_scanned']} file(s); "
                f"{len(secret_report['matches'])} secret-shaped match(es), "
                f"{len(secret_report['skipped'])} file(s) skipped."
            ),
        },
        {
            "category": "dependency_inventory",
            "status": "completed",
            "detail": (
                f"{len(dependency_report['packages'])} declared package(s) across "
                f"{len(dependency_report['manifests'])} manifest(s); "
                f"{len(dependency_report['unresolved'])} line(s) unresolved."
            ),
        },
    ]
    return {
        "basis": "native in-process source analysis (secret patterns and declared dependencies); no scanner binary ran",
        "findings": findings,
        "packages": dependency_report["packages"],
        "manifests": dependency_report["manifests"],
        "skipped": secret_report["skipped"],
        "checks": checks,
    }


__all__ = ["SourceAnalysisError", "analyze_source_tree", "resolve_within"]
