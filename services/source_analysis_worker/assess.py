"""Source-analysis assessment: the product entry point for scanning a code tree.

The HTTP pipeline takes a URL; this takes an operator-authorized directory. When the pinned
Gitleaks binary and the isolation sandbox are available it runs Gitleaks over the tree for
secret detection; otherwise it falls back to the in-process built-in secret detector. Declared
dependencies are always inventoried in-process. Either way the result is normalized into the
same Finding shape the rest of the product uses.

The one trust boundary is the path: the operator names a directory, so `resolve_within`
confines every request to a single configured root (`Settings.source_root`), collapsing
symlinks and `..` with `realpath` and rejecting anything that resolves outside it. The
detectors never follow directory symlinks while walking, and Gitleaks runs under the sandbox
with a pinned configuration so the scanned tree cannot reconfigure or silence it.
"""

import os
from pathlib import Path
from typing import Any

from services.source_analysis_worker.dependencies import inventory
from services.source_analysis_worker.secrets import detect

_GITLEAKS_MAX_SECONDS = 60


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


def _secret_finding(match: dict[str, Any], *, source: str, prefix: str) -> dict[str, Any]:
    """One normalized Finding from a secret match ({rule,file,line,fingerprint}); honest about its source."""
    rule, where, line = match["rule"], match["file"], match["line"]
    return {
        "fingerprint": f"{prefix}:{match['fingerprint']}",
        "title": f"Secret-shaped value matched {source} rule {rule}"[:250],
        "category": "secret_exposure",
        "severity": "high",
        "confidence": "medium",
        "status": "suspected",
        "description": f"{source} rule '{rule}' matched in {where} at line {line} (not verified live).",
        "remediation": "Rotate the value if it is a real credential and remove it from source control.",
        "affected_url": f"file://{where}#L{line}",
        "recommended_validations": [],
    }


def _gitleaks_binary() -> Path | None:
    """The pinned Gitleaks binary, from SHARAY_GITLEAKS_BIN or the newest tools/bin install."""
    override = os.environ.get("SHARAY_GITLEAKS_BIN")
    if override:
        path = Path(override)
        return path if path.is_file() else None
    base = Path(__file__).resolve().parents[2] / "tools" / "bin"
    installs = sorted(base.glob("gitleaks-*/gitleaks"))
    return installs[-1] if installs else None


def _run_gitleaks(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run the pinned Gitleaks over the tree in the sandbox; return (findings, check). Skips cleanly."""
    binary = _gitleaks_binary()
    if binary is None:
        return [], {
            "category": "gitleaks",
            "status": "skipped",
            "detail": "No pinned Gitleaks binary is installed; the built-in secret detector was used.",
        }
    try:
        from packages.scanner_adapters.integrations import gitleaks as gl
        from services.scanner_worker import attest, run_isolated

        if not attest().get("available"):
            return [], {
                "category": "gitleaks",
                "status": "skipped",
                "detail": "The isolation sandbox is unavailable here; the built-in secret detector was used.",
            }
        argv = gl.build_argv(str(binary), str(root), max_seconds=_GITLEAKS_MAX_SECONDS)
        config_dir = str(Path(gl.PINNED_CONFIG).parent)
        result = run_isolated(
            argv,
            exec_paths=[str(binary.parent)],
            read_paths=[str(root), config_dir],
            max_seconds=_GITLEAKS_MAX_SECONDS + 5,
            max_output_bytes=1024 * 1024,
        )
        if result.outcome != "completed" or result.exit_code != 0 or result.output_truncated:
            return [], {
                "category": "gitleaks",
                "status": "completed_with_errors",
                "detail": (
                    f"Gitleaks did not complete cleanly (outcome {result.outcome}, exit {result.exit_code}, "
                    f"truncated {result.output_truncated}); the built-in secret detector was used instead."
                ),
            }
        parsed = gl.parse(result.stdout, source_root=str(root))
        findings = [
            _secret_finding(match, source="Gitleaks", prefix="gitleaks") for match in parsed["findings"]
        ]
        version = binary.parent.name.replace("gitleaks-", "")
        detail = f"Gitleaks {version} scanned the tree and reported {len(findings)} secret(s)."
        suppressions = gl.suppression_files(root)
        if suppressions:
            detail += (
                f" Suppression files are present ({', '.join(suppressions[:5])}); coverage may be reduced."
            )
        return findings, {"category": "gitleaks", "status": "completed", "detail": detail}
    except Exception as exc:  # any sandbox/parse failure falls back to the native detector
        return [], {
            "category": "gitleaks",
            "status": "completed_with_errors",
            "detail": f"Gitleaks run error ({type(exc).__name__}); the built-in secret detector was used instead.",
        }


def analyze_source_tree(root: Path) -> dict[str, Any]:
    """Scan a confined tree for secrets (Gitleaks when available, else built-in) and inventory deps."""
    dependency_report = inventory(root)
    gitleaks_findings, gitleaks_check = _run_gitleaks(root)
    checks = [gitleaks_check]

    if gitleaks_check["status"] == "completed":
        findings = gitleaks_findings
        secret_tool = "Gitleaks"
    else:
        secret_report = detect(root)
        findings = [
            _secret_finding(match, source="built-in", prefix="sharay_secret")
            for match in secret_report["matches"]
        ]
        secret_tool = "built-in detector"
        checks.append(
            {
                "category": "secret_detection",
                "status": "completed",
                "detail": (
                    f"Built-in detector scanned {secret_report['files_scanned']} file(s); "
                    f"{len(secret_report['matches'])} secret-shaped match(es), "
                    f"{len(secret_report['skipped'])} file(s) skipped."
                ),
            }
        )
        skipped = secret_report["skipped"]

    if gitleaks_check["status"] == "completed":
        skipped = []

    checks.append(
        {
            "category": "dependency_inventory",
            "status": "completed",
            "detail": (
                f"{len(dependency_report['packages'])} declared package(s) across "
                f"{len(dependency_report['manifests'])} manifest(s); "
                f"{len(dependency_report['unresolved'])} line(s) unresolved."
            ),
        }
    )
    return {
        "basis": f"source analysis: secrets via {secret_tool}, declared dependencies in-process",
        "findings": findings,
        "packages": dependency_report["packages"],
        "manifests": dependency_report["manifests"],
        "skipped": skipped,
        "checks": checks,
    }


__all__ = ["SourceAnalysisError", "analyze_source_tree", "resolve_within"]
