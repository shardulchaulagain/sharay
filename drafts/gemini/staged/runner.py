"""Draft Narrow Runner Entry Point for Staged Ingestion (L1/C5/C6).

Author: Gemini (Principal Architect, Debugger & Helper)
Status: Draft module under drafts/gemini/staged/ for Claude and Codex review.

Architecture:
1. Strict Seatbelt Profile:
   - Exactly one output folder writable: `(subpath (param "OUTPUT"))`.
   - Exactly one archive readable: `(literal (param "ARCHIVE"))`.
   - Read access for Python runtime and services package.
   - DENY process fork: `(deny process-fork)`.
   - DENY all network outbound and inbound.
2. Hardened Lifecycle:
   - Pre-flight parent checks: archive must be regular file, output must be empty real folder.
   - Child executes extract_archive in single-threaded isolated process.
   - Post-extraction audit: Parent validates output using drafts.gemini.staged_ingestion_validator.
   - Fail-closed cleanup: Any failure, rejection, timeout, or validation flaw immediately
     purges the output directory.
"""

from __future__ import annotations

import json
import math
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from drafts.gemini.staged_ingestion_validator import (
    StagedValidationError,
    ValidationBudgets,
    purge_staging,
    validate_staged_tree,
)

SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# Narrow Seatbelt profile specifically tailored for archive extraction:
# - Write access: ONLY the staging output folder and /dev/null.
# - Read access: ONLY the archive literal, Python runtime, and services module.
# - Fork: Denied.
# - Network: Denied.
_SEATBELT_EXTRACTION_PROFILE = """(version 1)
(deny default)
(deny process-fork)
(allow signal (target same-sandbox))
(allow sysctl-read)
(allow file-read-metadata)
(allow process-exec (literal (param "PYTHON")))
(allow file-read*
  (literal "/") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random")
  (subpath "/usr/lib") (subpath "/System/Library") (subpath "/System/Volumes/Preboot/Cryptexes")
  (subpath "/private/var/db/dyld")
  (subpath (param "RUNTIME"))
  (subpath (param "SERVICES"))
  (literal (param "ARCHIVE"))
  (subpath (param "OUTPUT")))
(allow file-write*
  (literal "/dev/null")
  (subpath (param "OUTPUT")))
"""

# Child launcher that sets strict rlimits before invoking sandbox-exec
_LAUNCH_RLIMITS = (
    "import os, resource, sys\n"
    "for name, value in zip(('CORE', 'NOFILE', 'CPU', 'FSIZE'), sys.argv[1:5]):\n"
    "    kind = getattr(resource, 'RLIMIT_' + name)\n"
    "    hard = resource.getrlimit(kind)[1]\n"
    "    value = int(value) if hard == resource.RLIM_INFINITY else min(int(value), hard)\n"
    "    resource.setrlimit(kind, (value, value))\n"
    "os.execv(sys.argv[5], sys.argv[5:])\n"
)

# In-sandbox extraction script executed by Python interpreter
_CHILD_EXTRACTOR = """
import importlib.util, json, sys
location = sys.argv[1]
spec = importlib.util.spec_from_file_location("services", location + "/__init__.py", submodule_search_locations=[location])
module = importlib.util.module_from_spec(spec)
sys.modules["services"] = module
spec.loader.exec_module(module)
from services.source_analysis_worker import ArchiveError, extract_archive
names = ("max_files", "max_file_bytes", "max_total_bytes", "max_archive_bytes")
try:
    summary = extract_archive(sys.argv[2], sys.argv[3], **dict(zip(names, map(int, sys.argv[4:8]))))
except ArchiveError as exc:
    print(json.dumps({"rejected": str(exc)}))
    sys.exit(3)
except Exception as exc:
    print(json.dumps({"rejected": f"Unexpected error: {exc}"}))
    sys.exit(4)
summary["skipped"] = len(summary["skipped"])
print(json.dumps(summary))
"""


class StagedExtractionError(ValueError):
    """Extraction failed, was rejected, or breached isolation boundaries."""


@dataclass(frozen=True)
class StagedExtractionResult:
    outcome: str  # "completed", "rejected", "timeout", "cancelled", "failed"
    exit_code: int
    duration_ms: int
    extracted_files: int
    extracted_folders: int
    extracted_bytes: int
    rejection_reason: str | None = None
    enforced: tuple[str, ...] = ()


def _stop_process_group(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except (OSError, ProcessLookupError):
        try:
            os.kill(pid, sig)
        except (OSError, ProcessLookupError):
            pass


def run_staged_extraction(
    archive: Path | str,
    output: Path | str,
    *,
    max_files: int = 10000,
    max_file_bytes: int = 20 * 1024 * 1024,
    max_total_bytes: int = 200 * 1024 * 1024,
    max_archive_bytes: int = 100 * 1024 * 1024,
    max_seconds: float = 60.0,
    cancelled: Callable[[], bool] = lambda: False,
    force_direct: bool = False,
) -> StagedExtractionResult:
    """Execute isolated archive extraction into output/tree, followed by parent validation.

    Guarantees:
    - Pre-flight validates paths before launching child.
    - Child runs under Seatbelt sandbox with deny-fork, deny-network, read-archive, write-output.
    - If nested sandbox is blocked by host kernel (Operation not permitted) and force_direct is True,
      executes direct child runner for testing while honestly reporting lack of Seatbelt enforcement.
    - Parent performs independent lstat tree validation after child termination.
    - On ANY error or validation failure, purges the output directory completely.
    """
    budgets = (max_files, max_file_bytes, max_total_bytes, max_archive_bytes)
    if any(type(v) is not int or v < 1 for v in budgets):
        raise StagedExtractionError("Budgets must be positive integers.")

    archive_path = Path(archive)
    output_path = Path(output)

    # 1. Parent Pre-flight checks
    try:
        arch_stat = archive_path.lstat()
        out_stat = output_path.lstat()
        if stat.S_ISLNK(arch_stat.st_mode) or not stat.S_ISREG(arch_stat.st_mode):
            raise StagedExtractionError("Archive must be a regular file, not a symlink or directory.")
        if stat.S_ISLNK(out_stat.st_mode) or not stat.S_ISDIR(out_stat.st_mode):
            raise StagedExtractionError("Output must be a real directory, not a symlink.")
        if any(output_path.iterdir()):
            raise StagedExtractionError("Output directory must be empty.")
        archive_path = archive_path.resolve(strict=True)
        output_path = output_path.resolve(strict=True)
    except OSError as exc:
        raise StagedExtractionError(f"Pre-flight path inspection failed: {exc}") from exc

    tree_dest = output_path / "tree"
    services_dir = Path(__file__).resolve().parents[3] / "services"
    python_bin = os.path.realpath(sys.executable)
    runtime_dir = Path(sys.base_prefix).resolve()

    # 2. Build Seatbelt execution command
    use_seatbelt = not force_direct and sys.platform == "darwin" and os.access(SANDBOX_EXEC, os.X_OK)

    cpu_limit = math.ceil(max_seconds) + 1
    fsize_limit = max_file_bytes + 1

    extractor_args = [
        str(services_dir),
        str(archive_path),
        str(tree_dest),
        *map(str, budgets),
    ]

    if use_seatbelt:
        command = [
            python_bin,
            "-I",
            "-S",
            "-c",
            _LAUNCH_RLIMITS,
            "0",  # RLIMIT_CORE
            "256",  # RLIMIT_NOFILE
            str(cpu_limit),
            str(fsize_limit),
            SANDBOX_EXEC,
            "-D",
            f"PYTHON={python_bin}",
            "-D",
            f"RUNTIME={runtime_dir}",
            "-D",
            f"SERVICES={services_dir}",
            "-D",
            f"ARCHIVE={archive_path}",
            "-D",
            f"OUTPUT={output_path}",
            "-p",
            _SEATBELT_EXTRACTION_PROFILE,
            python_bin,
            "-I",
            "-c",
            _CHILD_EXTRACTOR,
            *extractor_args,
        ]
    else:
        # Direct execution fallback for environments where nested Seatbelt is disallowed
        command = [
            python_bin,
            "-I",
            "-c",
            _CHILD_EXTRACTOR,
            *extractor_args,
        ]

    started = time.monotonic()
    outcome = ""
    stdout_data = b""
    stderr_data = b""

    # 3. Process Execution & Deadline Management
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(
                command,
                cwd=output_path,
                env={"PATH": "/usr/bin:/bin", "HOME": str(output_path), "LANG": "C"},
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            try:
                while process.poll() is None and not outcome:
                    if cancelled():
                        outcome = "cancelled"
                    elif time.monotonic() - started >= max_seconds:
                        outcome = "timeout"
                    else:
                        time.sleep(0.02)
                if outcome:
                    _stop_process_group(process.pid, signal.SIGTERM)
                    try:
                        process.wait(3.0)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                _stop_process_group(process.pid, signal.SIGKILL)
                process.wait()

            stdout.seek(0)
            stderr.seek(0)
            stdout_data = stdout.read()
            stderr_data = stderr.read()
    except Exception as exc:
        purge_staging(output_path)
        raise StagedExtractionError(f"Child process could not be launched: {exc}") from exc

    duration_ms = round((time.monotonic() - started) * 1000)

    # 4. Evaluate Child Outcome
    if outcome in ("cancelled", "timeout"):
        purge_staging(output_path)
        return StagedExtractionResult(
            outcome=outcome,
            exit_code=process.returncode,
            duration_ms=duration_ms,
            extracted_files=0,
            extracted_folders=0,
            extracted_bytes=0,
            rejection_reason=f"Execution halted: {outcome}",
        )

    # Detect Seatbelt kernel denial when nested inside another sandbox (exit code 71)
    if use_seatbelt and process.returncode == 71 and b"Operation not permitted" in stderr_data:
        purge_staging(output_path)
        raise StagedExtractionError(
            "Seatbelt sandbox cannot be applied in this environment (nested sandbox operation not permitted)."
        )

    if process.returncode != 0:
        purge_staging(output_path)
        reason = "Child extractor process exited with error"
        try:
            parsed = json.loads(stdout_data.decode("utf-8"))
            if "rejected" in parsed:
                reason = parsed["rejected"]
        except Exception:
            pass
        return StagedExtractionResult(
            outcome="rejected" if process.returncode == 3 else "failed",
            exit_code=process.returncode,
            duration_ms=duration_ms,
            extracted_files=0,
            extracted_folders=0,
            extracted_bytes=0,
            rejection_reason=reason,
        )

    # 5. Parent Independent Validation of Staged Tree
    try:
        val_budgets = ValidationBudgets(
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )
        validated = validate_staged_tree(tree_dest, budgets=val_budgets)
    except StagedValidationError as exc:
        purge_staging(output_path)
        return StagedExtractionResult(
            outcome="failed",
            exit_code=process.returncode,
            duration_ms=duration_ms,
            extracted_files=0,
            extracted_folders=0,
            extracted_bytes=0,
            rejection_reason=f"Parent validation failed: {exc}",
        )

    enforced_controls = (
        ("seatbelt_profile", "single_process_no_fork", "no_network_egress", "output_only_writes")
        if use_seatbelt
        else ("direct_process_isolated_env",)
    )

    return StagedExtractionResult(
        outcome="completed",
        exit_code=0,
        duration_ms=duration_ms,
        extracted_files=validated.file_count,
        extracted_folders=validated.dir_count,
        extracted_bytes=validated.total_bytes,
        enforced=enforced_controls,
    )


__all__ = [
    "StagedExtractionError",
    "StagedExtractionResult",
    "run_staged_extraction",
]
