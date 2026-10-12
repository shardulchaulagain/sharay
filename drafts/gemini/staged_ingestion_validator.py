"""Parent-side validator and atomic adoption for staged archive ingestion (L1/C5/C6).

Drafted by Gemini as architect helper for Claude and Codex.
Untrusted until reviewed by the path owner and verified with tests.

Security guarantees:
1. Validates the staging root with lstat (rejects symlinks).
2. Re-verifies every file and folder with lstat (no symlinks, no fifos, no sockets, no devices).
3. Re-verifies hard-link count (st_nlink == 1) to prevent shared inode bypasses.
4. Normalizes permissions (clearing UF_IMMUTABLE and setting 0o600/0o700) so a child
   cannot brick cleanup or leave unreadable entries.
5. Strictly re-counts node counts, per-file byte sizes, and total byte budgets.
6. Error messages are fixed string constants (no untrusted names or bytes echoed).
7. Atomic adoption (os.replace) requiring the staging tree and destination to share the
   same filesystem mount (st_dev match), preventing non-atomic copy fallbacks.
8. Clean failure: any budget breach, type mismatch or corruption purges the entire
   staging folder and raises a clear exception.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


class StagedValidationError(ValueError):
    """The staged directory failed verification or could not be cleaned up."""


@dataclass(frozen=True)
class ValidationBudgets:
    max_files: int = 10000
    max_file_bytes: int = 20 * 1024 * 1024
    max_total_bytes: int = 200 * 1024 * 1024
    max_depth: int = 32
    max_name_bytes: int = 1024


@dataclass(frozen=True)
class ValidatedTree:
    root: Path
    file_count: int
    dir_count: int
    total_bytes: int


def unlock_path(path: str | Path) -> None:
    """Clear immutable flags and restore write permissions without following symlinks."""
    p_str = str(path)
    try:
        if hasattr(os, "chflags"):
            os.chflags(p_str, 0, follow_symlinks=False)
        os.chmod(p_str, stat.S_IRWXU, follow_symlinks=False)
    except OSError:
        pass


def purge_staging(staging_dir: Path | str) -> bool:
    """Recursively unlock and remove the staging directory. Never acts through symlinks."""
    p = Path(staging_dir)
    try:
        try:
            status = p.lstat()
        except OSError:
            return True
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            p.unlink(missing_ok=True)
            return not p.exists()
        from services.scanner_worker import remove_tree
        return remove_tree(p)
    except OSError:
        return False


def validate_staged_tree(
    staging_output: Path | str,
    budgets: ValidationBudgets | None = None,
) -> ValidatedTree:
    """Independently audit an untrusted extracted tree in the parent process.

    Must be called only AFTER the extraction child process has completely terminated.
    Raises StagedValidationError with fixed error text on any anomaly and purges staging_output.
    """
    if budgets is None:
        budgets = ValidationBudgets()

    target_root = Path(staging_output)
    try:
        root_stat = target_root.lstat()
    except OSError as exc:
        purge_staging(target_root)
        raise StagedValidationError("Staging output root is missing or inaccessible.") from exc

    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        purge_staging(target_root)
        raise StagedValidationError("Staging output root is not a directory or is a symbolic link.")

    target_root = target_root.resolve()

    total_files = 0
    total_dirs = 0
    total_bytes = 0

    try:
        unlock_path(target_root)
        for dirpath, dirnames, filenames in os.walk(target_root, topdown=True, followlinks=False):
            # Check directory depth
            rel_dir = Path(dirpath).relative_to(target_root)
            depth = len(rel_dir.parts)
            if depth > budgets.max_depth:
                raise StagedValidationError("Directory depth exceeds budget.")

            for dname in dirnames:
                total_dirs += 1
                if total_files + total_dirs > budgets.max_files:
                    raise StagedValidationError("Total nodes exceed max_files budget.")
                dpath = Path(dirpath, dname)
                dstat = dpath.lstat()
                if not stat.S_ISDIR(dstat.st_mode) or stat.S_ISLNK(dstat.st_mode):
                    raise StagedValidationError("Directory entry is not a directory or is a symbolic link.")
                if len(dname.encode("utf-8", "replace")) > budgets.max_name_bytes:
                    raise StagedValidationError("Directory name exceeds maximum length.")
                unlock_path(dpath)
                os.chmod(dpath, 0o700, follow_symlinks=False)

            for fname in filenames:
                total_files += 1
                if total_files + total_dirs > budgets.max_files:
                    raise StagedValidationError("Total nodes exceed max_files budget.")
                fpath = Path(dirpath, fname)
                fstat = fpath.lstat()
                if not stat.S_ISREG(fstat.st_mode) or stat.S_ISLNK(fstat.st_mode):
                    raise StagedValidationError("Entry is not a regular file (symlink or special).")
                # Reject hard links (multiple directory entries to same inode)
                if fstat.st_nlink != 1:
                    raise StagedValidationError("Entry has st_nlink != 1 (hard link rejected).")
                unlock_path(fpath)
                if len(fname.encode("utf-8", "replace")) > budgets.max_name_bytes:
                    raise StagedValidationError("File name exceeds maximum length.")
                if fstat.st_size > budgets.max_file_bytes:
                    raise StagedValidationError("File size exceeds per-file budget.")
                total_bytes += fstat.st_size
                if total_bytes > budgets.max_total_bytes:
                    raise StagedValidationError("Total decompressed bytes exceed budget.")
                # Normalize file permissions: read-only by owner, no execute bits
                os.chmod(fpath, 0o600, follow_symlinks=False)

    except Exception as exc:
        removed = purge_staging(target_root)
        if not removed:
            raise StagedValidationError(
                "Validation failed and staging directory could not be removed."
            ) from exc
        if isinstance(exc, StagedValidationError):
            raise
        raise StagedValidationError("Staged extraction validation failed due to an unexpected error.") from exc

    return ValidatedTree(
        root=target_root,
        file_count=total_files,
        dir_count=total_dirs,
        total_bytes=total_bytes,
    )


def adopt_staged_tree(staging_output: Path | str, final_destination: Path | str) -> Path:
    """Atomically move a validated staging tree to its permanent destination.

    Enforces that staging_output and final_destination share the same filesystem device,
    ensuring os.replace is a single atomic rename rather than a multi-step copy.
    """
    src = Path(staging_output).resolve()
    dest = Path(final_destination).resolve()

    if not src.exists():
        raise StagedValidationError("Source staging tree does not exist.")
    if dest.exists():
        raise StagedValidationError("Final destination already exists; will not overwrite.")

    dest.parent.mkdir(parents=True, exist_ok=True)

    # Verify same filesystem to prevent fallback to non-atomic recursive copies
    if src.stat().st_dev != dest.parent.stat().st_dev:
        purge_staging(src)
        raise StagedValidationError(
            "Staging folder and destination must reside on the same filesystem for atomic adoption."
        )

    try:
        os.replace(src, dest)
    except OSError as exc:
        purge_staging(src)
        raise StagedValidationError("Atomic adoption failed.") from exc

    return dest
