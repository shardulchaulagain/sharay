"""Parent-side check of a staged extraction (L6): trust nothing the child left behind.

Call only after the extraction child has exited. `output` must be a folder the PARENT
created inside a directory the child could not write, so the child cannot have replaced
it; everything inside it is treated as hostile. Adopting the validated tree and recording
provenance belong to the caller. Counting here detects an overrun; it does not prevent one.

Based on Gemini's reviewed draft (drafts/gemini/staged_ingestion_validator.py); one defect
in that draft is fixed here: cleanup never walks through a symbolic link. A second, found
by this module's own test, is avoided: nothing about an entry is changed before lstat shows
it is a real directory or a singly linked regular file.
"""

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from services.scanner_worker import remove_tree


class StagedTreeError(ValueError):
    """The staged output failed validation; `removed` says whether it could be deleted."""

    def __init__(self, message: str, removed: bool):
        super().__init__(message)
        self.removed = removed


# Removal that survives locked entries without acting through links; shared with the runner.
purge = remove_tree


def _unlistable(error: OSError) -> None:
    raise ValueError("The staged tree contains a directory that cannot be listed.") from error


def validate_staged_tree(
    output: Path | str,
    *,
    max_files: int = 10000,
    max_file_bytes: int = 20 * 1024 * 1024,
    max_total_bytes: int = 200 * 1024 * 1024,
    max_depth: int = 34,
) -> dict:
    """Re-check every node under `output`; on any problem delete it and raise StagedTreeError.

    Accepts only real directories and singly linked regular files, clamps their modes, and
    recounts nodes and bytes against the same budgets the child was given. Returns counts,
    a relative inventory (path, bytes, sha256 of each file as the parent read it) and one
    digest over that inventory, for the caller's provenance record.
    """
    output = Path(output)
    budgets = (max_files, max_file_bytes, max_total_bytes, max_depth)
    files = folders = total = 0
    inventory: list[dict] = []
    problem = ""
    try:
        if any(type(value) is not int or value < 1 for value in budgets):
            raise ValueError("Budgets must be positive integers.")
        if not stat.S_ISDIR(output.lstat().st_mode):
            raise ValueError("The staged output is not a real directory.")
        os.chmod(output, stat.S_IRWXU)
        # onerror: os.walk otherwise skips a directory it cannot list (an ACL survives chmod)
        # and the tree would validate as smaller than it is.
        for parent, folder_names, file_names in os.walk(output, onerror=_unlistable):
            if len(Path(parent).relative_to(output).parts) >= max_depth:
                raise ValueError("The staged tree is deeper than the budget allows.")
            # Every entry is inspected with lstat BEFORE anything about it is changed: a hard
            # link shares its mode and flags with a file that may live outside the tree.
            for name in folder_names:
                path = os.path.join(parent, name)
                if not stat.S_ISDIR(os.lstat(path).st_mode):
                    raise ValueError("The staged tree contains a link or special entry.")
                if sys.platform == "darwin":  # file flags are macOS/BSD only
                    os.chflags(path, 0, follow_symlinks=False)
                os.chmod(path, stat.S_IRWXU, follow_symlinks=False)
                folders += 1
            for name in file_names:
                path = os.path.join(parent, name)
                status = os.lstat(path)
                if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                    raise ValueError("The staged tree contains a link, hard link or special entry.")
                files += 1
                total += status.st_size
                if status.st_size > max_file_bytes or total > max_total_bytes:
                    raise ValueError("The staged tree is larger than the size budget.")
                if sys.platform == "darwin":
                    os.chflags(path, 0, follow_symlinks=False)
                os.chmod(path, 0o600, follow_symlinks=False)
                digest = hashlib.sha256()
                # Hash exactly as many bytes as lstat reported; O_NOFOLLOW in case of a swap.
                with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                relative = Path(path).relative_to(output).as_posix()
                inventory.append({"path": relative, "bytes": status.st_size, "sha256": digest.hexdigest()})
            if files + folders > max_files:
                raise ValueError("The staged tree has more files and folders than the budget allows.")
    except ValueError as exc:
        problem = str(exc)
    except OSError:
        problem = "The staged output could not be inspected."
    if problem:
        raise StagedTreeError(problem, purge(output))
    inventory.sort(key=lambda item: item["path"])
    # Canonical JSON, so a file name containing a newline or space cannot imitate another row.
    canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    combined = hashlib.sha256(canonical.encode())
    return {
        "files": files,
        "folders": folders,
        "bytes": total,
        "inventory": inventory,
        "tree_sha256": combined.hexdigest(),
    }


__all__ = ["StagedTreeError", "purge", "validate_staged_tree"]
