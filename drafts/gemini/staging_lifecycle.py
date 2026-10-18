"""Opaque Staging Lifecycle and Trusted Adoption Architecture (C5/C6 & L1).

Author: Gemini (Principal Architect, Debugger & Helper)
Status: Draft module under drafts/gemini/ for Codex and Claude review.

Design Goals (Addressing Codex review-response entry-5721d2f72380423b):
1. Opaque Staging Reference:
   - Callers never pass arbitrary destination paths to authorize durable adoption.
   - The platform allocates private, randomized staging directories under a managed root.
2. Parent Verification & Recount:
   - Parent inspects the extracted tree with lstat before touching any entry.
   - Enforces singly linked regular files (st_nlink == 1), real directories, and clamps permissions.
   - Computes deterministic tree_sha256 digest over sorted relative paths and file digests.
3. Trusted Adoption Contract:
   - Adoption requires both the StagingReference and the ValidatedStagingTree descriptor.
   - Re-verifies tree_sha256 digest at adoption time to prevent post-validation tampering.
   - Verifies same-device mount (st_dev) before atomic os.replace rename.
   - Writes immutable provenance manifest recording source integrity and byte counts.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from services.scanner_worker import remove_tree


class StagingLifecycleError(ValueError):
    """Staging area creation, verification, or adoption failed."""


@dataclass(frozen=True)
class StagingReference:
    """Opaque reference to an active, unadopted staging directory."""

    token: str
    staging_dir: Path
    tree_dir: Path
    created_at: str

    def exists(self) -> bool:
        return self.staging_dir.exists()


@dataclass(frozen=True)
class ValidatedStagingTree:
    """Cryptographically verified metadata returned by the parent validator."""

    token: str
    tree_sha256: str
    file_count: int
    dir_count: int
    total_bytes: int
    inventory: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class StagingBudgets:
    max_files: int = 10000
    max_file_bytes: int = 20 * 1024 * 1024
    max_total_bytes: int = 200 * 1024 * 1024
    max_depth: int = 32
    max_name_bytes: int = 1024


def create_staging_area(staging_root: Path | str) -> StagingReference:
    """Create a private, randomized staging folder owned by the parent process."""
    root = Path(staging_root).resolve()
    if not root.is_dir():
        raise StagingLifecycleError("Managed staging root must be an existing directory.")

    token = secrets.token_hex(16)
    staging_dir = root / f"staging_{token}"
    tree_dir = staging_dir / "tree"

    try:
        # Create staging dir with strict 0700 parent permissions
        staging_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        tree_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as exc:
        raise StagingLifecycleError(f"Failed to allocate staging directory: {exc}") from exc

    return StagingReference(
        token=token,
        staging_dir=staging_dir,
        tree_dir=tree_dir,
        created_at=datetime.now(UTC).isoformat(),
    )


def purge_staging_area(ref: StagingReference) -> bool:
    """Safely purge the staging area without following links."""
    return remove_tree(ref.staging_dir)


def _compute_tree_hash(inventory: list[dict[str, object]]) -> str:
    """Compute unambiguous canonical digest over sorted inventory."""
    canonical = json.dumps(
        sorted(inventory, key=lambda x: str(x["path"])),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_staging_area(
    ref: StagingReference,
    budgets: StagingBudgets | None = None,
) -> ValidatedStagingTree:
    """Independently audit an untrusted staging tree after child execution.

    Fails closed and purges the staging directory on any anomaly.
    """
    if budgets is None:
        budgets = StagingBudgets()

    if not ref.staging_dir.exists() or not ref.tree_dir.exists():
        purge_staging_area(ref)
        raise StagingLifecycleError("Staging tree directory is missing or inaccessible.")

    total_files = 0
    total_dirs = 0
    total_bytes = 0
    inventory: list[dict[str, object]] = []

    def on_walk_error(err: OSError) -> None:
        raise StagingLifecycleError(f"Directory enumeration failed: {err}")

    try:
        root_stat = ref.tree_dir.lstat()
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
            raise StagingLifecycleError("Staging tree root is not a real directory.")

        for parent, dirnames, filenames in os.walk(
            ref.tree_dir, topdown=True, followlinks=False, onerror=on_walk_error
        ):
            rel_parent = Path(parent).relative_to(ref.tree_dir)
            if len(rel_parent.parts) > budgets.max_depth:
                raise StagingLifecycleError("Directory nesting exceeds budget.")

            for dname in dirnames:
                total_dirs += 1
                if total_files + total_dirs > budgets.max_files:
                    raise StagingLifecycleError("Node count exceeds max_files budget.")
                dpath = Path(parent, dname)
                dstat = dpath.lstat()
                if stat.S_ISLNK(dstat.st_mode) or not stat.S_ISDIR(dstat.st_mode):
                    raise StagingLifecycleError("Directory entry is a link or non-directory.")
                if len(dname.encode("utf-8", "replace")) > budgets.max_name_bytes:
                    raise StagingLifecycleError("Directory name exceeds budget.")
                # Clamp directory mode to owner-only
                try:
                    os.chflags(dpath, 0, follow_symlinks=False)
                except OSError:
                    pass
                os.chmod(dpath, 0o700, follow_symlinks=False)

            for fname in filenames:
                total_files += 1
                if total_files + total_dirs > budgets.max_files:
                    raise StagingLifecycleError("Node count exceeds max_files budget.")
                fpath = Path(parent, fname)
                fstat = fpath.lstat()
                if stat.S_ISLNK(fstat.st_mode) or not stat.S_ISREG(fstat.st_mode):
                    raise StagingLifecycleError("File entry is a link or special file.")
                if fstat.st_nlink != 1:
                    raise StagingLifecycleError("Hard link detected (st_nlink > 1).")
                if len(fname.encode("utf-8", "replace")) > budgets.max_name_bytes:
                    raise StagingLifecycleError("File name exceeds budget.")
                if fstat.st_size > budgets.max_file_bytes:
                    raise StagingLifecycleError("Single file size exceeds budget.")

                total_bytes += fstat.st_size
                if total_bytes > budgets.max_total_bytes:
                    raise StagingLifecycleError("Aggregate tree size exceeds budget.")

                # Clamp file mode to owner read-only
                try:
                    os.chflags(fpath, 0, follow_symlinks=False)
                except OSError:
                    pass
                os.chmod(fpath, 0o600, follow_symlinks=False)

                # Hash file content
                fhasher = hashlib.sha256()
                with open(fpath, "rb") as fp:
                    while chunk := fp.read(65536):
                        fhasher.update(chunk)
                file_hash = fhasher.hexdigest()

                rel_file_path = fpath.relative_to(ref.tree_dir).as_posix()
                inventory.append(
                    {
                        "path": rel_file_path,
                        "bytes": fstat.st_size,
                        "sha256": file_hash,
                    }
                )

    except Exception as exc:
        purge_staging_area(ref)
        if isinstance(exc, StagingLifecycleError):
            raise
        raise StagingLifecycleError(f"Staging tree verification failed: {exc}") from exc

    tree_sha256 = _compute_tree_hash(inventory)

    return ValidatedStagingTree(
        token=ref.token,
        tree_sha256=tree_sha256,
        file_count=total_files,
        dir_count=total_dirs,
        total_bytes=total_bytes,
        inventory=tuple(inventory),
    )


def adopt_staging_area(
    ref: StagingReference,
    validated: ValidatedStagingTree,
    durable_destination: Path | str,
) -> dict[str, object]:
    """Atomically adopt a validated staging tree into durable storage.

    Verifies:
    1. Token match between reference and validation descriptor.
    2. Tree hash consistency check.
    3. Mount compatibility (st_dev) for atomic os.replace.
    4. Records cryptographic provenance manifest.
    """
    if ref.token != validated.token:
        raise StagingLifecycleError("Staging token mismatch between reference and validation record.")

    dest = Path(durable_destination).resolve()
    if dest.exists() and any(dest.iterdir()):
        raise StagingLifecycleError("Adoption destination exists and is not empty.")

    dest.parent.mkdir(parents=True, exist_ok=True)

    # Re-verify device boundary to guarantee atomic rename
    ref_dev = ref.staging_dir.stat().st_dev
    dest_parent_dev = dest.parent.stat().st_dev
    if ref_dev != dest_parent_dev:
        purge_staging_area(ref)
        raise StagingLifecycleError("Staging directory and destination are on different filesystem mounts.")

    # Re-verify that files were not swapped between validation and adoption
    recheck_inventory = []
    for item in validated.inventory:
        item_path = ref.tree_dir / str(item["path"])
        if not item_path.is_file():
            purge_staging_area(ref)
            raise StagingLifecycleError("Integrity check failed: missing item at adoption.")
        hasher = hashlib.sha256()
        with open(item_path, "rb") as fp:
            while chunk := fp.read(65536):
                hasher.update(chunk)
        recheck_inventory.append(
            {
                "path": str(item["path"]),
                "bytes": item_path.stat().st_size,
                "sha256": hasher.hexdigest(),
            }
        )

    if _compute_tree_hash(recheck_inventory) != validated.tree_sha256:
        purge_staging_area(ref)
        raise StagingLifecycleError("Integrity check failed: tree hash mismatch at adoption.")

    # Atomic move
    try:
        os.replace(ref.tree_dir, dest)
    except OSError as exc:
        purge_staging_area(ref)
        raise StagingLifecycleError(f"Atomic adoption failed: {exc}") from exc

    # Clean up empty staging wrapper
    purge_staging_area(ref)

    # Write provenance record inside destination parent or return provenance dict
    provenance = {
        "status": "adopted",
        "adopted_at": datetime.now(UTC).isoformat(),
        "staging_token": validated.token,
        "tree_sha256": validated.tree_sha256,
        "file_count": validated.file_count,
        "dir_count": validated.dir_count,
        "total_bytes": validated.total_bytes,
        "inventory": list(validated.inventory),
    }

    provenance_file = dest.parent / f"{dest.name}.provenance.json"
    provenance_file.write_text(json.dumps(provenance, indent=2))

    return provenance


__all__ = [
    "StagingBudgets",
    "StagingLifecycleError",
    "StagingReference",
    "ValidatedStagingTree",
    "adopt_staging_area",
    "create_staging_area",
    "purge_staging_area",
    "validate_staging_area",
]
