"""Safe ingestion of supplied source archives (L6): extract data, never run it.

Only regular files and directories are written, without execute bits, inside a
new directory. Links and special files are skipped and reported. Traversal,
duplicates or any budget overrun reject the whole archive and remove what was
written. Sizes are counted while decompressing, never read from headers.

Budgets, precisely: max_file_bytes and max_total_bytes bound the bytes written
as files. For tar, a further stream budget bounds every decompressed byte the
reader pulls, including headers, extended metadata and the payload of skipped
entries. For zip, max_archive_bytes bounds the directory a parser must hold;
skipped zip entries are never decompressed.

Limit: this parses hostile bytes with the standard library in the caller's
process. The budgets bound archive size, decompressed bytes and created nodes,
not the parser's own time or memory, so it is a tested parser slice and not a
product upload path until it runs inside an isolated, staged ingestion job.
"""

import bz2
import gzip
import lzma
import os
import re
import shutil
import stat
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")
_CHUNK = 65536
_MAX_REPORTED = 100
MAX_DEPTH = 32
MAX_NAME_BYTES = 1024
_COMPRESSION: tuple[tuple[bytes, Any], ...] = (
    (b"\x1f\x8b", gzip.open),
    (b"BZh", bz2.open),
    (b"\xfd7zXZ\x00", lzma.open),
)


class ArchiveError(ValueError):
    """The archive is unsafe, unsupported or over budget; nothing from it was kept."""


class _Budgeted:
    """Counts every decompressed byte a tar reader pulls, headers and metadata included."""

    def __init__(self, stream: IO[bytes], limit: int):
        self.stream, self.remaining = stream, limit

    def read(self, size: int = -1) -> bytes:
        data = self.stream.read(size)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ArchiveError("The archive expands beyond its size budget.")
        return data


def _zip_members(archive: Path) -> Iterator[tuple[str, str, IO[bytes] | None]]:
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            kind = stat.S_IFMT(info.external_attr >> 16)
            if info.is_dir():
                yield info.filename, "directory", None
            elif kind not in (0, stat.S_IFREG):
                yield info.filename, "link or special file", None
            else:
                with bundle.open(info) as stream:
                    yield info.filename, "file", stream


def _tar_members(archive: Path, limit: int) -> Iterator[tuple[str, str, IO[bytes] | None]]:
    with open(archive, "rb") as raw:
        magic = raw.read(6)
    opener = next((opener for prefix, opener in _COMPRESSION if magic.startswith(prefix)), open)
    # Decompressed here and read as one forward stream, so tarfile's own header and
    # extended-metadata reads pass through the same byte budget as file contents.
    with opener(archive, "rb") as stream:
        try:
            bundle = tarfile.open(fileobj=_Budgeted(stream, limit), mode="r|")  # type: ignore[call-overload]
        except tarfile.ReadError as exc:
            raise ArchiveError("Only zip and tar archives are supported.") from exc
        with bundle:
            for member in bundle:
                if member.isdir():
                    yield member.name, "directory", None
                elif not member.isreg():
                    yield member.name, "link or special file", None
                elif member.issparse():
                    # Stream mode cannot rebuild the holes; an empty stand-in would misstate content.
                    yield member.name, "sparse file is not supported", None
                else:
                    yield member.name, "file", bundle.extractfile(member)


def _target(destination: Path, name: str) -> Path:
    parts = [part for part in name.replace("\\", "/").split("/") if part not in ("", ".")]
    if "\0" in name or name.startswith(("/", "\\")) or ".." in parts or (parts and ":" in parts[0]):
        raise ArchiveError("The archive contains an entry outside its own tree.")
    if len(parts) > MAX_DEPTH or len(name.encode("utf-8", "replace")) > MAX_NAME_BYTES:
        raise ArchiveError("The archive contains a path that is too deep or too long.")
    return destination.joinpath(*parts)


def extract_archive(
    archive: Path | str,
    destination: Path | str,
    *,
    max_files: int = 10000,
    max_file_bytes: int = 20 * 1024 * 1024,
    max_total_bytes: int = 200 * 1024 * 1024,
    max_archive_bytes: int = 100 * 1024 * 1024,
) -> dict:
    """Extract a zip or tar archive into a new directory; return counts and what was skipped.

    max_files bounds both the archive's entries and the files plus folders actually created.
    """
    archive, destination = Path(archive), Path(destination)
    budgets = (max_files, max_file_bytes, max_total_bytes, max_archive_bytes)
    # Checked before anything is read or created: a NaN or string budget must not disable a limit.
    if any(type(value) is not int for value in budgets) or not (
        1 <= max_files <= 100000
        and 1 <= max_file_bytes <= max_total_bytes <= 2 * 1024**3
        and 1 <= max_archive_bytes <= 2 * 1024**3
    ):
        raise ArchiveError("Budgets must be positive integers inside the supported bounds.")
    try:
        # Bounds what the zip directory or any uncompressed metadata can make a parser hold.
        if not archive.is_file() or archive.stat().st_size > max_archive_bytes:
            raise ArchiveError("The archive is missing or larger than the input budget.")
        is_zip = zipfile.is_zipfile(archive)
    except (OSError, RecursionError, MemoryError) as exc:
        raise ArchiveError("The archive could not be inspected safely.") from exc
    # Tar overhead allowance: one header and one extended header per entry, plus end blocks.
    members = (
        _zip_members(archive) if is_zip else _tar_members(archive, max_total_bytes + max_files * 2048 + 65536)
    )
    # A new directory, so no existing symlink or file can redirect a write.
    try:
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise ArchiveError("The destination must be a new directory.") from exc
    destination = destination.resolve()
    files = folders = total = entries = 0
    skipped: list[dict] = []

    def make_folders(folder: Path) -> None:
        # Implied parents count too: one deep path must not create unbudgeted directories.
        nonlocal folders
        missing = []
        while folder != destination and not folder.exists():
            missing.append(folder)
            folder = folder.parent
        for item in reversed(missing):
            folders += 1
            if files + folders > max_files:
                raise ArchiveError("The archive creates more files and folders than the budget allows.")
            item.mkdir(mode=0o700)

    try:
        for name, kind, stream in members:
            entries += 1
            if entries > max_files:
                raise ArchiveError("The archive has more entries than the file budget allows.")
            # Every entry's path is checked, including ones that will be skipped.
            target = _target(destination, name)
            if kind not in ("file", "directory"):
                # Never materialized: a later entry "through" it lands in a plain directory.
                if len(skipped) < _MAX_REPORTED:
                    skipped.append({"name": _UNPRINTABLE.sub("?", name)[:200], "reason": kind})
                continue
            if kind == "directory":
                make_folders(target)  # "./" resolves to the destination itself: nothing to do
                continue
            if target == destination or stream is None:
                raise ArchiveError("The archive contains a file entry without a usable name.")
            make_folders(target.parent)
            if files + folders >= max_files:
                raise ArchiveError("The archive creates more files and folders than the budget allows.")
            written = 0
            # O_EXCL: a duplicate name can never overwrite an earlier entry. No execute bit.
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                while chunk := stream.read(_CHUNK):
                    written += len(chunk)
                    total += len(chunk)
                    if written > max_file_bytes or total > max_total_bytes:
                        raise ArchiveError("The archive expands beyond its size budget.")
                    output.write(chunk)
            files += 1
    except BaseException as exc:
        # Whatever went wrong, even an unexpected error, nothing from this archive stays on disk.
        shutil.rmtree(destination, ignore_errors=True)
        if destination.exists():
            # Never report a clean rejection while partial output is still there.
            raise ArchiveError(
                "The archive was rejected and its partial output could not be removed."
            ) from exc
        expected = (
            ValueError,  # malformed names and unsupported member layouts raise these in the stdlib
            OSError,
            EOFError,
            RuntimeError,  # includes RecursionError from pathological nested metadata
            MemoryError,
            NotImplementedError,
            tarfile.TarError,
            zipfile.BadZipFile,
            lzma.LZMAError,
        )
        if isinstance(exc, ArchiveError) or not isinstance(exc, expected):
            raise
        # Corrupt data, encrypted entries, duplicate names and name collisions all end here.
        raise ArchiveError("The archive is corrupt, encrypted or has conflicting entries.") from exc
    return {"files": files, "folders": folders, "bytes": total, "skipped": skipped}


__all__ = ["ArchiveError", "extract_archive"]
