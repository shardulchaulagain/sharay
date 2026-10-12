"""Read less of the shared log: only what is new to one writer, optionally shortened.

    python -m scripts.log_view --agent claude            # full text of entries since my last one
    python -m scripts.log_view --agent claude --brief    # header plus the first 400 characters each
    python -m scripts.log_view --tree                    # short hash of the source tree

Record the tree hash next to a full test run (`suite @tree=<hash> -> ...`). The hash covers the
project's INPUTS: Python source and tests, gate and dependency manifests, and frontend source
and lockfile. It does not cover what is installed (interpreter, packages, node_modules), so an
equal hash means "same inputs", and a run may be reused only in the same environment.
Read-only: this never writes the log.
"""

import argparse
import hashlib
import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path

from scripts.session_log import DEFAULT_LOG, HEADER, ROOT, WRITERS, read_log

# Every file under these folders is an input, whatever its suffix, except what is generated.
INPUT_FOLDERS = (
    "aegis",
    "sharay",
    "packages",
    "services",
    "scripts",
    "tests",
    "fixtures",
    "migrations",
    "engineering",
    "apps/web",
    ".github",
)
ROOT_FILES = ("pyproject.toml", "alembic.ini", "requirements*.txt")
GENERATED_FOLDERS = {
    "node_modules",
    "out",
    ".next",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
GENERATED_FILES = (".DS_Store", ".pyc", ".tsbuildinfo")
_HASH_ERROR = "Cannot hash project inputs safely: an input is unavailable, linked, non-regular or changed."


def _file_digest(root_fd: int, relative: Path) -> bytes:
    """Pin directories without following links, then stream one unchanged regular file."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with ExitStack() as cleanup:
        parent_fd = root_fd
        parents = []
        for part in relative.parts[:-1]:
            opened = os.open(part, directory_flags, dir_fd=parent_fd)
            cleanup.callback(os.close, opened)
            parents.append((parent_fd, part, opened))
            parent_fd = opened
        leaf = relative.name
        expected = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(leaf, file_flags, dir_fd=parent_fd)
        cleanup.callback(os.close, descriptor)
        before = os.fstat(descriptor)

        def identity(value: os.stat_result) -> tuple[int, ...]:
            return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns

        if not stat.S_ISREG(before.st_mode) or identity(before) != identity(expected):
            raise ValueError(_HASH_ERROR)
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError(_HASH_ERROR)
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if identity(before) != identity(after) or identity(before) != identity(current):
            raise ValueError(_HASH_ERROR)
        for directory_fd, name, opened_fd in parents:
            current_directory = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            opened_directory = os.fstat(opened_fd)
            if not stat.S_ISDIR(current_directory.st_mode) or (
                current_directory.st_dev,
                current_directory.st_ino,
            ) != (opened_directory.st_dev, opened_directory.st_ino):
                raise ValueError(_HASH_ERROR)
        return digest.digest()


def unread(agent: str, log_path: Path = DEFAULT_LOG, brief: int = 0, since: str = "") -> list[str]:
    """Entries by other writers after this writer's latest entry (or after `since`), oldest first.

    Pass `since` (the last entry id you actually read) when others may have posted between
    your last read and your last write; otherwise those entries would be skipped.
    """
    if agent not in WRITERS:
        raise ValueError("Use an explicit writer")
    blocks = [
        block
        for block in re.split(r"\n(?=## entry-)", read_log(log_path))
        if HEADER.match(block.split("\n", 1)[0])
    ]
    last = max(
        (index for index, block in enumerate(blocks) if f" — {agent} — " in block.split("\n", 1)[0]),
        default=-1,
    )
    if since:
        found = [index for index, block in enumerate(blocks) if block.startswith(f"## {since} ")]
        if not found:
            # Falling back silently could hide exactly the entries the caller is looking for.
            raise ValueError("Unknown entry id for --since.")
        last = found[0]
    shown = []
    for block in blocks[last + 1 :]:
        if f" — {agent} — " in block.split("\n", 1)[0]:
            continue
        text = block.strip()
        if brief and len(text) > brief:
            text = text[:brief].rstrip() + f" …[{len(block)} characters; read the log for the rest]"
        shown.append(text)
    return shown


def tree_hash(root: Path = ROOT) -> str:
    """Hash regular inputs safely; this is neither an OS sandbox nor an atomic tree snapshot."""
    try:
        chosen = [path for pattern in ROOT_FILES for path in root.glob(pattern)]
        for folder in INPUT_FOLDERS:
            source = root / folder
            if source.is_symlink():
                raise ValueError(_HASH_ERROR)
            for path in source.rglob("*"):
                generated = GENERATED_FOLDERS.intersection(path.relative_to(root).parts)
                if generated or path.name.endswith(GENERATED_FILES):
                    continue
                if path.is_symlink():
                    raise ValueError(_HASH_ERROR)
                if path.is_file():
                    chosen.append(path)
                elif not path.is_dir():
                    raise ValueError(_HASH_ERROR)
        digest = hashlib.sha256()
        with ExitStack() as cleanup:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
            root_fd = os.open(root, flags)
            cleanup.callback(os.close, root_fd)
            for path in sorted(chosen):
                relative = path.relative_to(root)
                name = "/".join(relative.parts).encode()
                digest.update(name + b"\0" + _file_digest(root_fd, relative))
        return digest.hexdigest()[:12]
    except (OSError, ValueError, AttributeError):
        raise ValueError(_HASH_ERROR) from None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--agent", choices=WRITERS)
    parser.add_argument("--brief", action="store_true", help="Shorten each entry to 400 characters")
    parser.add_argument("--since", default="", help="Show entries after this entry id instead")
    parser.add_argument("--tree", action="store_true", help="Print the source tree hash and exit")
    args = parser.parse_args(argv)
    if args.tree:
        try:
            print(tree_hash())
        except ValueError:
            parser.error(_HASH_ERROR)
        return 0
    if not args.agent:
        parser.error("--agent is required unless --tree is given")
    try:
        entries = unread(args.agent, brief=400 if args.brief else 0, since=args.since)
    except ValueError as exc:
        parser.error(str(exc))
    print("\n\n".join(entries))
    print(f"\n{len(entries)} unread entr{'y' if len(entries) == 1 else 'ies'} for {args.agent}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
