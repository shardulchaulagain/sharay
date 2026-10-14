"""Private SQLite snapshots and recovery into a new directory, without changing records."""

import hashlib
import math
import os
import sqlite3
import stat
import tempfile
import time
from pathlib import Path

from alembic.script import ScriptDirectory
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from aegis.audit import verify_audit
from aegis.config import ROOT
from aegis.models import Base

_ERROR = "Database snapshot failed validation or could not be safely completed."


def _deadline(max_seconds: float) -> float:
    if type(max_seconds) not in (int, float) or not 0 < max_seconds <= 300 or not math.isfinite(max_seconds):
        raise ValueError("Snapshot deadline must be a finite number between zero and 300 seconds.")
    return time.monotonic() + max_seconds


def _check_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ValueError("Database snapshot exceeded its deadline.")


def _path(path: Path) -> Path:
    # Do not normalize '..' across a symbolic link before checking the path.
    if ".." in path.parts:
        raise ValueError(_ERROR)
    path = path.absolute()
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError(_ERROR)
    return path


def _source(path: Path) -> Path:
    path = _path(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(_ERROR)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = _path(Path(str(path) + suffix))
        if sidecar.exists() and not stat.S_ISREG(sidecar.stat().st_mode):
            raise ValueError(_ERROR)
    return path


def _connect(path: Path, deadline: float, *, readonly: bool) -> sqlite3.Connection:
    _check_time(deadline)
    connection = sqlite3.connect(
        path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True, timeout=0.05
    )
    connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    return connection


def _validate(path: Path, deadline: float) -> None:
    connection = _connect(path, deadline, readonly=True)
    engine = create_engine("sqlite://", creator=lambda: connection, poolclass=StaticPool)
    try:
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError(_ERROR)
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError(_ERROR)
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not (set(Base.metadata.tables) | {"alembic_version"}).issubset(tables):
            raise ValueError(_ERROR)
        revisions = {row[0] for row in connection.execute("SELECT version_num FROM alembic_version")}
        if revisions != set(ScriptDirectory(str(ROOT / "migrations")).get_heads()):
            raise ValueError(_ERROR)
        with Session(engine) as session:
            if not verify_audit(session):
                raise ValueError(_ERROR)
        _check_time(deadline)
    finally:
        engine.dispose()
        connection.close()


def _copy(source: Path, snapshot: Path, deadline: float) -> dict[str, str | int]:
    descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    reader = _connect(source, deadline, readonly=True)
    try:
        writer = _connect(snapshot, deadline, readonly=False)
        try:
            reader.backup(writer, pages=64, progress=lambda *_: _check_time(deadline), sleep=0.01)
            # A standalone snapshot must not depend on WAL/SHM sidecars.
            writer.execute("PRAGMA journal_mode=DELETE")
        finally:
            writer.close()
    finally:
        reader.close()
    _validate(snapshot, deadline)
    digest = hashlib.sha256()
    with snapshot.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            _check_time(deadline)
            digest.update(chunk)
        os.fsync(stream.fileno())
    _check_time(deadline)
    return {"sha256": digest.hexdigest(), "bytes": snapshot.stat().st_size}


def backup_database(data_dir: Path, destination: Path, *, max_seconds: float = 30) -> dict[str, str | int]:
    """Copy committed SQLite/WAL data to a new private snapshot; never overwrite."""
    deadline = _deadline(max_seconds)
    try:
        source = _source(data_dir / "aegis.db")
        destination = _path(destination)
        if destination.exists() or destination in {
            Path(str(source) + suffix) for suffix in ("-wal", "-shm", "-journal")
        }:
            raise ValueError(_ERROR)
        with tempfile.TemporaryDirectory(prefix=".sharay-backup-", dir=destination.parent) as folder:
            os.chmod(folder, 0o700)
            snapshot = Path(folder) / "snapshot.db"
            metadata = _copy(source, snapshot, deadline)
            _path(destination)
            _check_time(deadline)
            os.link(snapshot, destination)
        return metadata
    except Exception:
        raise ValueError(_ERROR) from None


def restore_database(snapshot: Path, new_data_dir: Path, *, max_seconds: float = 30) -> dict[str, str | int]:
    """Validate and restore into a brand-new private directory, without starting services."""
    deadline = _deadline(max_seconds)
    created = False
    destination: Path | None = None
    try:
        source = _source(snapshot)
        new_data_dir = _path(new_data_dir)
        if new_data_dir.exists():
            raise ValueError(_ERROR)
        with tempfile.TemporaryDirectory(prefix=".sharay-restore-", dir=new_data_dir.parent) as folder:
            os.chmod(folder, 0o700)
            copied = Path(folder) / "snapshot.db"
            metadata = _copy(source, copied, deadline)
            _path(new_data_dir)
            _check_time(deadline)
            new_data_dir.mkdir(mode=0o700)
            created = True
            os.chmod(new_data_dir, 0o700)
            destination = new_data_dir / "aegis.db"
            os.link(copied, destination)
        return metadata
    except Exception:
        if created:
            try:
                _path(new_data_dir)
                if destination is not None:
                    destination.unlink(missing_ok=True)
                new_data_dir.rmdir()
            except (OSError, ValueError):
                # Never follow a replaced path or erase unexpected recovery files.
                pass
        raise ValueError(_ERROR) from None
