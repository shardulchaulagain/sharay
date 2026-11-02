"""Evidence and Artifact Object Storage Engine (Phase 5).

Provides local content-addressed storage for raw HTTP traces, PCAP dumps,
vulnerability evidence, and screenshots. Remote storage is not implemented.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol


class EvidenceStore(Protocol):
    """Protocol for content-addressed evidence and artifact storage."""

    def put(self, content: bytes, metadata: dict[str, Any] | None = None) -> str:
        """Store content and return its unique SHA-256 hash or storage key."""
        ...

    def get(self, key: str) -> bytes:
        """Retrieve binary content by key or SHA-256."""
        ...

    def exists(self, key: str) -> bool:
        """Check if content exists in store."""
        ...


class LocalEvidenceStore:
    """Secure, local filesystem content-addressed evidence store."""

    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir / "evidence"
        self.root_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path_for_hash(self, sha256_hash: str) -> Path:
        if not isinstance(sha256_hash, str) or re.fullmatch(r"[0-9a-f]{64}", sha256_hash) is None:
            raise ValueError("Evidence keys must be lowercase SHA-256 digests")
        prefix = sha256_hash[:2]
        return self.root_dir / prefix / sha256_hash

    @contextmanager
    def _directory(self, key: str, *, create: bool = False) -> Iterator[int]:
        self._path_for_hash(key)
        root = os.open(self.root_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory = None
        try:
            if create:
                os.fchmod(root, 0o700)
                try:
                    os.mkdir(key[:2], mode=0o700, dir_fd=root)
                except FileExistsError:
                    pass
            directory = os.open(key[:2], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            if create:
                os.fchmod(directory, 0o700)
            yield directory
        finally:
            if directory is not None:
                os.close(directory)
            os.close(root)

    @staticmethod
    def _read(directory: int, name: str) -> bytes:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            # Atomic replacement can unlink an inode after this descriptor opens it.
            if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                raise ValueError("Evidence artifacts must be regular files without hard links")
            return stream.read()

    @staticmethod
    def _write(directory: int, name: str, content: bytes) -> None:
        # Unique temporary files keep concurrent submissions from sharing partial writes.
        temporary = f".{uuid.uuid4().hex}.tmp"
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass

    @staticmethod
    def _verify(content: bytes, key: str) -> bytes:
        if hashlib.sha256(content).hexdigest() != key:
            raise ValueError("Evidence artifact failed its SHA-256 integrity check")
        return content

    def put(self, content: bytes, metadata: dict[str, Any] | None = None) -> str:
        sha256 = hashlib.sha256(content).hexdigest()
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("Evidence metadata must be an object")
        encoded_metadata = (
            json.dumps(metadata, indent=2, allow_nan=False).encode() if metadata is not None else None
        )
        with self._directory(sha256, create=True) as directory:
            try:
                self._verify(self._read(directory, sha256), sha256)
            except FileNotFoundError:
                self._write(directory, sha256, content)
            if encoded_metadata is not None:
                name = f"{sha256}.meta.json"
                try:
                    self._read(directory, name)
                except FileNotFoundError:
                    pass
                self._write(directory, name, encoded_metadata)
        return sha256

    def get(self, key: str) -> bytes:
        with self._directory(key) as directory:
            return self._verify(self._read(directory, key), key)

    def exists(self, key: str) -> bool:
        try:
            self.get(key)
        except FileNotFoundError:
            return False
        return True

    def get_metadata(self, key: str) -> dict[str, Any] | None:
        try:
            with self._directory(key) as directory:
                self._verify(self._read(directory, key), key)
                content = self._read(directory, f"{key}.meta.json")
        except FileNotFoundError:
            return None
        try:
            metadata = json.loads(content)
            json.dumps(metadata, allow_nan=False)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Evidence metadata is not valid JSON") from exc
        if not isinstance(metadata, dict):
            raise ValueError("Evidence metadata must be an object")
        return metadata


class S3EvidenceStore:
    """Unavailable S3 / MinIO adapter; never claim unperformed remote I/O."""

    def __init__(
        self,
        bucket_name: str,
        endpoint_url: str | None = None,
        prefix: str = "evidence",
    ) -> None:
        self.bucket = bucket_name
        self.endpoint_url = (endpoint_url or "https://s3.amazonaws.com").rstrip("/")
        self.prefix = prefix.strip("/")

    def _object_key(self, sha256_hash: str) -> str:
        return f"{self.prefix}/{sha256_hash[:2]}/{sha256_hash}"

    def put(self, content: bytes, metadata: dict[str, Any] | None = None) -> str:
        raise NotImplementedError("S3 evidence storage is not implemented; no artifact was uploaded.")

    def get(self, key: str) -> bytes:
        raise NotImplementedError("S3 evidence retrieval is not implemented.")

    def exists(self, key: str) -> bool:
        raise NotImplementedError("S3 evidence existence checks are not implemented.")


def get_evidence_store(data_dir: Path) -> EvidenceStore:
    """Return configured evidence store (S3 if configured in env, else LocalContentAddressedStorage)."""
    s3_bucket = os.environ.get("SHARAY_S3_BUCKET")
    if s3_bucket:
        return S3EvidenceStore(
            bucket_name=s3_bucket,
            endpoint_url=os.environ.get("SHARAY_S3_ENDPOINT"),
        )
    return LocalEvidenceStore(data_dir)


__all__ = [
    "EvidenceStore",
    "LocalEvidenceStore",
    "S3EvidenceStore",
    "get_evidence_store",
]
