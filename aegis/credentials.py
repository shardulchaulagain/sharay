"""Symmetric encryption for stored test credentials (P1-4).

Credentials are encrypted at rest with Fernet (AES-128-CBC + HMAC). The master key comes from
SHARAY_CREDENTIAL_KEY when set, otherwise a per-install key generated once at data_dir/credential.key
with 0600 permissions. Plaintext credential values never touch the database or any report.
"""

import os
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from aegis.config import Settings


@lru_cache(maxsize=8)
def _fernet_for(key_source: str, data_dir: str) -> Fernet:
    if key_source:
        return Fernet(key_source.encode())
    path = Path(data_dir) / "credential.key"
    if path.is_file():
        return Fernet(path.read_bytes())
    key = Fernet.generate_key()
    # Create exclusively with owner-only perms; never world/group readable.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
    except FileExistsError:  # a concurrent writer won the race
        return Fernet(path.read_bytes())
    return Fernet(key)


def _fernet(settings: Settings) -> Fernet:
    return _fernet_for(os.environ.get("SHARAY_CREDENTIAL_KEY", ""), str(settings.data_dir))


def encrypt(settings: Settings, plaintext: str) -> str:
    """Encrypt a credential value for storage; returns an opaque token string."""
    return _fernet(settings).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(settings: Settings, token: str) -> str:
    """Decrypt a stored credential token back to plaintext for use within a scan."""
    try:
        return _fernet(settings).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise ValueError("Credential could not be decrypted (wrong or rotated key).") from exc


def resolve_auth(settings: Settings, credentials) -> dict:
    """Decrypt approved credentials into an auth dict (cookies/headers) for an authenticated scan.

    Only credential NAMES are surfaced for evidence; plaintext values live only in the returned auth
    and are never stored. `credentials` is a sequence of Credential rows."""
    cookies: dict[str, str] = {}
    headers: dict[str, str] = {}
    names: list[str] = []
    for cred in credentials:
        value = decrypt(settings, cred.encrypted_value)
        names.append(cred.name)
        if cred.kind == "cookie" and cred.header_name:
            cookies[cred.header_name] = value
        elif cred.kind == "header" and cred.header_name:
            headers[cred.header_name] = value
        elif cred.kind == "bearer":
            headers["Authorization"] = f"Bearer {value}"
        elif cred.kind == "basic":
            headers["Authorization"] = f"Basic {value}"
    return {"cookies": cookies, "headers": headers, "identity_names": sorted(names)}
