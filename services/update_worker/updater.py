"""Zero-Telemetry Cryptographically-Verified Auto-Updater.

Sector 11: Packaging, Distribution & Docs (Milestone P3.11).
Provides:
1. Release manifest signature verification (HMAC-SHA256 / Ed25519).
2. Zero-telemetry update checks (manifests parsed locally, no client data transmitted).
3. Atomic binary swapping with staging and automated rollback on failure.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import logging
import os
import shutil
from typing import Any, Dict, List, Optional, Tuple

from packages.crypto.ed25519 import ed25519_sign_hex, ed25519_verify_hex

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class ReleaseManifest:
    """Represents a signed release manifest from the update channel."""

    version: str
    release_date: str
    sha256_hash: str
    binary_url: str
    mandatory_update: bool
    signature: str


class ZeroTelemetryUpdateManager:
    """Manages update discovery, binary hash verification, and atomic swap without telemetry."""

    def __init__(
        self,
        current_version: str = "0.1.0",
        public_key_hex: Optional[str] = None,
        notary_secret: Optional[str] = None,
    ) -> None:
        self.current_version = current_version
        self.public_key_hex = public_key_hex
        # No embedded default: a trust root must be supplied (Ed25519 public key or an explicit/env
        # HMAC secret). Without one, signature verification fails closed instead of trusting a
        # source-visible shared secret that anyone could forge against.
        resolved_secret = notary_secret or os.environ.get("SHARAY_UPDATE_SECRET")
        self.notary_secret = resolved_secret.encode("utf-8") if resolved_secret else None
        self.update_log: List[Dict[str, Any]] = []

    def verify_manifest_signature(self, manifest: ReleaseManifest) -> bool:
        """Verifies Ed25519 asymmetric (or legacy HMAC) digital signature of release manifest."""
        canonical = (
            f"{manifest.version}:{manifest.release_date}:{manifest.sha256_hash}:{manifest.binary_url}".encode(
                "utf-8"
            )
        )
        if self.public_key_hex:
            return ed25519_verify_hex(manifest.signature, canonical, self.public_key_hex)
        if len(manifest.signature) == 128 and not self.notary_secret:
            return False
        if self.notary_secret:
            calc_sig = hmac.new(self.notary_secret, canonical, hashlib.sha256).hexdigest()
            return hmac.compare_digest(calc_sig, manifest.signature)
        return False

    @staticmethod
    def sign_manifest_ed25519(manifest_data: dict[str, Any], private_key_hex: str) -> str:
        """Signs release manifest canonical fields with an Ed25519 private key."""
        canonical = f"{manifest_data['version']}:{manifest_data['release_date']}:{manifest_data['sha256_hash']}:{manifest_data['binary_url']}".encode(
            "utf-8"
        )
        return ed25519_sign_hex(canonical, private_key_hex)

    def check_for_update(self, manifest_json: str) -> Optional[ReleaseManifest]:
        """Parses signed release feed with zero client telemetry transmission."""
        try:
            data = json.loads(manifest_json)
            manifest = ReleaseManifest(
                version=data["version"],
                release_date=data["release_date"],
                sha256_hash=data["sha256_hash"],
                binary_url=data["binary_url"],
                mandatory_update=data.get("mandatory", False),
                signature=data["signature"],
            )

            # Signature check
            if not self.verify_manifest_signature(manifest):
                self.update_log.append(
                    {
                        "event": "signature_verification_failed",
                        "version": manifest.version,
                    }
                )
                return None

            # Version comparison (semver string parsing)
            if self._is_newer(manifest.version, self.current_version):
                return manifest
        except Exception as exc:
            self.update_log.append({"event": "manifest_parse_error", "error": str(exc)})
        return None

    def apply_update_staged(
        self,
        binary_bytes: bytes,
        manifest: ReleaseManifest,
        target_install_path: str,
    ) -> Tuple[bool, str]:
        """Verify the manifest signature and binary SHA-256, then atomically swap with rollback."""
        # 0. Signature check at the write boundary. The API calls this directly, so it cannot rely
        # on an earlier check_for_update; an invalid or unverifiable signature must never be applied.
        if not self.verify_manifest_signature(manifest):
            self.update_log.append({"event": "signature_verification_failed", "version": manifest.version})
            return (False, "Update rejected: manifest signature verification failed.")

        # 1. Integrity check
        calc_hash = hashlib.sha256(binary_bytes).hexdigest()
        if not hmac.compare_digest(calc_hash, manifest.sha256_hash):
            return (
                False,
                f"Binary SHA-256 mismatch (expected {manifest.sha256_hash}, calculated {calc_hash})",
            )

        # 2. Atomic in-place swap
        temp_dest = f"{target_install_path}.update.tmp"
        backup_dest = f"{target_install_path}.bak"
        try:
            with open(temp_dest, "wb") as f:
                f.write(binary_bytes)

            if os.path.exists(target_install_path):
                shutil.copy2(target_install_path, backup_dest)

            os.replace(temp_dest, target_install_path)
            self.current_version = manifest.version
            self.update_log.append({"event": "update_applied", "version": manifest.version})
            return True, f"Successfully upgraded to version {manifest.version}"
        except Exception as exc:
            # Rollback
            if os.path.exists(backup_dest):
                shutil.copy2(backup_dest, target_install_path)
            return False, f"Update application failed; rolled back: {exc}"
        finally:
            if os.path.exists(temp_dest):
                os.remove(temp_dest)

    @staticmethod
    def _is_newer(new_ver: str, curr_ver: str) -> bool:
        def parse_v(v: str) -> Tuple[int, ...]:
            return tuple(int(p) for p in v.lstrip("v").split(".") if p.isdigit())

        return parse_v(new_ver) > parse_v(curr_ver)
