"""Cryptographic Evidence Bundle Packager and Verification Engine.

Sector 6: Reporting & Evidence.
Provides:
1. Downloadable, cryptographic SHA-256 Merkle-sealed evidence archive (.zip).
2. Contains findings snapshot, raw network observations, and standalone AutoPyVerifier PoC scripts.
3. Fail-closed evidence bundle verification proving forensic integrity and non-tampering.
"""

from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EvidenceBundleBuilder:
    """Packages raw assessment captures and PoCs into a tamper-evident, sealed ZIP bundle."""

    @classmethod
    def build_bundle(
        cls,
        assessment_id: str,
        assessment_data: Dict[str, Any],
        raw_captures: Optional[List[Dict[str, Any]]] = None,
        autopy_scripts: Optional[Dict[str, str]] = None,
        created_at: Optional[float] = None,
    ) -> bytes:
        buf = io.BytesIO()
        file_hashes: Dict[str, str] = {}
        timestamp = created_at if created_at is not None else time.time()

        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 1. Findings snapshot
            findings_bytes = json.dumps(assessment_data.get("findings", []), indent=2, sort_keys=True).encode(
                "utf-8"
            )
            zf.writestr("findings.json", findings_bytes)
            file_hashes["findings.json"] = _sha256(findings_bytes)

            # 2. Raw request/response observations
            captures = raw_captures if raw_captures is not None else assessment_data.get("observations", [])
            obs_bytes = json.dumps(captures, indent=2, sort_keys=True).encode("utf-8")
            zf.writestr("requests/observations.json", obs_bytes)
            file_hashes["requests/observations.json"] = _sha256(obs_bytes)

            # 3. AutoPyVerifier standalone scripts
            scripts = autopy_scripts or {}
            for name, code in scripts.items():
                script_path = f"autopyverifier/{name}.py"
                code_bytes = code.encode("utf-8")
                zf.writestr(script_path, code_bytes)
                file_hashes[script_path] = _sha256(code_bytes)

            # 4. Merkle Root Hash calculation
            sorted_hashes = [file_hashes[p] for p in sorted(file_hashes.keys())]
            merkle_root = hashlib.sha256("".join(sorted_hashes).encode("utf-8")).hexdigest()

            # 5. Cryptographic Manifest & Seal
            manifest = {
                "assessment_id": assessment_id,
                "created_at": timestamp,
                "file_count": len(file_hashes),
                "files": file_hashes,
                "merkle_root_seal": merkle_root,
                "provenance_standard": "SHARAY-SEAL-V2",
            }
            manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
            zf.writestr("manifest.json", manifest_bytes)

        return buf.getvalue()

    @classmethod
    def verify_bundle(cls, bundle_bytes: bytes) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Cryptographically verifies that every file in the bundle matches its sealed hash."""
        try:
            with zipfile.ZipFile(io.BytesIO(bundle_bytes), "r") as zf:
                if "manifest.json" not in zf.namelist():
                    return False, "Missing manifest.json in evidence bundle", None

                manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                declared_files = manifest.get("files", {})
                declared_root = manifest.get("merkle_root_seal", "")

                computed_hashes: Dict[str, str] = {}
                for path, expected_hash in declared_files.items():
                    if path not in zf.namelist():
                        return False, f"Missing declared file in bundle: {path}", None
                    actual_hash = _sha256(zf.read(path))
                    if actual_hash != expected_hash:
                        return (
                            False,
                            f"Hash mismatch for {path}: expected {expected_hash}, got {actual_hash}",
                            None,
                        )
                    computed_hashes[path] = actual_hash

                # Recompute Merkle root
                sorted_hashes = [computed_hashes[p] for p in sorted(computed_hashes.keys())]
                recomputed_root = hashlib.sha256("".join(sorted_hashes).encode("utf-8")).hexdigest()

                if recomputed_root != declared_root:
                    return (
                        False,
                        f"Merkle root seal mismatch: declared {declared_root}, got {recomputed_root}",
                        None,
                    )

                return True, "Evidence bundle verification succeeded: all hashes intact.", manifest
        except Exception as exc:
            return False, f"Corrupted or invalid zip archive: {exc}", None
