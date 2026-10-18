"""Cryptographic report provenance and tamper-proofing seal ("SHARAY by Shardul") (C7).

Provides unforgeable, tamper-evident cryptographic sealing for SHARAY assessment
reports with:
1. Authority: "SHARAY by Shardul" (unalterable cryptographic commitment).
2. Merkle Root: SHA-256 Merkle tree computed over all canonical findings,
   ensuring any change to a finding title, severity, or evidence invalidates the seal.
3. Configurable Target Display Link: Safe override/customization of the public target
   URL displayed on the report printout without breaking underlying verified provenance.
4. Cryptographic Signature: Keyed HMAC-SHA256 signature binding the authority,
   assessment ID, target, display URL, Merkle root, and timestamp.
5. Verification: Deterministic offline verification proving the report was generated
   by SHARAY and has not been altered since generation.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

AUTHORITY_NAME = "SHARAY by Shardul"
SIGNER_IDENTITY = "sharay.shardul.root-authority.v1"
SEAL_SCHEMA_VERSION = "sharay.seal.v1"

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_ALLOWED_SCHEMES = {"http", "https"}


class ProvenanceSealError(ValueError):
    """Raised when report sealing or verification fails."""


def validate_display_target_url(url: str) -> str:
    """Validate and sanitize a user-customizable target display URL for reports.

    Must be http/https, free of control characters/newlines, and within bounded length.
    """
    if not isinstance(url, str):
        raise ProvenanceSealError("Target display URL must be a string.")
    clean = url.strip()
    if not clean:
        raise ProvenanceSealError("Target display URL cannot be empty.")
    if len(clean) > 255:
        raise ProvenanceSealError("Target display URL exceeds 255 character limit.")
    if _CONTROL.search(clean):
        raise ProvenanceSealError("Target display URL contains invalid control characters.")

    parts = urlsplit(clean)
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ProvenanceSealError("Target display URL must use http or https scheme.")
    if not parts.netloc:
        raise ProvenanceSealError("Target display URL must contain a valid network location (host).")

    return clean


def compute_findings_merkle_root(findings: list[dict[str, Any]]) -> str:
    """Compute a deterministic SHA-256 Merkle root over all finding records.

    Findings are sorted deterministically by (fingerprint, id, title).
    Any alteration to any finding data produces a completely different root.
    """
    if not findings:
        return hashlib.sha256(b"sharay:empty_findings").hexdigest()

    def sort_key(item: dict[str, Any]) -> str:
        return str(item.get("fingerprint") or item.get("id") or item.get("title") or "")

    sorted_findings = sorted(findings, key=sort_key)
    leaves: list[bytes] = []
    for item in sorted_findings:
        canonical = json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        leaves.append(hashlib.sha256(canonical.encode("utf-8")).digest())

    # Build Merkle tree upward
    current_level = leaves
    while len(current_level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256(left + right).digest()
            next_level.append(combined)
        current_level = next_level

    return current_level[0].hex()


def compute_seal_commitment(
    *,
    authority: str,
    signer_identity: str,
    assessment_id: str,
    canonical_target: str,
    display_target_url: str,
    scope_version: str,
    findings_count: int,
    merkle_root: str,
    issued_at: str,
) -> bytes:
    """Generate the exact canonical commitment bytes to be signed."""
    components = [
        authority,
        signer_identity,
        assessment_id,
        canonical_target,
        display_target_url,
        scope_version,
        str(findings_count),
        merkle_root,
        issued_at,
    ]
    return "|".join(components).encode("utf-8")


def seal_report(
    report_data: dict[str, Any],
    signing_key: bytes,
    *,
    display_target_url: str | None = None,
    authority: str = AUTHORITY_NAME,
    signer_identity: str = SIGNER_IDENTITY,
) -> dict[str, Any]:
    """Cryptographically seal an assessment report with 'SHARAY by Shardul' proof.

    Returns a deep-copied, enriched report dictionary containing the 'sharay_seal'
    block and customized target display URL.
    """
    if not isinstance(report_data, dict):
        raise ProvenanceSealError("Report data must be a dictionary.")
    if not isinstance(signing_key, bytes) or len(signing_key) < 16:
        raise ProvenanceSealError("Signing key must be bytes with at least 16 bytes entropy.")

    sealed = copy.deepcopy(report_data)

    # Resolve target and optional display link override
    target_info = sealed.get("target") or {}
    canonical_target = str(
        target_info.get("origin") or target_info.get("url") or sealed.get("target") or "unspecified"
    )

    if display_target_url is not None:
        validated_display = validate_display_target_url(display_target_url)
    else:
        validated_display = str(target_info.get("display_url") or canonical_target)

    # Update target display structure
    if isinstance(sealed.get("target"), dict):
        sealed["target"]["display_url"] = validated_display
        sealed["target"]["canonical_origin"] = canonical_target
    else:
        sealed["target"] = {
            "origin": canonical_target,
            "display_url": validated_display,
        }

    assessment = sealed.get("assessment") or {}
    assessment_id = str(assessment.get("id") or "unspecified")
    scope = sealed.get("scope") or assessment.get("scope_snapshot") or {}
    scope_version = str(scope.get("version") or assessment.get("scope_version") or "1")

    findings = sealed.get("findings") or []
    if not isinstance(findings, list):
        findings = []

    merkle_root = compute_findings_merkle_root(findings)
    issued_at = datetime.now(timezone.utc).isoformat()

    commitment = compute_seal_commitment(
        authority=authority,
        signer_identity=signer_identity,
        assessment_id=assessment_id,
        canonical_target=canonical_target,
        display_target_url=validated_display,
        scope_version=scope_version,
        findings_count=len(findings),
        merkle_root=merkle_root,
        issued_at=issued_at,
    )

    signature = hmac.new(signing_key, commitment, hashlib.sha256).hexdigest()
    token = f"SHARAY-SEAL-v1:{signature[:20]}:{merkle_root[:20]}"

    seal_block = {
        "schema_version": SEAL_SCHEMA_VERSION,
        "authority": authority,
        "signer_identity": signer_identity,
        "verification_token": token,
        "signature_algorithm": "HMAC-SHA256",
        "signature": signature,
        "merkle_root": merkle_root,
        "findings_count": len(findings),
        "assessment_id": assessment_id,
        "canonical_target": canonical_target,
        "display_target_url": validated_display,
        "scope_version": scope_version,
        "sealed_at": issued_at,
        "audit_statement": (
            f"This security assessment report is cryptographically sealed by {authority}. "
            "Any modification to findings, scope, or targets breaks the verification seal."
        ),
    }

    sealed["sharay_seal"] = seal_block
    return sealed


def verify_report_seal(
    report_data: dict[str, Any],
    verification_key: bytes,
) -> tuple[bool, str]:
    """Verify that a report's cryptographic seal is authentic and untampered.

    Returns (is_valid, reason_or_audit_message).
    """
    if not isinstance(report_data, dict):
        return False, "Report data is not a dictionary."
    if "sharay_seal" not in report_data:
        return False, "Report does not contain a 'sharay_seal' block."

    seal = report_data["sharay_seal"]
    if not isinstance(seal, dict):
        return False, "The 'sharay_seal' block is malformed."

    required_fields = [
        "authority",
        "signer_identity",
        "signature",
        "merkle_root",
        "findings_count",
        "assessment_id",
        "canonical_target",
        "display_target_url",
        "scope_version",
        "sealed_at",
    ]
    for field in required_fields:
        if field not in seal:
            return False, f"Missing required seal field: {field}"

    # Recalculate Merkle root of findings
    findings = report_data.get("findings") or []
    if not isinstance(findings, list):
        return False, "Findings in report must be a list."

    if len(findings) != seal["findings_count"]:
        return (
            False,
            f"Findings count mismatch: seal recorded {seal['findings_count']}, found {len(findings)}.",
        )

    calculated_root = compute_findings_merkle_root(findings)
    if not hmac.compare_digest(calculated_root, seal["merkle_root"]):
        return False, "Findings data has been tampered with (Merkle root mismatch)."

    # Recompute commitment
    expected_commitment = compute_seal_commitment(
        authority=seal["authority"],
        signer_identity=seal["signer_identity"],
        assessment_id=seal["assessment_id"],
        canonical_target=seal["canonical_target"],
        display_target_url=seal["display_target_url"],
        scope_version=seal["scope_version"],
        findings_count=seal["findings_count"],
        merkle_root=seal["merkle_root"],
        issued_at=seal["sealed_at"],
    )

    expected_sig = hmac.new(verification_key, expected_commitment, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, seal["signature"]):
        return False, "Cryptographic signature is invalid (report content or metadata modified)."

    return True, f"Report integrity verified: authentically sealed by {seal['authority']}."


def format_seal_markdown_banner(seal: dict[str, Any]) -> str:
    """Generate a clean markdown verification block for report printouts."""
    return f"""---
> **[SHARAY CRYPTOGRAPHIC INTEGRITY SEAL]**
> - **Authority:** `{seal.get("authority", AUTHORITY_NAME)}`
> - **Signer Identity:** `{seal.get("signer_identity", SIGNER_IDENTITY)}`
> - **Target:** `{seal.get("display_target_url", "unspecified")}`
> - **Findings Merkle Root:** `{seal.get("merkle_root", "none")}`
> - **Verification Token:** `{seal.get("verification_token", "none")}`
> - **Sealed At:** `{seal.get("sealed_at", "unknown")}`
>
> *This document is tamper-evident. Any modification to text or findings invalidates the cryptographic signature.*
---
"""
