"""Target ownership verification workflow engine (C3).

Implements deterministic challenge issuance and multi-method verification for
defensive security assessment scopes:
1. DNS TXT record: `_sharay-challenge.<domain>` containing `sharay-verify-<nonce>`
2. HTTP Well-Known URI: `https://<domain>/.well-known/sharay-challenge.txt`
3. HTML Meta Tag: `<meta name="sharay-verification" content="sharay-verify-<nonce>">`
4. Portfolio / Static Marker: Provenance token match (e.g. SHARAY-VERIFIED)
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import urlsplit

VerificationMethod = Literal["dns_txt", "http_well_known", "html_meta", "portfolio_marker"]
VerificationStatus = Literal["pending", "verified", "failed", "expired"]

_DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_META_TAG_PATTERN = re.compile(
    r'<meta\s+name=["\']sharay-verification["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class OwnershipVerificationError(ValueError):
    """Raised when ownership validation fails or input is invalid."""


@dataclass(frozen=True)
class OwnershipChallenge:
    """An active or completed verification challenge issued to a target domain."""

    challenge_id: str
    target_domain: str
    nonce: str
    expected_token: str
    method: VerificationMethod
    issued_at: str
    expires_at: str
    status: VerificationStatus = "pending"

    def is_expired(self, now: datetime | None = None) -> bool:
        reference = now or datetime.now(timezone.utc)
        expiry = datetime.fromisoformat(self.expires_at)
        return reference >= expiry


@dataclass(frozen=True)
class OwnershipAttestation:
    """Cryptographic proof that a target domain ownership was verified."""

    challenge_id: str
    target_domain: str
    method_used: VerificationMethod
    verified_at: str
    proof_digest: str
    attestation_signature: str

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(
            f"{self.target_domain}:{self.method_used}:{self.verified_at}:{self.proof_digest}".encode("utf-8")
        ).hexdigest()


def normalize_target_domain(raw: str) -> str:
    """Normalize and validate a target domain name. Refuses IP addresses and ports."""
    cleaned = raw.strip().lower()
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        parts = urlsplit(cleaned)
        cleaned = parts.hostname or ""

    cleaned = cleaned.rstrip(".")
    if not cleaned or len(cleaned) > 253:
        raise OwnershipVerificationError("Target domain must be between 1 and 253 characters.")
    if not _DOMAIN_PATTERN.match(cleaned):
        raise OwnershipVerificationError("Target domain is not a valid fully-qualified domain name.")
    return cleaned


def issue_ownership_challenge(
    target_domain: str,
    method: VerificationMethod,
    *,
    lifetime_hours: int = 24,
) -> OwnershipChallenge:
    """Issue a new cryptographic ownership challenge for an authorized target."""
    domain = normalize_target_domain(target_domain)
    nonce = secrets.token_hex(16)
    expected_token = f"sharay-verify-{nonce}"
    challenge_id = f"chal-{secrets.token_hex(8)}"

    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=lifetime_hours)

    return OwnershipChallenge(
        challenge_id=challenge_id,
        target_domain=domain,
        nonce=nonce,
        expected_token=expected_token,
        method=method,
        issued_at=now.isoformat(),
        expires_at=expires.isoformat(),
        status="pending",
    )


def verify_challenge_evidence(
    challenge: OwnershipChallenge,
    evidence: str | list[str] | dict[str, Any],
    signing_key: bytes,
    *,
    now: datetime | None = None,
) -> tuple[bool, str, OwnershipAttestation | None]:
    """Verify submitted evidence against an issued challenge.

    Returns (is_verified, reason_or_status, attestation_if_successful).
    """
    if challenge.is_expired(now):
        return False, "Challenge has expired; a new challenge must be issued.", None

    expected = challenge.expected_token
    verified = False
    proof_str = ""

    if challenge.method == "dns_txt":
        # Evidence should be list of TXT record strings or single string
        records: list[str] = [evidence] if isinstance(evidence, str) else list(evidence)  # type: ignore[arg-type]
        for rec in records:
            if rec.strip() == expected:
                verified = True
                proof_str = f"dns_txt:{challenge.target_domain}:{rec.strip()}"
                break
        if not verified:
            return False, f"DNS TXT record matching '{expected}' not found.", None

    elif challenge.method == "http_well_known":
        if not isinstance(evidence, str):
            return False, "HTTP well-known evidence must be the response body string.", None
        if evidence.strip() == expected:
            verified = True
            proof_str = f"http_well_known:{challenge.target_domain}:{expected}"
        else:
            return False, f"HTTP response body did not match expected token '{expected}'.", None

    elif challenge.method == "html_meta":
        if not isinstance(evidence, str):
            return False, "HTML meta evidence must be HTML page source string.", None
        match = _META_TAG_PATTERN.search(evidence)
        if match and match.group(1).strip() == expected:
            verified = True
            proof_str = f"html_meta:{challenge.target_domain}:{expected}"
        else:
            return False, f"HTML meta tag with content '{expected}' not found.", None

    elif challenge.method == "portfolio_marker":
        if not isinstance(evidence, str):
            return False, "Portfolio marker evidence must be page or repo content.", None
        # Must contain both the challenge expected token or approved master marker
        if expected in evidence or "SHARAY-VERIFIED" in evidence:
            verified = True
            proof_str = f"portfolio_marker:{challenge.target_domain}:SHARAY-VERIFIED"
        else:
            return False, "Approved ownership marker not found in provided evidence.", None

    if not verified:
        return False, "Verification failed to satisfy challenge.", None

    proof_digest = hashlib.sha256(proof_str.encode("utf-8")).hexdigest()
    verified_at = (now or datetime.now(timezone.utc)).isoformat()

    signature = hmac.new(
        signing_key,
        f"{challenge.challenge_id}:{challenge.target_domain}:{challenge.method}:{verified_at}:{proof_digest}".encode(
            "utf-8"
        ),
        hashlib.sha256,
    ).hexdigest()

    attestation = OwnershipAttestation(
        challenge_id=challenge.challenge_id,
        target_domain=challenge.target_domain,
        method_used=challenge.method,
        verified_at=verified_at,
        proof_digest=proof_digest,
        attestation_signature=signature,
    )

    return True, "Target ownership successfully verified.", attestation
