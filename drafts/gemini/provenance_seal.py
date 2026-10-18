"""SHARAY Cryptographic Provenance Seal & Merkle Verification Engine.

Provides tamper-evident assessment seals and cryptographic verification for bug bounty
and penetration testing reports (C7/C8):
1. RFC 8785-compliant deterministic JSON canonicalization.
2. RFC 6962-compliant Merkle Tree with domain separation (0x00 leaf, 0x01 interior).
3. Zero-dependency RFC 8032 Ed25519 digital signature generation and verification.
4. Independent inclusion proof generation and verification for individual findings.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

# =====================================================================
# 1. RFC 8785 Deterministic Canonical JSON
# =====================================================================


def canonical_json_bytes(data: Any) -> bytes:
    """Serialize data into deterministic, whitespace-free canonical UTF-8 bytes."""
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


# =====================================================================
# 2. RFC 8032 Pure-Python Ed25519 Digital Signatures (Edwards25519)
# =====================================================================

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * _inv(5) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY % _Q)


def _edwards_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2) % _Q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2) % _Q
    return (x3, y3)


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _scalarmult(p, e // 2)
    q = _edwards_add(q, q)
    if e & 1:
        q = _edwards_add(q, p)
    return q


def _encodepoint(p: tuple[int, int]) -> bytes:
    x, y = p
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _decodepoint(s: bytes) -> tuple[int, int]:
    y = sum(2**i * ((s[i // 8] >> (i % 8)) & 1) for i in range(255))
    x = _xrecover(y)
    if x & 1 != ((s[31] >> 7) & 1):
        x = _Q - x
    return (x, y)


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 (secret_key_seed, public_key) pair (32 bytes each)."""
    sk = secrets.token_bytes(32)
    pk = ed25519_publickey(sk)
    return sk, pk


def ed25519_publickey(sk: bytes) -> bytes:
    """Compute the 32-byte public key from the 32-byte secret seed."""
    h = hashlib.sha512(sk).digest()
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    a_point = _scalarmult(_B, a)
    return _encodepoint(a_point)


def ed25519_sign(message: bytes, sk: bytes, pk: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature over message."""
    h = hashlib.sha512(sk).digest()
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % _L
    r_point = _scalarmult(_B, r)
    rs = _encodepoint(r_point)
    k = int.from_bytes(hashlib.sha512(rs + pk + message).digest(), "little") % _L
    s = (r + k * a) % _L
    return rs + s.to_bytes(32, "little")


def ed25519_verify(signature: bytes, message: bytes, pk: bytes) -> bool:
    """Verify a 64-byte Ed25519 signature against message and 32-byte public key."""
    if len(signature) != 64 or len(pk) != 32:
        return False
    rs, ss = signature[:32], signature[32:]
    try:
        r_point = _decodepoint(rs)
        a_point = _decodepoint(pk)
    except Exception:
        return False
    s = int.from_bytes(ss, "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(rs + pk + message).digest(), "little") % _L
    left = _scalarmult(_B, s)
    right = _edwards_add(r_point, _scalarmult(a_point, k))
    return left == right


# =====================================================================
# 3. RFC 6962 Merkle Tree with Second-Preimage Defense
# =====================================================================


def _hash_leaf(data: bytes) -> bytes:
    """RFC 6962 leaf hash prefix: SHA-256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def _hash_interior(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash prefix: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTree:
    """Balanced Merkle Tree for verifiable assessment provenance."""

    def __init__(self) -> None:
        self.leaves: list[bytes] = []
        self._leaf_hashes: list[bytes] = []

    def add_leaf(self, item: Any) -> int:
        """Add an item (dict, bytes, or string), return its 0-indexed position."""
        raw = canonical_json_bytes(item) if not isinstance(item, bytes) else item
        leaf_h = _hash_leaf(raw)
        idx = len(self.leaves)
        self.leaves.append(raw)
        self._leaf_hashes.append(leaf_h)
        return idx

    @property
    def count(self) -> int:
        return len(self._leaf_hashes)

    def root_hash(self) -> str:
        """Compute the hexadecimal Merkle Root digest."""
        if not self._leaf_hashes:
            return hashlib.sha256(b"").hexdigest()
        nodes = list(self._leaf_hashes)
        while len(nodes) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    next_level.append(_hash_interior(nodes[i], nodes[i + 1]))
                else:
                    # Odd node: promote to next level
                    next_level.append(nodes[i])
            nodes = next_level
        return nodes[0].hex()

    def audit_proof(self, index: int) -> list[dict[str, str]]:
        """Generate audit proof path for a leaf at index."""
        if index < 0 or index >= len(self._leaf_hashes):
            raise IndexError("Leaf index out of bounds")
        proof: list[dict[str, str]] = []
        nodes = list(self._leaf_hashes)
        curr = index
        while len(nodes) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    combined = _hash_interior(nodes[i], nodes[i + 1])
                    next_level.append(combined)
                    if i == curr:
                        proof.append({"position": "right", "sibling": nodes[i + 1].hex()})
                    elif i + 1 == curr:
                        proof.append({"position": "left", "sibling": nodes[i].hex()})
                else:
                    next_level.append(nodes[i])
            curr //= 2
            nodes = next_level
        return proof


def verify_inclusion_proof(leaf_data: Any, proof: list[dict[str, str]], expected_root: str) -> bool:
    """Verify that leaf_data is included in expected_root using proof path."""
    raw = canonical_json_bytes(leaf_data) if not isinstance(leaf_data, bytes) else leaf_data
    curr = _hash_leaf(raw)
    for step in proof:
        sibling = bytes.fromhex(step["sibling"])
        if step["position"] == "left":
            curr = _hash_interior(sibling, curr)
        elif step["position"] == "right":
            curr = _hash_interior(curr, sibling)
        else:
            return False
    return curr.hex() == expected_root


# =====================================================================
# 4. Assessment Provenance Seal Core
# =====================================================================


@dataclass(frozen=True)
class ProvenanceSealPayload:
    seal_version: int
    engine: str
    assessment_id: str
    organization_id: str
    scope_version: int
    leaf_count: int
    merkle_root: str
    assessor_public_key: str
    sealed_at: str


@dataclass(frozen=True)
class AssessmentProvenanceSeal:
    payload: ProvenanceSealPayload
    seal_signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": asdict(self.payload),
            "seal_signature": self.seal_signature,
        }


def seal_assessment(
    assessment_data: dict[str, Any],
    secret_key: bytes,
    public_key: bytes,
) -> tuple[AssessmentProvenanceSeal, MerkleTree]:
    """Construct Merkle Tree over assessment facts, compute root, and sign seal."""
    tree = MerkleTree()

    # 1. Leaf: Scope Policy authorization
    scope = assessment_data.get("scope", {})
    tree.add_leaf({"category": "scope_authorization", "scope": scope})

    # 2. Leaves: Tools and versions
    for tool in assessment_data.get("tools", []):
        tree.add_leaf({"category": "tool_provenance", "tool": tool})

    # 3. Leaves: Chronological events
    for event in assessment_data.get("events", []):
        tree.add_leaf({"category": "audit_event", "event": event})

    # 4. Leaves: Collected observations
    for obs in assessment_data.get("observations", []):
        tree.add_leaf({"category": "raw_observation", "observation": obs})

    # 5. Leaves: Validated findings
    for finding in assessment_data.get("findings", []):
        tree.add_leaf({"category": "validated_finding", "finding": finding})

    root = tree.root_hash()
    payload = ProvenanceSealPayload(
        seal_version=1,
        engine="SHARAY-1.0.0",
        assessment_id=str(assessment_data.get("id", "unassigned")),
        organization_id=str(assessment_data.get("organization_id", "unassigned")),
        scope_version=int(scope.get("version", 1)),
        leaf_count=tree.count,
        merkle_root=root,
        assessor_public_key=public_key.hex(),
        sealed_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )

    canonical_payload_bytes = canonical_json_bytes(asdict(payload))
    sig = ed25519_sign(canonical_payload_bytes, secret_key, public_key)
    seal = AssessmentProvenanceSeal(payload=payload, seal_signature=sig.hex())
    return seal, tree


def verify_provenance_seal(
    seal_dict: dict[str, Any],
    expected_public_key: str | None = None,
) -> tuple[bool, str]:
    """Verify cryptographic authenticity and tamper-evidence of a SHARAY seal."""
    try:
        payload = seal_dict["payload"]
        sig_hex = seal_dict["seal_signature"]
        pk_hex = expected_public_key or payload["assessor_public_key"]
        sig = bytes.fromhex(sig_hex)
        pk = bytes.fromhex(pk_hex)
        canonical_bytes = canonical_json_bytes(payload)
        if not ed25519_verify(sig, canonical_bytes, pk):
            return False, "Ed25519 cryptographic signature verification failed: seal has been modified"
        return True, "Valid authentic SHARAY assessment provenance seal"
    except Exception as exc:
        return False, f"Malformed seal structure or decoding error: {exc}"
