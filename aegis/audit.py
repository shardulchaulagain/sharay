import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.models import AuditEvent


def event_digest(event: AuditEvent) -> str:
    payload = [
        event.organization_id,
        event.actor,
        event.action,
        event.resource_id,
        event.detail,
        event.created_at,
        event.previous_hash,
    ]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def audit(
    db: Session, org: str, actor: str, action: str, resource: str, detail: dict[str, Any] | None = None
) -> None:
    db.flush()
    previous = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
    record = AuditEvent(
        organization_id=org,
        actor=actor,
        action=action,
        resource_id=resource,
        detail=detail or {},
        created_at=time.time(),
        previous_hash=previous.event_hash if previous else "0" * 64,
    )
    record.event_hash = event_digest(record)
    db.add(record)
    db.flush()


def verify_audit(db: Session) -> bool:
    previous = "0" * 64
    for row in db.scalars(select(AuditEvent).order_by(AuditEvent.id)):
        if row.previous_hash != previous or row.event_hash != event_digest(row):
            return False
        previous = row.event_hash
    return True


def record_egress_attestation(
    db: Session,
    org: str,
    actor: str,
    action: str,
    resource: str,
    detail: dict[str, Any] | None = None,
) -> str:
    """Record an egress firewall attestation event and return its cryptographic event hash."""
    audit(db, org=org, actor=actor, action=action, resource=resource, detail=detail)
    latest = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
    return latest.event_hash if latest else ""


@dataclass
class NotaryAnchorReceipt:
    anchor_id: str
    organization_id: str
    last_event_id: int
    chain_tip_hash: str
    notarized_at: float
    notary_signature: str
    public_key_fingerprint: str


class AuditNotaryService:
    """External Append-Only Notarization Ledger for tamper-evident audit logs."""

    def __init__(self, notary_secret_key: bytes | None = None) -> None:
        self.secret_key = notary_secret_key or secrets.token_bytes(32)
        self.pub_fingerprint = hashlib.sha256(self.secret_key).hexdigest()[:16]
        self.receipts: list[NotaryAnchorReceipt] = []

    def notarize_chain(self, db: Session, organization_id: str) -> NotaryAnchorReceipt | None:
        """Reads latest audit chain tip and commits signed anchor receipt."""
        latest_event = db.scalar(
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization_id)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        if latest_event is None:
            return None

        anchor_id = f"anchor-{secrets.token_hex(8)}"
        now = time.time()
        payload = f"{anchor_id}:{organization_id}:{latest_event.id}:{latest_event.event_hash}:{now}"
        signature = hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

        receipt = NotaryAnchorReceipt(
            anchor_id=anchor_id,
            organization_id=organization_id,
            last_event_id=latest_event.id,
            chain_tip_hash=latest_event.event_hash,
            notarized_at=now,
            notary_signature=signature,
            public_key_fingerprint=self.pub_fingerprint,
        )
        self.receipts.append(receipt)
        return receipt

    def verify_chain_against_receipt(self, db: Session, receipt: NotaryAnchorReceipt) -> tuple[bool, str]:
        """Proves that database audit ledger has not been tampered with up to anchor receipt."""
        payload = f"{receipt.anchor_id}:{receipt.organization_id}:{receipt.last_event_id}:{receipt.chain_tip_hash}:{receipt.notarized_at}"
        expected_sig = hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(receipt.notary_signature, expected_sig):
            return False, "Notary signature verification failed: invalid signature"

        target_event = db.get(AuditEvent, receipt.last_event_id)
        if target_event is None:
            return False, f"Event {receipt.last_event_id} missing from database (records deleted)"

        if target_event.event_hash != receipt.chain_tip_hash:
            return (
                False,
                f"Tamper detected at event {receipt.last_event_id}: "
                f"expected tip {receipt.chain_tip_hash}, found {target_event.event_hash}",
            )

        return True, f"Audit chain verified up to event {receipt.last_event_id} against external notary."


@dataclass
class AuditEntry:
    entry_id: str
    timestamp: float
    actor: str
    action: str
    target: str
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str


class SignedAuditLedgerExporter:
    """Exports cryptographic Merkle-sealed, append-only audit ledgers for regulatory compliance."""

    def __init__(self, signing_key: str = "sharay_audit_compliance_notary_key_2026") -> None:
        self.signing_key = signing_key.encode("utf-8")
        self.entries: list[AuditEntry] = []
        self._last_hash: str = "0" * 64

    def append_event(
        self,
        entry_id: str,
        actor: str,
        action: str,
        target: str,
        details: dict[str, Any],
        now: float | None = None,
    ) -> AuditEntry:
        ts = now if now is not None else time.time()
        prev = self._last_hash

        canonical_content = json.dumps(
            {
                "entry_id": entry_id,
                "timestamp": ts,
                "actor": actor,
                "action": action,
                "target": target,
                "details": details,
                "prev_hash": prev,
            },
            sort_keys=True,
        )

        entry_hash = hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()
        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=ts,
            actor=actor,
            action=action,
            target=target,
            details=details,
            prev_hash=prev,
            entry_hash=entry_hash,
        )
        self.entries.append(entry)
        self._last_hash = entry_hash
        return entry

    def generate_signed_export(self) -> dict[str, Any]:
        """Generates Merkle-anchored, signed export bundle."""
        if not self.entries:
            merkle_root = hashlib.sha256(b"EMPTY_LEDGER").hexdigest()
        else:
            hashes = [e.entry_hash for e in self.entries]
            while len(hashes) > 1:
                if len(hashes) % 2 != 0:
                    hashes.append(hashes[-1])
                new_level = []
                for i in range(0, len(hashes), 2):
                    combined = f"{hashes[i]}:{hashes[i + 1]}".encode("utf-8")
                    new_level.append(hashlib.sha256(combined).hexdigest())
                hashes = new_level
            merkle_root = hashes[0]

        sig_payload = f"{merkle_root}:{self._last_hash}:{len(self.entries)}".encode("utf-8")
        notary_signature = hmac.new(self.signing_key, sig_payload, hashlib.sha256).hexdigest()

        return {
            "format": "SHARAY-AUDIT-EXPORT-V1",
            "exported_at": time.time(),
            "total_entries": len(self.entries),
            "merkle_root": merkle_root,
            "last_block_hash": self._last_hash,
            "notary_signature": notary_signature,
            "ledger": [
                {
                    "entry_id": e.entry_id,
                    "timestamp": e.timestamp,
                    "actor": e.actor,
                    "action": e.action,
                    "target": e.target,
                    "details": e.details,
                    "prev_hash": e.prev_hash,
                    "entry_hash": e.entry_hash,
                }
                for e in self.entries
            ],
        }

    @classmethod
    def verify_export_integrity(cls, export_data: dict[str, Any], signing_key: str) -> tuple[bool, str]:
        """Verifies complete blockchain-style hash link continuity, Merkle root, and signature."""
        key_bytes = signing_key.encode("utf-8")
        entries = export_data.get("ledger", [])
        expected_root = export_data.get("merkle_root", "")
        last_block = export_data.get("last_block_hash", "")
        sig = export_data.get("notary_signature", "")

        sig_payload = f"{expected_root}:{last_block}:{len(entries)}".encode("utf-8")
        calc_sig = hmac.new(key_bytes, sig_payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, calc_sig):
            return False, "Cryptographic notary signature mismatch"

        current_prev = "0" * 64
        for idx, item in enumerate(entries):
            if item["prev_hash"] != current_prev:
                return (
                    False,
                    f"Hash-chain broken at entry index {idx}: expected prev {current_prev}, got {item['prev_hash']}",
                )

            canonical_content = json.dumps(
                {
                    "entry_id": item["entry_id"],
                    "timestamp": item["timestamp"],
                    "actor": item["actor"],
                    "action": item["action"],
                    "target": item["target"],
                    "details": item["details"],
                    "prev_hash": item["prev_hash"],
                },
                sort_keys=True,
            )
            calc_hash = hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()
            if calc_hash != item["entry_hash"]:
                return False, f"Entry hash tampered at index {idx}"

            current_prev = calc_hash

        if entries and current_prev != last_block:
            return False, "Final block hash mismatch"

        return True, "Audit chain valid, continuous, and verified"
