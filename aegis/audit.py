"""Append-only, hash-linked local audit events (not external tamper protection)."""

import hashlib
import json
import time
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
