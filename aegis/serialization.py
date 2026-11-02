"""Public serializers explicitly omit authentication and secrets."""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.models import (
    Assessment,
    AuditEvent,
    Finding,
    FindingEvidence,
    FindingHistory,
    Observation,
    Project,
    Target,
    User,
)


def timestamp(value: float | None) -> str | None:
    return datetime.fromtimestamp(value, timezone.utc).isoformat() if value is not None else None


def user_view(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "organization_id": user.organization_id,
    }


def project_view(row: Project) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "archived": row.archived,
        "created_at": timestamp(row.created_at),
    }


def target_view(row: Target) -> dict[str, Any]:
    from packages.security_policies import PolicyError, check_execution_url

    try:
        check_execution_url(row.scope, row.url, owned=row.verification_status == "operator_authorized")
        execution_blocker = None
    except PolicyError as exc:
        execution_blocker = str(exc)
    return {
        "id": row.id,
        "project_id": row.project_id,
        "url": row.url,
        "scope": row.scope,
        "scope_version": row.scope_version,
        "verification_status": row.verification_status,
        "execution_blocker": execution_blocker,
        "authorized_by": row.authorized_by,
        "approved_at": timestamp(row.approved_at),
        "created_at": timestamp(row.created_at),
    }


def assessment_view(row: Assessment) -> dict[str, Any]:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "target_id": row.target_id,
        "profile": row.profile,
        "status": row.status,
        "stage": row.stage,
        "scope_snapshot": row.scope_snapshot,
        "scope_version": row.scope_version,
        "retest_of": row.retest_of,
        "cancel_requested": row.cancel_requested,
        "created_at": timestamp(row.created_at),
        "started_at": timestamp(row.started_at),
        "finished_at": timestamp(row.finished_at),
        "error": row.error,
        "checks": row.checks,
    }


def observation_view(row: Observation) -> dict[str, Any]:
    return {
        "id": row.id,
        "assessment_id": row.assessment_id,
        "data": row.data,
        "evidence_hash": row.evidence_hash,
        "observed_at": timestamp(row.observed_at),
    }


def finding_view(db: Session, row: Finding, assessment_id: str | None = None) -> dict[str, Any]:
    query = (
        select(FindingEvidence)
        .join(Assessment, Assessment.id == FindingEvidence.assessment_id)
        .where(FindingEvidence.finding_id == row.id)
        .order_by(
            Assessment.finished_at.asc().nullsfirst(),
            Assessment.created_at,
            Assessment.id,
            FindingEvidence.id,
        )
    )
    if assessment_id:
        query = query.where(FindingEvidence.assessment_id == assessment_id)
    evidence: list[dict[str, Any]] = [
        {"id": e.id, "assessment_id": e.assessment_id, "data": e.data, "evidence_hash": e.evidence_hash}
        for e in db.scalars(query)
    ]
    history = [
        {"status": h.status, "actor": h.actor, "reason": h.reason, "created_at": timestamp(h.created_at)}
        for h in db.scalars(
            select(FindingHistory)
            .where(FindingHistory.finding_id == row.id)
            .order_by(FindingHistory.created_at)
        )
    ]
    result = {
        "id": row.id,
        "project_id": row.project_id,
        "target_id": row.target_id,
        "fingerprint": row.fingerprint,
        "title": row.title,
        "category": row.category,
        "severity": row.severity,
        "confidence": row.confidence,
        "status": row.status,
        "description": row.description,
        "remediation": row.remediation,
        "affected_url": row.affected_url,
        "first_seen": timestamp(row.first_seen),
        "last_seen": timestamp(row.last_seen),
        "evidence": evidence,
        "history": history,
        "cvss": None,
        "business_impact": "Not assessed",
    }
    if assessment_id and evidence:
        snapshot = evidence[-1]["data"]
        result["current_status"] = row.status
        if not isinstance(snapshot, dict):
            return result
        for field in (
            "status",
            "title",
            "category",
            "severity",
            "confidence",
            "description",
            "remediation",
            "affected_url",
            "poc",
            "autopyverifier",
            "lifecycle_state",
        ):
            if field in snapshot:
                result[field] = snapshot[field]
    return result


def audit_view(row: AuditEvent) -> dict[str, Any]:
    return {
        "id": row.id,
        "actor": row.actor,
        "action": row.action,
        "resource_id": row.resource_id,
        "detail": row.detail,
        "created_at": timestamp(row.created_at),
        "previous_hash": row.previous_hash,
        "event_hash": row.event_hash,
    }
