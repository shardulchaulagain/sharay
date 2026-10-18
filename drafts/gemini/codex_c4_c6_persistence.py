"""Draft C4-C6 SQLAlchemy models, Pydantic schemas, and reconstruction bridge for SHARAY.

Prepared in drafts/gemini/ for Codex (C4-C6 owner) to review and merge into
`aegis/models.py`, `aegis/schemas.py`, and `aegis/api.py`.
Follows the exact conventions of `aegis/models.py` (UUID string primary keys via `identifier`,
`Float` epoch timestamps via `time.time`, and `JSON` columns).
Approved by human architect directive (signature: shardul).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import Field
from sqlalchemy import JSON, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegis.models import Assessment, Base, Finding, identifier
from aegis.schemas import Input

ValidationStatusLiteral = Literal[
    "suspected",
    "confirmed_reproducible",
    "validation_failed",
    "blocked_by_scope",
]

SessionStateLiteral = Literal[
    "opening",
    "active",
    "degraded",
    "expired",
    "terminated",
    "cleaned_up",
]

CleanupStatusLiteral = Literal[
    "pending",
    "verified_clean",
    "manual_action_required",
    "not_applicable",
]


def _epoch_to_iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


class ValidationRun(Base):
    """Stores an authorized vulnerability validation / reproduction run (C5)."""

    __tablename__ = "validation_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    technique_id: Mapped[str] = mapped_column(String(120), index=True)
    vuln_class: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(40), default="suspected", index=True)
    root_cause: Mapped[str] = mapped_column(Text, default="")
    preconditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    request_evidence_id: Mapped[str | None] = mapped_column(ForeignKey("finding_evidence.id"), nullable=True)
    response_evidence_id: Mapped[str | None] = mapped_column(ForeignKey("finding_evidence.id"), nullable=True)
    observed_privileges: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_resources: Mapped[list[str]] = mapped_column(JSON, default=list)
    observed_impact_summary: Mapped[str] = mapped_column(Text, default="")
    approved_by: Mapped[str] = mapped_column(String(80), default="shardul")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    completed_at: Mapped[float | None] = mapped_column(Float, nullable=True)


class DiagnosticSession(Base):
    """Stores a bounded interactive diagnostic session and its measured duration (C4/C5)."""

    __tablename__ = "diagnostic_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    validation_run_id: Mapped[str] = mapped_column(ForeignKey("validation_runs.id"), index=True)
    transport: Mapped[str] = mapped_column(String(64), default="http-session")
    target_locator: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(32), default="active", index=True)
    privilege_context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    accessible_resources: Mapped[list[str]] = mapped_column(JSON, default=list)
    boundary_checks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    opened_at: Mapped[float] = mapped_column(Float, default=time.time)
    last_heartbeat_at: Mapped[float] = mapped_column(Float, default=time.time)
    expires_at: Mapped[float] = mapped_column(Float)
    terminated_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    approved_by: Mapped[str] = mapped_column(String(80), default="shardul")


class ImpactCalibration(Base):
    """Separates theoretical, observed, and not-yet-tested impact for a finding (C6)."""

    __tablename__ = "impact_calibrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    validation_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("validation_runs.id"), index=True, nullable=True
    )
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("diagnostic_sessions.id"), index=True, nullable=True
    )
    theoretical_impact: Mapped[str] = mapped_column(Text)
    observed_impact: Mapped[str] = mapped_column(Text)
    not_yet_tested: Mapped[list[str]] = mapped_column(JSON, default=list)
    calibrated_severity: Mapped[str] = mapped_column(String(30), index=True)
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class CleanupVerification(Base):
    """Records controlled artifact cleanup and verification after diagnostic testing (C6/C7)."""

    __tablename__ = "cleanup_verifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("diagnostic_sessions.id"), index=True, nullable=True
    )
    validation_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("validation_runs.id"), index=True, nullable=True
    )
    artifacts_registered: Mapped[list[str]] = mapped_column(JSON, default=list)
    artifacts_removed: Mapped[list[str]] = mapped_column(JSON, default=list)
    verification_method: Mapped[str] = mapped_column(String(120), default="stateless-probe")
    status: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("finding_evidence.id"), nullable=True)
    verified_at: Mapped[float | None] = mapped_column(Float, nullable=True)


class ValidationRunCreate(Input):
    assessment_id: str = Field(min_length=1, max_length=36)
    finding_id: str = Field(min_length=1, max_length=36)
    technique_id: str = Field(min_length=1, max_length=120)
    vuln_class: str = Field(min_length=1, max_length=80)
    status: ValidationStatusLiteral = "suspected"
    root_cause: str = ""
    preconditions: dict[str, Any] = Field(default_factory=dict)
    request_evidence_id: str | None = None
    response_evidence_id: str | None = None
    observed_privileges: list[str] = Field(default_factory=list)
    affected_resources: list[str] = Field(default_factory=list)
    observed_impact_summary: str = ""
    approved_by: str = Field(default="shardul", min_length=1, max_length=80)


class DiagnosticSessionCreate(Input):
    assessment_id: str = Field(min_length=1, max_length=36)
    validation_run_id: str = Field(min_length=1, max_length=36)
    transport: str = Field(default="http-session", min_length=1, max_length=64)
    target_locator: str = Field(min_length=1, max_length=2000)
    privilege_context: dict[str, Any] = Field(default_factory=dict)
    accessible_resources: list[str] = Field(default_factory=list)
    boundary_checks: list[dict[str, Any]] = Field(default_factory=list)
    ttl_seconds: int = Field(default=900, ge=30, le=86400)
    approved_by: str = Field(default="shardul", min_length=1, max_length=80)


class DiagnosticSessionTerminate(Input):
    reason: str = Field(default="completed", min_length=1, max_length=240)


class ImpactCalibrationCreate(Input):
    finding_id: str = Field(min_length=1, max_length=36)
    validation_run_id: str | None = None
    session_id: str | None = None
    theoretical_impact: str = Field(min_length=1)
    observed_impact: str = Field(min_length=1)
    not_yet_tested: list[str] = Field(default_factory=list)
    calibrated_severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    rationale: str = ""


class CleanupVerificationCreate(Input):
    session_id: str | None = None
    validation_run_id: str | None = None
    artifacts_registered: list[str] = Field(default_factory=list)
    artifacts_removed: list[str] = Field(default_factory=list)
    verification_method: str = Field(default="stateless-probe", min_length=1, max_length=120)
    status: CleanupStatusLiteral = "verified_clean"
    evidence_id: str | None = None


def records_to_reconstruction_payload(
    *,
    assessment: Assessment,
    findings: list[Finding],
    validation_runs: list[ValidationRun],
    sessions: list[DiagnosticSession],
    calibrations: list[ImpactCalibration],
    cleanups: list[CleanupVerification],
    tools: list[dict[str, str]] | None = None,
    evidence_hashes: list[str] | None = None,
) -> dict[str, Any]:
    """Convert stored ORM rows into the dictionary contract consumed by
    `build_assessment_reconstruction` and `compute_provenance_envelope`.
    """
    run_by_id: dict[str, ValidationRun] = {run.id: run for run in validation_runs}
    root_cause_by_finding: dict[str, str] = {
        run.finding_id: run.root_cause for run in validation_runs if run.root_cause
    }
    calibrated_sev_by_finding: dict[str, str] = {
        cal.finding_id: cal.calibrated_severity for cal in calibrations if cal.calibrated_severity
    }

    finding_dicts: list[dict[str, Any]] = []
    for f in findings:
        finding_dicts.append(
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "status": f.status,
                "severity": calibrated_sev_by_finding.get(f.id, f.severity),
                "confidence": f.confidence,
                "affected_url": f.affected_url,
                "description": f.description,
                "root_cause": root_cause_by_finding.get(f.id, f.description),
                "remediation": f.remediation,
            }
        )

    validation_dicts: list[dict[str, Any]] = []
    for run in validation_runs:
        preconds = [f"{k}={v}" for k, v in sorted((run.preconditions or {}).items())]
        validation_dicts.append(
            {
                "finding_id": run.finding_id,
                "module_id": run.technique_id,
                "vulnerability_class": run.vuln_class,
                "outcome": run.status,
                "preconditions_met": preconds,
                "evidence_hash": run.response_evidence_id or run.request_evidence_id or "",
            }
        )

    session_dicts: list[dict[str, Any]] = []
    for sess in sessions:
        parent_run = run_by_id.get(sess.validation_run_id)
        session_dicts.append(
            {
                "session_id": sess.id,
                "finding_id": parent_run.finding_id if parent_run is not None else "",
                "session_kind": sess.transport,
                "state": sess.state,
                "established_at": _epoch_to_iso(sess.opened_at),
                "terminated_at": _epoch_to_iso(sess.terminated_at),
                "duration_seconds": sess.duration_seconds,
                "privilege_context": dict(sess.privilege_context or {}),
                "action_log": list(sess.boundary_checks or []),
            }
        )

    impact_dicts: list[dict[str, Any]] = []
    for cal in calibrations:
        impact_dicts.append(
            {
                "finding_id": cal.finding_id,
                "dimension": "observed_boundary",
                "state": "observed",
                "summary": cal.observed_impact,
                "evidence_hash": "",
            }
        )
        impact_dicts.append(
            {
                "finding_id": cal.finding_id,
                "dimension": "theoretical_ceiling",
                "state": "theoretical",
                "summary": cal.theoretical_impact,
                "evidence_hash": "",
            }
        )
        for untested in cal.not_yet_tested or []:
            impact_dicts.append(
                {
                    "finding_id": cal.finding_id,
                    "dimension": "untested_vector",
                    "state": "not_yet_tested",
                    "summary": str(untested),
                    "evidence_hash": "",
                }
            )

    cleanup_dicts: list[dict[str, Any]] = []
    for cl in cleanups:
        artifacts = list(cl.artifacts_registered or []) or ["session-state"]
        for idx, artifact in enumerate(artifacts):
            cleanup_dicts.append(
                {
                    "artifact_id": f"{cl.id}:{idx}",
                    "session_id": cl.session_id or "",
                    "artifact_kind": cl.verification_method,
                    "location": str(artifact),
                    "status": cl.status,
                    "verified_at": _epoch_to_iso(cl.verified_at),
                }
            )

    return {
        "assessment": {
            "id": assessment.id,
            "project_id": assessment.project_id,
            "target_id": assessment.target_id,
            "status": assessment.status,
            "profile": assessment.profile,
            "scope_snapshot": dict(assessment.scope_snapshot or {}),
            "scope_version": assessment.scope_version,
            "created_at": assessment.created_at,
            "started_at": assessment.started_at,
            "finished_at": assessment.finished_at,
        },
        "scope": {
            **dict(assessment.scope_snapshot or {}),
            "version": assessment.scope_version,
        },
        "tools": list(tools or []),
        "findings": finding_dicts,
        "validations": validation_dicts,
        "sessions": session_dicts,
        "impacts": impact_dicts,
        "cleanup_records": cleanup_dicts,
        "report_metadata": {
            "generated_at": _epoch_to_iso(assessment.finished_at or assessment.created_at),
            "evidence_hashes": list(evidence_hashes or []),
        },
    }
