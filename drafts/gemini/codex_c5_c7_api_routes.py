"""Draft C5-C7 FastAPI router for controlled vulnerability validation, diagnostic sessions,
3-state impact calibration, cleanup verification, and tamper-evident report provenance.

Prepared in drafts/gemini/ for Codex (C5-C7 owner) to review and mount in `aegis/api.py`
via `app.include_router(create_validation_router())`.
Approved by human architect directive (signature: shardul).
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException
from sqlalchemy import select

from aegis.api import DB, SCAN_ROLES, Actor, owned
from aegis.audit import audit
from aegis.auth import require_role
from aegis.models import Assessment, Finding, FindingEvidence, FindingHistory
from aegis.serialization import timestamp
from drafts.gemini.codex_c4_c6_persistence import (
    CleanupVerification,
    CleanupVerificationCreate,
    DiagnosticSession,
    DiagnosticSessionCreate,
    DiagnosticSessionTerminate,
    ImpactCalibration,
    ImpactCalibrationCreate,
    ValidationRun,
    ValidationRunCreate,
    records_to_reconstruction_payload,
)
from drafts.gemini.report_provenance import (
    build_assessment_reconstruction,
    compute_provenance_envelope,
)


def validation_run_view(row: ValidationRun) -> dict[str, Any]:
    return {
        "id": row.id,
        "assessment_id": row.assessment_id,
        "finding_id": row.finding_id,
        "technique_id": row.technique_id,
        "vuln_class": row.vuln_class,
        "status": row.status,
        "root_cause": row.root_cause,
        "preconditions": row.preconditions,
        "request_evidence_id": row.request_evidence_id,
        "response_evidence_id": row.response_evidence_id,
        "observed_privileges": row.observed_privileges,
        "affected_resources": row.affected_resources,
        "observed_impact_summary": row.observed_impact_summary,
        "approved_by": row.approved_by,
        "created_at": timestamp(row.created_at),
        "completed_at": timestamp(row.completed_at),
    }


def diagnostic_session_view(row: DiagnosticSession) -> dict[str, Any]:
    return {
        "id": row.id,
        "assessment_id": row.assessment_id,
        "validation_run_id": row.validation_run_id,
        "transport": row.transport,
        "target_locator": row.target_locator,
        "state": row.state,
        "privilege_context": row.privilege_context,
        "accessible_resources": row.accessible_resources,
        "boundary_checks": row.boundary_checks,
        "opened_at": timestamp(row.opened_at),
        "last_heartbeat_at": timestamp(row.last_heartbeat_at),
        "expires_at": timestamp(row.expires_at),
        "terminated_at": timestamp(row.terminated_at),
        "duration_seconds": row.duration_seconds,
        "approved_by": row.approved_by,
    }


def impact_calibration_view(row: ImpactCalibration) -> dict[str, Any]:
    return {
        "id": row.id,
        "finding_id": row.finding_id,
        "validation_run_id": row.validation_run_id,
        "session_id": row.session_id,
        "theoretical_impact": row.theoretical_impact,
        "observed_impact": row.observed_impact,
        "not_yet_tested": row.not_yet_tested,
        "calibrated_severity": row.calibrated_severity,
        "rationale": row.rationale,
        "created_at": timestamp(row.created_at),
    }


def cleanup_verification_view(row: CleanupVerification) -> dict[str, Any]:
    return {
        "id": row.id,
        "session_id": row.session_id,
        "validation_run_id": row.validation_run_id,
        "artifacts_registered": row.artifacts_registered,
        "artifacts_removed": row.artifacts_removed,
        "verification_method": row.verification_method,
        "status": row.status,
        "evidence_id": row.evidence_id,
        "verified_at": timestamp(row.verified_at),
    }


def create_validation_router() -> APIRouter:
    router = APIRouter()

    @router.post("/api/v1/assessments/{assessment_id}/validations", status_code=201)
    def create_validation_run(
        assessment_id: str,
        data: ValidationRunCreate,
        db: DB,
        user: Actor,
    ) -> dict[str, Any]:
        require_role(user, *SCAN_ROLES)
        if data.assessment_id != assessment_id:
            raise HTTPException(422, "Path assessment_id must match payload assessment_id")
        asmt = owned(db, Assessment, assessment_id, user)
        if not asmt.scope_snapshot.get("authorized_by"):
            raise HTTPException(403, "Assessment scope snapshot lacks explicit authorization")
        finding = owned(db, Finding, data.finding_id, user)
        if finding.target_id != asmt.target_id:
            raise HTTPException(409, "Finding does not belong to the assessment target")

        now = time.time()
        row = ValidationRun(
            organization_id=user.organization_id,
            assessment_id=asmt.id,
            finding_id=finding.id,
            technique_id=data.technique_id,
            vuln_class=data.vuln_class,
            status=data.status,
            root_cause=data.root_cause,
            preconditions=data.preconditions,
            request_evidence_id=data.request_evidence_id,
            response_evidence_id=data.response_evidence_id,
            observed_privileges=data.observed_privileges,
            affected_resources=data.affected_resources,
            observed_impact_summary=data.observed_impact_summary,
            approved_by=data.approved_by,
            created_at=now,
            completed_at=now if data.status != "suspected" else None,
        )
        db.add(row)
        db.flush()

        if data.status == "confirmed_reproducible" and finding.status != "confirmed":
            finding.status = "confirmed"
            db.add(
                FindingHistory(
                    finding_id=finding.id,
                    status="confirmed",
                    actor=user.id,
                    reason=f"Confirmed by validation run {row.id} ({row.technique_id})",
                )
            )

        audit(
            db,
            user.organization_id,
            user.id,
            "validation.recorded",
            row.id,
            {
                "assessment_id": asmt.id,
                "finding_id": finding.id,
                "technique_id": row.technique_id,
                "status": row.status,
                "approved_by": row.approved_by,
            },
        )
        return validation_run_view(row)

    @router.post("/api/v1/assessments/{assessment_id}/sessions", status_code=201)
    def open_diagnostic_session(
        assessment_id: str,
        data: DiagnosticSessionCreate,
        db: DB,
        user: Actor,
    ) -> dict[str, Any]:
        require_role(user, *SCAN_ROLES)
        if data.assessment_id != assessment_id:
            raise HTTPException(422, "Path assessment_id must match payload assessment_id")
        asmt = owned(db, Assessment, assessment_id, user)
        val_run = owned(db, ValidationRun, data.validation_run_id, user)
        if val_run.assessment_id != asmt.id:
            raise HTTPException(409, "Validation run does not belong to this assessment")
        if val_run.status != "confirmed_reproducible":
            raise HTTPException(409, "Diagnostic session requires a confirmed_reproducible validation run")

        now = time.time()
        row = DiagnosticSession(
            organization_id=user.organization_id,
            assessment_id=asmt.id,
            validation_run_id=val_run.id,
            transport=data.transport,
            target_locator=data.target_locator,
            state="active",
            privilege_context=data.privilege_context,
            accessible_resources=data.accessible_resources,
            boundary_checks=data.boundary_checks,
            opened_at=now,
            last_heartbeat_at=now,
            expires_at=now + data.ttl_seconds,
            duration_seconds=0.0,
            approved_by=data.approved_by,
        )
        db.add(row)
        db.flush()
        audit(
            db,
            user.organization_id,
            user.id,
            "session.opened",
            row.id,
            {
                "assessment_id": asmt.id,
                "validation_run_id": val_run.id,
                "transport": row.transport,
                "ttl_seconds": data.ttl_seconds,
                "approved_by": row.approved_by,
            },
        )
        return diagnostic_session_view(row)

    @router.post("/api/v1/sessions/{session_id}/terminate")
    def terminate_diagnostic_session(
        session_id: str,
        data: DiagnosticSessionTerminate,
        db: DB,
        user: Actor,
    ) -> dict[str, Any]:
        require_role(user, *SCAN_ROLES)
        row = owned(db, DiagnosticSession, session_id, user)
        if row.state in {"terminated", "cleaned_up"}:
            return diagnostic_session_view(row)

        now = time.time()
        row.terminated_at = now
        row.last_heartbeat_at = now
        row.duration_seconds = round(max(0.0, now - row.opened_at), 3)
        row.state = "terminated"
        audit(
            db,
            user.organization_id,
            user.id,
            "session.terminated",
            row.id,
            {"duration_seconds": row.duration_seconds, "reason": data.reason},
        )
        return diagnostic_session_view(row)

    @router.post("/api/v1/findings/{finding_id}/impact-calibrations", status_code=201)
    def create_impact_calibration(
        finding_id: str,
        data: ImpactCalibrationCreate,
        db: DB,
        user: Actor,
    ) -> dict[str, Any]:
        require_role(user, *SCAN_ROLES)
        if data.finding_id != finding_id:
            raise HTTPException(422, "Path finding_id must match payload finding_id")
        finding = owned(db, Finding, finding_id, user)
        if data.validation_run_id is not None:
            owned(db, ValidationRun, data.validation_run_id, user)
        if data.session_id is not None:
            owned(db, DiagnosticSession, data.session_id, user)

        row = ImpactCalibration(
            organization_id=user.organization_id,
            finding_id=finding.id,
            validation_run_id=data.validation_run_id,
            session_id=data.session_id,
            theoretical_impact=data.theoretical_impact,
            observed_impact=data.observed_impact,
            not_yet_tested=data.not_yet_tested,
            calibrated_severity=data.calibrated_severity,
            rationale=data.rationale,
        )
        finding.severity = data.calibrated_severity
        db.add(row)
        db.flush()
        audit(
            db,
            user.organization_id,
            user.id,
            "finding.impact_calibrated",
            finding.id,
            {
                "calibration_id": row.id,
                "calibrated_severity": row.calibrated_severity,
                "untested_count": len(row.not_yet_tested or []),
            },
        )
        return impact_calibration_view(row)

    @router.post("/api/v1/sessions/{session_id}/cleanup", status_code=201)
    def verify_session_cleanup(
        session_id: str,
        data: CleanupVerificationCreate,
        db: DB,
        user: Actor,
    ) -> dict[str, Any]:
        require_role(user, *SCAN_ROLES)
        sess = owned(db, DiagnosticSession, session_id, user)
        now = time.time()
        if sess.terminated_at is None:
            sess.terminated_at = now
            sess.duration_seconds = round(max(0.0, now - sess.opened_at), 3)
        if data.status == "verified_clean":
            sess.state = "cleaned_up"

        row = CleanupVerification(
            organization_id=user.organization_id,
            session_id=sess.id,
            validation_run_id=data.validation_run_id or sess.validation_run_id,
            artifacts_registered=data.artifacts_registered,
            artifacts_removed=data.artifacts_removed,
            verification_method=data.verification_method,
            status=data.status,
            evidence_id=data.evidence_id,
            verified_at=now if data.status == "verified_clean" else None,
        )
        db.add(row)
        db.flush()
        audit(
            db,
            user.organization_id,
            user.id,
            "session.cleanup_verified",
            sess.id,
            {"cleanup_id": row.id, "status": row.status},
        )
        return cleanup_verification_view(row)

    @router.get("/api/v1/assessments/{assessment_id}/reconstruction")
    def get_assessment_reconstruction(
        assessment_id: str,
        db: DB,
        user: Actor,
    ) -> dict[str, Any]:
        asmt = owned(db, Assessment, assessment_id, user)
        finding_rows = list(
            db.scalars(
                select(Finding).where(
                    Finding.target_id == asmt.target_id,
                    Finding.organization_id == user.organization_id,
                )
            )
        )
        runs = list(
            db.scalars(
                select(ValidationRun).where(
                    ValidationRun.assessment_id == asmt.id,
                    ValidationRun.organization_id == user.organization_id,
                )
            )
        )
        sessions = list(
            db.scalars(
                select(DiagnosticSession).where(
                    DiagnosticSession.assessment_id == asmt.id,
                    DiagnosticSession.organization_id == user.organization_id,
                )
            )
        )
        finding_ids = [f.id for f in finding_rows]
        calibrations = (
            list(
                db.scalars(
                    select(ImpactCalibration).where(
                        ImpactCalibration.finding_id.in_(finding_ids),
                        ImpactCalibration.organization_id == user.organization_id,
                    )
                )
            )
            if finding_ids
            else []
        )
        session_ids = [s.id for s in sessions]
        cleanups = (
            list(
                db.scalars(
                    select(CleanupVerification).where(
                        CleanupVerification.session_id.in_(session_ids),
                        CleanupVerification.organization_id == user.organization_id,
                    )
                )
            )
            if session_ids
            else []
        )
        evidence_hashes = list(
            db.scalars(select(FindingEvidence.evidence_hash).where(FindingEvidence.assessment_id == asmt.id))
        )

        payload = records_to_reconstruction_payload(
            assessment=asmt,
            findings=finding_rows,
            validation_runs=runs,
            sessions=sessions,
            calibrations=calibrations,
            cleanups=cleanups,
            evidence_hashes=evidence_hashes,
        )
        reconstruction = build_assessment_reconstruction(payload)
        provenance = compute_provenance_envelope(payload)
        return {
            "assessment_id": asmt.id,
            "reconstruction": reconstruction,
            "sharay_provenance": provenance,
        }

    return router


def mount_validation_router(app: FastAPI) -> None:
    """Register C5-C7 validation/session/provenance routes on `app` before any
    catch-all `StaticFiles` mount at `/` (`aegis/api.py:771`), which otherwise
    intercepts POST requests with HTTP 405 Method Not Allowed.
    """
    router = create_validation_router()
    static_idx = next(
        (
            idx
            for idx, route in enumerate(app.router.routes)
            if getattr(route, "path", None) in {"", "/"} and getattr(route, "name", None) == "desktop_ui"
        ),
        None,
    )
    if static_idx is None:
        app.include_router(router)
    else:
        static_route = app.router.routes.pop(static_idx)
        app.include_router(router)
        app.router.routes.append(static_route)
