"""Authenticated, organization-scoped local assessment API."""

import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from aegis.audit import audit, verify_audit
from aegis.auth import add_user, authenticate, check_csrf, require_role, sign_in
from aegis.config import ROOT, Settings
from aegis.database import create_database
from aegis.models import Assessment, AuditEvent, Finding, FindingEvidence, Observation, Project, Target, User
from aegis.schemas import (
    ApprovalInput,
    AssessmentInput,
    FindingUpdate,
    Login,
    MemberInput,
    ProjectInput,
    ProjectUpdate,
    TargetInput,
    TargetScopeUpdate,
)
from aegis.serialization import (
    assessment_view,
    audit_view,
    finding_view,
    observation_view,
    project_view,
    target_view,
    timestamp,
    user_view,
)
from packages.reporting import render_report
from packages.scanner_adapters import preflight
from packages.security_policies import PolicyError, ScopePolicy, normalize_url, validate_scope
from packages.shared_schemas import ProposedToolAction, adapter_roadmap

COOKIE = "aegis_session"
CONTROL_ROLES = ("owner", "security_administrator")
SCAN_ROLES = (*CONTROL_ROLES, "analyst")
TERMINAL = {"completed", "completed_with_errors", "cancelled", "failed"}


def get_db(request: Request):
    with request.app.state.sessions() as db:
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            db.execute(text("BEGIN IMMEDIATE"))
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise


DB = Annotated[Session, Depends(get_db)]


def current_user(request: Request, db: DB) -> User:
    user, session = authenticate(db, request.cookies.get(COOKIE))
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        check_csrf(session, request.headers.get("x-csrf-token"))
    return user


Actor = Annotated[User, Depends(current_user)]


def owned(db: Session, model, identifier: str, user: User):
    row = db.scalar(
        select(model).where(model.id == identifier, model.organization_id == user.organization_id)
    )
    if row is None:
        raise HTTPException(404, "Resource not found")
    return row


def page(db: Session, query, serializer, limit: int, offset: int):
    count = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    return {
        "items": [serializer(row) for row in db.scalars(query.limit(limit).offset(offset))],
        "total": count,
        "limit": limit,
        "offset": offset,
    }


def request_cancellation(db: Session, row: Assessment, user: User, reason: str = "operator_cancel"):
    if row.status in TERMINAL:
        return
    row.cancel_requested = True
    if row.status == "queued":
        row.status, row.stage, row.finished_at = (
            "cancelled",
            "Scope changed before execution" if reason == "scope_changed" else "Cancelled before execution",
            time.time(),
        )
    else:
        row.status, row.stage = "cancelling", "Stopping bounded HTTP request"
    audit(db, user.organization_id, user.id, "assessment.cancel_requested", row.id, {"reason": reason})


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    engine, sessions = create_database(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        import fcntl

        from aegis.worker import WorkerSupervisor

        instance = (settings.data_dir / "app.lock").open("a") if settings.start_worker else None
        if instance:
            try:
                fcntl.flock(instance, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                instance.close()
                engine.dispose()
                raise RuntimeError("Another SHARAY instance owns this data directory") from exc
        supervisor = WorkerSupervisor(settings) if settings.start_worker else None
        app.state.supervisor = supervisor
        try:
            if supervisor:
                supervisor.start()
            yield
        finally:
            try:
                if supervisor:
                    supervisor.stop()
            finally:
                if instance:
                    instance.close()
                engine.dispose()

    app = FastAPI(
        title="SHARAY local assessment API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.sessions = sessions
    app.state.engine = engine
    app.state.settings = settings
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1"])

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if request.headers.get("origin") != settings.origin:
                return JSONResponse({"detail": "Origin rejected", "request_id": request_id}, status_code=403)
            raw_length = request.headers.get("content-length", "0")
            if (
                len(raw_length) > 10
                or not raw_length.isascii()
                or not raw_length.isdecimal()
                or int(raw_length) > 65536
            ):
                return JSONResponse(
                    {"detail": "Request body exceeds 64 KiB", "request_id": request_id}, status_code=413
                )
            chunks, size = [], 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > 65536:
                    return JSONResponse(
                        {"detail": "Request body exceeds 64 KiB", "request_id": request_id}, status_code=413
                    )
                chunks.append(chunk)
            request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers.update(
            {
                "X-Request-ID": request_id,
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            }
        )
        if request.url.path.startswith("/api/"):
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        else:
            # Next static export has inline hydration scripts; evidence never enters them.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            )
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return JSONResponse(
            {"detail": exc.detail, "request_id": request.state.request_id}, status_code=exc.status_code
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Never return Pydantic input values (could contain a password).
        errors = [{"location": list(e["loc"]), "message": e["msg"]} for e in exc.errors()]
        return JSONResponse(
            {
                "detail": "Check the submitted fields",
                "errors": errors,
                "request_id": request.state.request_id,
            },
            status_code=422,
        )

    @app.exception_handler(ValueError)
    async def value_error(request: Request, exc: ValueError):
        return JSONResponse({"detail": str(exc), "request_id": request.state.request_id}, status_code=422)

    @app.get("/api/v1/health/live")
    def live():
        return {"status": "alive", "mode": "local_desktop"}

    @app.get("/api/v1/health/ready")
    def ready(db: DB):
        db.execute(text("SELECT 1"))
        supervisor = getattr(app.state, "supervisor", None)
        alive = bool(supervisor and supervisor.alive())
        return JSONResponse(
            {"database": "ready", "worker": "ready" if alive else "unavailable"},
            status_code=200 if alive or not settings.start_worker else 503,
        )

    @app.get("/api/v1/auth/bootstrap")
    def bootstrap(db: DB):
        return {"initialized": bool(db.scalar(select(User.id).limit(1)))}

    @app.post("/api/v1/auth/login")
    def login(data: Login, request: Request, response: Response, db: DB):
        client = request.client.host if request.client else "local"
        user, token, csrf = sign_in(db, data.username, data.password, client, settings.session_seconds)
        response.set_cookie(
            COOKIE,
            token,
            httponly=True,
            samesite="strict",
            secure=False,
            max_age=settings.session_seconds,
            path="/",
        )
        return {"user": user_view(user), "csrf_token": csrf}

    @app.get("/api/v1/auth/session")
    def session(request: Request, db: DB, user: Actor):
        _, record = authenticate(db, request.cookies.get(COOKIE))
        return {"user": user_view(user), "csrf_token": record.csrf}

    @app.post("/api/v1/auth/logout")
    def logout(request: Request, response: Response, db: DB, user: Actor):
        _, record = authenticate(db, request.cookies.get(COOKIE))
        db.delete(record)
        response.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict")
        audit(db, user.organization_id, user.id, "auth.logout", user.id)
        return {"status": "signed_out"}

    @app.get("/api/v1/auth/members")
    def members(db: DB, user: Actor):
        require_role(user, *CONTROL_ROLES)
        return {
            "items": [
                user_view(u)
                for u in db.scalars(select(User).where(User.organization_id == user.organization_id))
            ]
        }

    @app.post("/api/v1/auth/members", status_code=201)
    def member(data: MemberInput, db: DB, user: Actor):
        require_role(user, "owner")
        row = add_user(db, data.username, data.password, user.organization_id, data.role)
        audit(db, user.organization_id, user.id, "member.created", row.id, {"role": row.role})
        return user_view(row)

    @app.get("/api/v1/openapi.json")
    def schema(user: Actor):
        return app.openapi()

    @app.get("/api/v1/overview")
    def overview(db: DB, user: Actor):
        org = user.organization_id

        def count(model, *conditions):
            return (
                db.scalar(
                    select(func.count()).select_from(model).where(model.organization_id == org, *conditions)
                )
                or 0
            )

        return {
            "active_assessments": count(
                Assessment, Assessment.status.in_(["queued", "running", "cancelling"])
            ),
            "completed_assessments": count(
                Assessment, Assessment.status.in_(["completed", "completed_with_errors"])
            ),
            "confirmed_findings": count(Finding, Finding.status.in_(["confirmed", "reopened"])),
            "open_findings": count(
                Finding, Finding.status.not_in(["fixed", "false_positive", "accepted_risk"])
            ),
            "projects": count(Project, Project.archived.is_(False)),
            "assets": count(Target),
            "recent_assessments": [
                assessment_view(a)
                for a in db.scalars(
                    select(Assessment)
                    .where(Assessment.organization_id == org)
                    .order_by(Assessment.created_at.desc())
                    .limit(5)
                )
            ],
            "recent_events": [
                audit_view(a)
                for a in db.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.organization_id == org)
                    .order_by(AuditEvent.id.desc())
                    .limit(10)
                )
            ],
        }

    @app.get("/api/v1/projects")
    def projects(db: DB, user: Actor, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return page(
            db,
            select(Project)
            .where(Project.organization_id == user.organization_id)
            .order_by(Project.created_at.desc()),
            project_view,
            limit,
            offset,
        )

    @app.post("/api/v1/projects", status_code=201)
    def create_project(data: ProjectInput, db: DB, user: Actor):
        require_role(user, *SCAN_ROLES)
        if not data.name.strip():
            raise ValueError("Project name is required")
        row = Project(
            organization_id=user.organization_id,
            owner_id=user.id,
            name=data.name.strip(),
            description=data.description,
        )
        db.add(row)
        db.flush()
        audit(db, user.organization_id, user.id, "project.created", row.id)
        return project_view(row)

    @app.get("/api/v1/projects/{project_id}")
    def project(project_id: str, db: DB, user: Actor):
        row = owned(db, Project, project_id, user)
        return {
            **project_view(row),
            "targets": [
                target_view(t)
                for t in db.scalars(
                    select(Target).where(
                        Target.project_id == row.id, Target.organization_id == user.organization_id
                    )
                )
            ],
            "assessments": [
                assessment_view(a)
                for a in db.scalars(
                    select(Assessment)
                    .where(
                        Assessment.project_id == row.id, Assessment.organization_id == user.organization_id
                    )
                    .order_by(Assessment.created_at.desc())
                    .limit(100)
                )
            ],
            "findings": [
                finding_view(db, f)
                for f in db.scalars(
                    select(Finding)
                    .where(Finding.project_id == row.id, Finding.organization_id == user.organization_id)
                    .limit(100)
                )
            ],
        }

    @app.patch("/api/v1/projects/{project_id}")
    def update_project(project_id: str, data: ProjectUpdate, db: DB, user: Actor):
        require_role(user, *CONTROL_ROLES)
        row = owned(db, Project, project_id, user)
        if data.name is not None:
            if not data.name.strip():
                raise ValueError("Project name is required")
            data.name = data.name.strip()
        for key, value in data.model_dump(exclude_none=True).items():
            setattr(row, key, value)
        audit(db, user.organization_id, user.id, "project.updated", row.id)
        return project_view(row)

    @app.post("/api/v1/projects/{project_id}/targets", status_code=201)
    def create_target(project_id: str, data: TargetInput, db: DB, user: Actor):
        require_role(user, *CONTROL_ROLES)
        project = owned(db, Project, project_id, user)
        if project.archived:
            raise HTTPException(409, "Restore the project before registering targets")
        scope = validate_scope(data.scope, data.url)
        row = Target(
            organization_id=user.organization_id,
            project_id=project.id,
            url=normalize_url(data.url),
            scope=scope.model_dump(mode="json"),
        )
        db.add(row)
        db.flush()
        audit(
            db,
            user.organization_id,
            user.id,
            "scope.registered",
            row.id,
            {"scope_version": 1, "scope": row.scope, "verification": "awaiting_authorization"},
        )
        return target_view(row)

    @app.get("/api/v1/targets/{target_id}")
    def target(target_id: str, db: DB, user: Actor):
        return target_view(owned(db, Target, target_id, user))

    @app.patch("/api/v1/targets/{target_id}/scope")
    def update_scope(target_id: str, data: TargetScopeUpdate, db: DB, user: Actor):
        require_role(user, *CONTROL_ROLES)
        row = owned(db, Target, target_id, user)
        project = owned(db, Project, row.project_id, user)
        if project.archived:
            raise HTTPException(409, "Restore the project before editing target scopes")
        if data.expected_scope_version != row.scope_version:
            raise HTTPException(409, "Scope changed; reload and review the current version")
        scope = validate_scope(data.scope, data.url).model_dump(mode="json")
        url = normalize_url(data.url)
        if (url, scope) == (row.url, row.scope):
            return target_view(row)
        previous_url, previous_scope, previous_version = row.url, row.scope, row.scope_version
        row.url, row.scope, row.scope_version = url, scope, row.scope_version + 1
        row.verification_status, row.authorized_by, row.approved_at = "awaiting_authorization", None, None
        for pending in db.scalars(
            select(Assessment).where(
                Assessment.organization_id == user.organization_id,
                Assessment.target_id == row.id,
                Assessment.status.in_(["queued", "running", "cancelling"]),
            )
        ):
            request_cancellation(db, pending, user, "scope_changed")
        audit(
            db,
            user.organization_id,
            user.id,
            "scope.updated",
            row.id,
            {
                "previous_url": previous_url,
                "previous_scope": previous_scope,
                "previous_scope_version": previous_version,
                "url": url,
                "scope": scope,
                "scope_version": row.scope_version,
            },
        )
        return target_view(row)

    @app.post("/api/v1/targets/{target_id}/approve")
    def approve(target_id: str, data: ApprovalInput, db: DB, user: Actor):
        require_role(user, *CONTROL_ROLES)
        row = owned(db, Target, target_id, user)
        project = owned(db, Project, row.project_id, user)
        if project.archived:
            raise HTTPException(409, "Restore the project before approving targets")
        if data.expected_scope_version != row.scope_version:
            raise HTTPException(409, "Scope changed; reload and review the current version")
        validate_scope(row.scope, row.url)
        if data.acknowledgement != "I authorize this controlled laboratory target":
            raise HTTPException(422, "Explicit controlled laboratory authorization is required")
        row.verification_status, row.authorized_by, row.approved_at = "verified_lab", user.id, time.time()
        audit(
            db,
            user.organization_id,
            user.id,
            "scope.lab_approved",
            row.id,
            {"scope_version": row.scope_version, "scope": row.scope},
        )
        return target_view(row)

    @app.post("/api/v1/assessments", status_code=201)
    def launch(data: AssessmentInput, db: DB, user: Actor):
        require_role(user, *SCAN_ROLES)
        target = owned(db, Target, data.target_id, user)
        project = owned(db, Project, target.project_id, user)
        previous = db.scalar(
            select(Assessment).where(
                Assessment.organization_id == user.organization_id,
                Assessment.idempotency_key == data.idempotency_key,
            )
        )
        if previous:
            if (
                previous.target_id != data.target_id
                or previous.retest_of != data.retest_of
                or previous.scope_version != data.expected_scope_version
            ):
                raise HTTPException(409, "Idempotency key belongs to a different assessment request")
            return assessment_view(previous)
        if project.archived:
            raise HTTPException(409, "Project is archived")
        if data.expected_scope_version != target.scope_version:
            raise HTTPException(409, "Scope changed; reload and review the current version")
        if target.verification_status != "verified_lab" or not target.authorized_by:
            audit(db, user.organization_id, user.id, "assessment.authorization_rejected", target.id)
            db.commit()
            raise HTTPException(403, "Approve the controlled laboratory scope before assessment")
        try:
            validate_scope(target.scope, target.url)
        except PolicyError as exc:
            audit(
                db,
                user.organization_id,
                user.id,
                "assessment.scope_rejected",
                target.id,
                {"scope_version": target.scope_version, "reason": str(exc)},
            )
            db.commit()
            raise HTTPException(422, str(exc)) from None
        active = (
            db.scalar(
                select(func.count())
                .select_from(Assessment)
                .where(Assessment.status.in_(["queued", "running", "cancelling"]))
            )
            or 0
        )
        if active >= 10:
            raise HTTPException(429, "The local queue limit is ten assessments")
        if data.retest_of:
            baseline = owned(db, Assessment, data.retest_of, user)
            if baseline.target_id != target.id or baseline.status not in {
                "completed",
                "completed_with_errors",
            }:
                raise HTTPException(409, "Retest requires a completed assessment of the same target")
        snapshot = {
            **target.scope,
            "authorized_by": target.authorized_by,
            "verification_method": "explicit_controlled_lab",
            "approved_at": target.approved_at,
            "target_url": target.url,
        }
        row = Assessment(
            organization_id=user.organization_id,
            project_id=target.project_id,
            target_id=target.id,
            created_by=user.id,
            idempotency_key=data.idempotency_key,
            scope_snapshot=snapshot,
            scope_version=target.scope_version,
            retest_of=data.retest_of,
        )
        db.add(row)
        db.flush()
        audit(
            db,
            user.organization_id,
            user.id,
            "assessment.queued",
            row.id,
            {"target_id": target.id, "profile": "safe_http", "scope_version": target.scope_version},
        )
        return assessment_view(row)

    @app.get("/api/v1/assessments")
    def assessments(db: DB, user: Actor, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return page(
            db,
            select(Assessment)
            .where(Assessment.organization_id == user.organization_id)
            .order_by(Assessment.created_at.desc()),
            assessment_view,
            limit,
            offset,
        )

    @app.get("/api/v1/assessments/{assessment_id}")
    def assessment(assessment_id: str, db: DB, user: Actor):
        row = owned(db, Assessment, assessment_id, user)
        evidence_finding_ids = select(FindingEvidence.finding_id).where(
            FindingEvidence.assessment_id == row.id
        )
        return {
            **assessment_view(row),
            "observations": [
                observation_view(o)
                for o in db.scalars(
                    select(Observation).where(
                        Observation.assessment_id == row.id,
                        Observation.organization_id == user.organization_id,
                    )
                )
            ],
            "findings": [
                finding_view(db, f, row.id)
                for f in db.scalars(
                    select(Finding).where(
                        Finding.id.in_(evidence_finding_ids), Finding.organization_id == user.organization_id
                    )
                )
            ],
            "events": [
                audit_view(e)
                for e in db.scalars(
                    select(AuditEvent)
                    .where(
                        AuditEvent.resource_id == row.id, AuditEvent.organization_id == user.organization_id
                    )
                    .order_by(AuditEvent.id)
                )
            ],
        }

    @app.post("/api/v1/assessments/{assessment_id}/cancel")
    def cancel(assessment_id: str, db: DB, user: Actor):
        require_role(user, *SCAN_ROLES)
        row = owned(db, Assessment, assessment_id, user)
        request_cancellation(db, row, user)
        return assessment_view(row)

    @app.get("/api/v1/findings")
    def findings(
        db: DB,
        user: Actor,
        status: str | None = None,
        severity: str | None = None,
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ):
        query = select(Finding).where(Finding.organization_id == user.organization_id)
        if status:
            query = query.where(Finding.status == status)
        if severity:
            query = query.where(Finding.severity == severity)
        return page(
            db, query.order_by(Finding.last_seen.desc()), lambda f: finding_view(db, f), limit, offset
        )

    @app.patch("/api/v1/findings/{finding_id}")
    def update_finding(finding_id: str, data: FindingUpdate, db: DB, user: Actor):
        require_role(user, *SCAN_ROLES)
        row = owned(db, Finding, finding_id, user)
        from aegis.models import FindingHistory

        if data.status not in {
            "needs_triage",
            "suspected",
            "inconclusive",
            "false_positive",
            "accepted_risk",
            "remediation_in_progress",
        }:
            raise HTTPException(
                422, "Confirmation and fixed states require scanner evidence; choose a triage status"
            )
        row.status = data.status
        db.add(FindingHistory(finding_id=row.id, status=row.status, actor=user.id, reason="Analyst triage"))
        audit(db, user.organization_id, user.id, "finding.triaged", row.id, {"status": row.status})
        return finding_view(db, row)

    @app.get("/api/v1/integrations")
    def integrations(user: Actor):
        supervisor = getattr(app.state, "supervisor", None)
        return {
            "items": preflight(),
            "worker": "ready" if supervisor and supervisor.alive() else "unavailable",
            "ai": {"status": "disabled", "reason": "No provider configured; no evidence transmitted"},
        }

    @app.get("/api/v1/assets")
    def assets(db: DB, user: Actor, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return page(
            db,
            select(Target)
            .where(Target.organization_id == user.organization_id)
            .order_by(Target.created_at.desc()),
            target_view,
            limit,
            offset,
        )

    @app.get("/api/v1/tool-contracts")
    def tool_contracts(user: Actor):
        return {
            "proposal_schema": ProposedToolAction.model_json_schema(),
            "adapters": [metadata.model_dump(mode="json") for metadata in adapter_roadmap()],
            "execution": "Contracts describe fixed operations; this endpoint never executes them",
            "live_execution_enabled": False,
            "claude_review_request": "entry-748e50da33f94638",
        }

    @app.get("/api/v1/audit")
    def events(db: DB, user: Actor, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        require_role(user, *CONTROL_ROLES)
        result = page(
            db,
            select(AuditEvent)
            .where(AuditEvent.organization_id == user.organization_id)
            .order_by(AuditEvent.id.desc()),
            audit_view,
            limit,
            offset,
        )
        return {**result, "integrity_valid": verify_audit(db)}

    @app.get("/api/v1/reports/{assessment_id}")
    def report(assessment_id: str, db: DB, user: Actor, format: str = "html"):
        row = owned(db, Assessment, assessment_id, user)
        if row.status not in TERMINAL:
            raise HTTPException(409, "Wait for the assessment to stop before generating a report")
        detail = assessment(assessment_id, db, user)
        project = owned(db, Project, row.project_id, user)
        target = owned(db, Target, row.target_id, user)
        snapshot = row.scope_snapshot
        historical_target = {
            **target_view(target),
            "url": snapshot["target_url"],
            "scope": {key: value for key, value in snapshot.items() if key in ScopePolicy.model_fields},
            "scope_version": row.scope_version,
            "verification_status": "verified_lab",
            "authorized_by": snapshot["authorized_by"],
            "approved_at": timestamp(snapshot["approved_at"]),
        }
        data = {
            "assessment": assessment_view(row),
            "project": project_view(project),
            "target": historical_target,
            "scope": row.scope_snapshot,
            "observations": detail["observations"],
            "findings": detail["findings"],
            "checks": row.checks,
            "events": detail["events"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        body, content_type = render_report(data, format)
        extension = "md" if format == "markdown" else format
        return Response(
            body,
            media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="aegis-{row.id}.{extension}"'},
        )

    output = ROOT / "apps" / "web" / "out"
    if output.is_dir():
        app.mount("/", StaticFiles(directory=output, html=True), name="desktop_ui")
    return app
