"""Authenticated, organization-scoped local assessment API."""

import asyncio
import base64
import dataclasses
import hashlib
import ipaddress
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from aegis.audit import audit, verify_audit
from aegis.auth import add_user, authenticate, check_csrf, require_role, sign_in
from aegis.config import ROOT, Settings
from aegis.database import create_database
from aegis.interactive import (
    MultiOperatorSessionCoordinator,
    OwnershipState,
    SessionError,
    terminal_manager,
)
from aegis.models import Assessment, AuditEvent, Finding, FindingEvidence, Observation, Project, Target, User
from aegis.schemas import (
    ApprovalInput,
    AssessmentInput,
    BulkTriageInput,
    CreateSessionInput,
    ExploitGateConfirmation,
    FindingUpdate,
    Login,
    MemberInput,
    OnboardingAdvanceInput,
    ProjectInput,
    ProjectUpdate,
    SavedViewInput,
    ScanConfig,
    SessionCollaborateJoinInput,
    SessionCollaborateTakeoverInput,
    SessionCollaborateTransferInput,
    SessionCopilotInput,
    SessionInputData,
    SessionOwnershipInput,
    SessionResizeInput,
    SourceAnalysisInput,
    TargetInput,
    TargetScopeUpdate,
    UpdateApplyInput,
    UpdateCheckInput,
    WorkspaceProbeInput,
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
from aegis.visualization import (
    TriageStatus,
    Vector3D,
    VirtualizedTableEngine,
    WebGLForceGraph3D,
    bulk_triage_engine,
)
from packages.reporting import render_report
from packages.reporting.async_renderer import get_report_manager
from packages.scanner_adapters.workspace import InteractiveWorkspace
from packages.security_policies import (
    PolicyError,
    ScopePolicy,
    check_execution_url,
    normalize_url,
    resolve_pinned,
    validate_execution_scope,
    validate_scope,
)
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


def active_integrations() -> list[dict]:
    try:
        from services.scanner_worker.container import attest as container_attest

        attestation = container_attest()
    except Exception:
        attestation = {"available": False}

    has_container = bool(attestation.get("available"))
    backend = attestation.get("backend", "rootless-container")
    runtime = attestation.get("runtime", "podman")

    return [
        {
            "id": "safe_http",
            "name": "SHARAY safe HTTP",
            "version": "1.1.6",
            "available": True,
            "runnable": True,
            "status": "implemented",
            "supported_categories": ["http_headers", "tls"],
            "scope": "In-process deterministic security header and TLS analyzer",
            "guidance": "In-process deterministic HTTP header analysis with zero external dependencies.",
            "limitations": "Operating-system trust store. DNS queries, authenticated testing and external scanner execution are unavailable in safe_http.",
        },
        {
            "id": "container_sandbox",
            "name": f"Podman Egress Isolation Engine ({runtime})",
            "version": "5.x",
            "available": has_container,
            "runnable": has_container,
            "status": "implemented" if has_container else "unavailable",
            "supported_categories": ["egress_isolation", "firewall", "sandboxing"],
            "scope": "Single-destination firewall, rootless container execution with dropped capabilities",
            "guidance": (
                f"Active and enforced via {backend}. Podman machine runs on Apple HV; traffic is locked strictly to the authorized target IP."
                if has_container
                else "Podman container runtime not detected."
            ),
            "limitations": "Allowlist enforced at VM FORWARD chain; non-whitelisted destinations are dropped immediately.",
        },
        {
            "id": "workspace_takeover",
            "name": "Interactive Operator Takeover Console",
            "version": "1.0.0",
            "available": True,
            "runnable": True,
            "status": "implemented",
            "supported_categories": ["interactive_probing", "command_verification", "takeover"],
            "scope": "Real-time bounded HTTP probe execution with audit logging",
            "guidance": "Live interactive inspection console with 15s timeout clamp, rate pacing, and 64KB display budgeting.",
            "limitations": "Operator authorization required; requests constrained to approved paths and methods.",
        },
        {
            "id": "nuclei",
            "name": "Nuclei Template Scanner (Containerized)",
            "version": "3.x",
            "available": has_container,
            "runnable": has_container,
            "status": "implemented" if has_container else "missing",
            "supported_categories": ["vulnerabilities", "cve", "misconfiguration"],
            "scope": "docker.io/projectdiscovery/nuclei:latest over enforced egress",
            "guidance": (
                "Containerized template runner active. Dispatched on approved profiles with output parsed into verified findings."
                if has_container
                else "Requires container runtime."
            ),
            "limitations": "Templates mounted read-only; interactsh and intrusive fuzzing tags excluded by policy.",
        },
        {
            "id": "metasploit",
            "name": "Metasploit Validation Catalog",
            "version": "6.x",
            "available": True,
            "runnable": True,
            "status": "implemented",
            "supported_categories": ["vulnerability_validation", "exploit_checks", "auxiliary"],
            "scope": "10-class vulnerability validation catalog with bounded checks",
            "guidance": "Validation catalog active for SQLi, XSS, SSRF, IDOR, and auth checks with strict session contracts.",
            "limitations": "Read-only auxiliary checks; exploit execution disallowed by policy.",
        },
        {
            "id": "zap",
            "name": "OWASP ZAP Baseline DAST",
            "version": "2.15",
            "available": has_container,
            "runnable": has_container,
            "status": "implemented" if has_container else "missing",
            "supported_categories": ["dast", "web_vulnerabilities"],
            "scope": "Traditional JSON report parser and container runner over enforced egress",
            "guidance": (
                "OWASP ZAP baseline container runner and report parser integrated."
                if has_container
                else "Requires container runtime."
            ),
            "limitations": "Execution bounded by single-destination egress firewall.",
        },
        {
            "id": "nmap",
            "name": "Nmap Network Mapper",
            "version": "7.95",
            "available": has_container,
            "runnable": has_container,
            "status": "implemented" if has_container else "missing",
            "supported_categories": ["network_inventory", "port_discovery"],
            "scope": "Bounded rate and port profiling with strict XML parser",
            "guidance": (
                "Typed argv builder and strict XML parser active over single-destination egress."
                if has_container
                else "Requires container runtime."
            ),
            "limitations": "Port count capped; rate budgeted to 5 pkts/sec max.",
        },
        {
            "id": "semgrep",
            "name": "Semgrep SAST Scanner",
            "version": "1.x",
            "available": False,
            "runnable": False,
            "status": "unavailable",
            "supported_categories": ["sast", "code_analysis"],
            "scope": "SARIF/JSON parser and containerized engine",
            "guidance": (
                "Engine verified and parser built, but no assessment dispatches it yet: source-code "
                "analysis has no input surface in the product. Needs a code-analysis assessment flow."
            ),
            "limitations": "Operates on a code tree, not an HTTP target; not reachable from the current URL-based assessment.",
        },
        {
            "id": "gitleaks",
            "name": "Gitleaks Secret Scanner",
            "version": "8.x",
            "available": False,
            "runnable": False,
            "status": "unavailable",
            "supported_categories": ["secrets", "credential_detection"],
            "scope": "Secret detection engine and SARIF report parser",
            "guidance": (
                "Binary verified and pinned (update ledger) and the parser is built, but no assessment "
                "dispatches it yet: source-code analysis has no input surface in the product."
            ),
            "limitations": "Operates on a code tree, not an HTTP target; not reachable from the current URL-based assessment.",
        },
        {
            "id": "source_analysis",
            "name": "Native Source Analysis (secrets + dependencies)",
            "version": "1.0.0",
            "available": True,
            "runnable": True,
            "status": "implemented",
            "supported_categories": ["secrets", "dependency_inventory", "code_analysis"],
            "scope": "In-process secret-pattern detection and declared-dependency inventory over an operator-authorized directory",
            "guidance": "POST /api/v1/source-analysis with a path confined to the configured source root. No binary, container or network; findings normalized like any other.",
            "limitations": "Reads a local code tree only, confined to SHARAY_SOURCE_ROOT. Pattern-based, not a replacement for Gitleaks/Semgrep, which remain uncatalogued for dispatch.",
        },
        {
            "id": "recon_dns_tls",
            "name": "Passive Recon, DNS & TLS Probing",
            "version": "1.0.0",
            "available": True,
            "runnable": True,
            "status": "implemented",
            "supported_categories": ["recon", "dns", "tls"],
            "scope": "Passive DNS, certificate inspection, asset discovery",
            "guidance": "Real-time passive DNS and TLS certificate analyzer.",
            "limitations": "Passive reconnaissance only; no brute-force enumeration.",
        },
        {
            "id": "ai_reasoning",
            "name": "Live AI Verification & Adversarial Reasoning Engine",
            "version": "1.0.0",
            "available": True,
            "runnable": True,
            "status": "implemented",
            "supported_categories": [
                "adversarial_reasoning",
                "attack_graph",
                "exploit_hypotheses",
                "confidence_calibration",
            ],
            "scope": "Directed Acyclic Attack Graph (DAG) with automated multi-step hypothesis synthesis and calibrated false-positive scoring",
            "guidance": "Active. Models targets, open ports, spidered endpoints, and parameters into multi-vector attack graphs with LLM adversarial verification.",
            "limitations": "Non-destructive hypothesis validation; external LLM calls use hermetic HTTPS with strict token redaction.",
        },
    ]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    engine, sessions = create_database(settings)
    report_manager_lock = threading.Lock()

    def report_manager():
        with report_manager_lock:
            if app.state.report_manager is None:
                app.state.report_manager = get_report_manager(settings.data_dir / "reports")
            return app.state.report_manager

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
                try:
                    if app.state.report_manager is not None:
                        app.state.report_manager.shutdown()
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
    app.state.report_manager = None
    app.state.ticketing_engine = None
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

    @app.post("/api/v1/auth/totp/setup")
    def totp_setup(user: Actor):
        from aegis.auth import TOTPEngine

        secret = TOTPEngine.generate_secret()
        uri = TOTPEngine.generate_provisioning_uri(secret, username=user.username)
        plain_codes, hashed_codes = TOTPEngine.generate_backup_codes(count=8)
        return {
            "secret": secret,
            "provisioning_uri": uri,
            "backup_codes": plain_codes,
            "backup_hashes": hashed_codes,
        }

    @app.post("/api/v1/auth/totp/verify")
    def totp_verify(data: dict[str, str], user: Actor):
        from aegis.auth import TOTPEngine

        secret = data.get("secret", "")
        code = data.get("code", "")
        if not secret or not code:
            raise HTTPException(400, "Secret and code are required")
        valid, counter = TOTPEngine.verify_otp(secret, code)
        if not valid:
            raise HTTPException(401, "Invalid TOTP verification code")
        return {"valid": True, "counter": counter}

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
        try:
            check_execution_url(row.scope, row.url)
            lab = True
        except PolicyError:
            lab = False
        accepted = {"I authorize this target within the displayed scope"}
        if lab:
            accepted.add("I authorize this controlled laboratory target")
        if data.acknowledgement not in accepted:
            raise HTTPException(422, "Explicit authorization of this target and displayed scope is required")
        row.verification_status = "verified_lab" if lab else "operator_authorized"
        row.authorized_by, row.approved_at = user.id, time.time()
        audit(
            db,
            user.organization_id,
            user.id,
            "scope.lab_approved" if lab else "scope.operator_authorized",
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
                or previous.profile != data.profile
            ):
                raise HTTPException(409, "Idempotency key belongs to a different assessment request")
            try:
                if not isinstance(previous.scope_snapshot, dict):
                    raise ValueError("Invalid stored scope snapshot")
                previous_scope = {
                    key: value
                    for key, value in previous.scope_snapshot.items()
                    if key in ScopePolicy.model_fields
                }
                requested = (data.config or ScanConfig()).within_scope(previous_scope)
                stored_config = previous.scope_snapshot.get("scan_config")
                stored = ScanConfig.model_validate(
                    {} if stored_config is None else stored_config
                ).within_scope(previous_scope)
            except ValueError:
                raise HTTPException(
                    409, "Idempotency key belongs to a different assessment request"
                ) from None
            if requested != stored:
                raise HTTPException(409, "Idempotency key belongs to a different assessment request")
            return assessment_view(previous)
        if project.archived:
            raise HTTPException(409, "Project is archived")
        if data.expected_scope_version != target.scope_version:
            raise HTTPException(409, "Scope changed; reload and review the current version")
        if (
            target.verification_status not in {"verified_lab", "operator_authorized"}
            or not target.authorized_by
        ):
            audit(db, user.organization_id, user.id, "assessment.authorization_rejected", target.id)
            db.commit()
            raise HTTPException(403, "Approve the exact target scope before assessment")
        try:
            config = (data.config or ScanConfig()).within_scope(target.scope)
            config.require_local_profile(data.profile)
            validate_execution_scope(
                target.scope, target.url, owned=target.verification_status == "operator_authorized"
            )
            check_execution_url(
                target.scope, target.url, owned=target.verification_status == "operator_authorized"
            )
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
            "verification_status": target.verification_status,
            "verification_method": "explicit_operator_authorization"
            if target.verification_status == "operator_authorized"
            else "explicit_controlled_lab",
            "approved_at": target.approved_at,
            "target_url": target.url,
        }
        snapshot["scan_config"] = config.model_dump()
        row = Assessment(
            organization_id=user.organization_id,
            project_id=target.project_id,
            target_id=target.id,
            created_by=user.id,
            idempotency_key=data.idempotency_key,
            scope_snapshot=snapshot,
            scope_version=target.scope_version,
            retest_of=data.retest_of,
            profile=data.profile,
        )
        db.add(row)
        db.flush()
        audit(
            db,
            user.organization_id,
            user.id,
            "assessment.queued",
            row.id,
            {"target_id": target.id, "profile": data.profile, "scope_version": target.scope_version},
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

    @app.post("/api/v1/interactive/sessions", status_code=201)
    def create_interactive_session(data: CreateSessionInput, db: DB, user: Actor):
        require_role(user, *SCAN_ROLES)
        target = owned(db, Target, data.target_id, user)
        if owned(db, Project, target.project_id, user).archived:
            raise HTTPException(409, "Project is archived")
        if (
            target.verification_status not in {"verified_lab", "operator_authorized"}
            or not target.authorized_by
        ):
            raise HTTPException(403, "Target must be approved before opening an interactive session")
        try:
            validate_execution_scope(
                target.scope, target.url, owned=target.verification_status == "operator_authorized"
            )
        except PolicyError as exc:
            raise HTTPException(422, str(exc)) from None
        host = urlsplit(target.url).hostname or ""
        try:
            # Only explicit literal loopback labs bypass the public-address resolver.
            target_ip = host if host in {"127.0.0.1", "::1"} else resolve_pinned(host)
            if target.scope.get("allowed_cidrs") and not any(
                ipaddress.ip_address(target_ip) in ipaddress.ip_network(cidr)
                for cidr in target.scope["allowed_cidrs"]
            ):
                raise PolicyError("Pinned address is outside the approved address ranges.")
        except PolicyError as exc:
            raise HTTPException(422, str(exc)) from None
        try:
            session = terminal_manager.create_session(
                organization_id=user.organization_id,
                target_id=str(target.id),
                target_url=target.url,
                target_ip=target_ip,
                created_by=user.id,
                cols=data.cols,
                rows=data.rows,
            )
        except SessionError as exc:
            raise HTTPException(409, str(exc)) from None
        session.scope_version = target.scope_version
        audit(
            db,
            user.organization_id,
            user.id,
            "session.created",
            target.id,
            {"session_id": session.id, "target_url": target.url, "target_ip": target_ip},
        )
        db.commit()
        return {
            "id": session.id,
            "target_id": str(target.id),
            "target_url": target.url,
            "target_ip": session.target_ip,
            "state": session.state,
            "ownership_state": session.ownership_state,
            "pid": session.pid,
        }

    @app.get("/api/v1/interactive/sessions")
    def list_interactive_sessions(user: Actor):
        require_role(user, *SCAN_ROLES)
        return {"items": terminal_manager.list_sessions(user.organization_id)}

    @app.get("/api/v1/interactive/sessions/{session_id}/stream")
    async def stream_interactive_session(session_id: str, request: Request, user: Actor):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")

        async def output_generator():
            cursor = session.output_start
            last_authorization = 0.0
            while True:
                if await request.is_disconnected():
                    break
                terminal_manager.get_session(session.id, user.organization_id)
                cursor, chunk = session.output_since(cursor)
                if chunk or time.monotonic() - last_authorization >= 1:
                    try:
                        with sessions() as check_db:
                            actor, _ = authenticate(check_db, request.cookies.get(COOKIE))
                            require_role(actor, *SCAN_ROLES)
                            target = owned(check_db, Target, session.target_id, actor)
                            project = owned(check_db, Project, target.project_id, actor)
                            if (
                                project.archived
                                or not target.authorized_by
                                or target.verification_status not in {"verified_lab", "operator_authorized"}
                                or target.scope_version != session.scope_version
                                or target.url != session.target_url
                            ):
                                session.terminate(reason="target_authorization_changed")
                                break
                            validate_execution_scope(
                                target.scope,
                                target.url,
                                owned=target.verification_status == "operator_authorized",
                            )
                        last_authorization = time.monotonic()
                    except PolicyError:
                        session.terminate(reason="scope_invalid")
                        break
                    except HTTPException:
                        break
                if chunk:
                    yield chunk
                elif not session.is_alive():
                    break
                else:
                    await asyncio.sleep(0.015)

        return StreamingResponse(
            output_generator(),
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/v1/interactive/sessions/{session_id}/input")
    def input_interactive_session(
        session_id: str, payload: SessionInputData, request: Request, db: DB, user: Actor
    ):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")
        target = owned(db, Target, session.target_id, user)
        project = owned(db, Project, target.project_id, user)
        if (
            project.archived
            or not target.authorized_by
            or target.verification_status not in {"verified_lab", "operator_authorized"}
        ):
            session.terminate(reason="target_authorization_revoked")
            raise HTTPException(403, "Target is no longer authorized for console commands")
        if session.scope_version != target.scope_version or session.target_url != target.url:
            session.terminate(reason="scope_changed")
            raise HTTPException(409, "Scope changed; open a new console after reviewing authorization")
        try:
            validate_execution_scope(
                target.scope, target.url, owned=target.verification_status == "operator_authorized"
            )
        except PolicyError as exc:
            session.terminate(reason="scope_invalid")
            raise HTTPException(422, str(exc)) from None

        scope = target.scope
        operator = {"id": user.id, "username": user.username, "role": user.role}
        organization_id = user.organization_id
        operator_authorized = target.verification_status == "operator_authorized"
        # Network diagnostics must not hold SQLite's writer lock and block Ctrl-C/EOF.
        db.commit()

        def retest_finding(finding_id: str) -> str:
            with sessions() as queue_db:
                queue_db.execute(text("BEGIN IMMEDIATE"))
                actor, _ = authenticate(queue_db, request.cookies.get(COOKIE))
                require_role(actor, *SCAN_ROLES)
                current_target = owned(queue_db, Target, session.target_id, actor)
                if (
                    current_target.scope_version != session.scope_version
                    or current_target.url != session.target_url
                ):
                    session.terminate(reason="scope_changed")
                    raise SessionError("Scope changed; open a new console after reviewing authorization")
                session.check_cancelled()
                finding = owned(queue_db, Finding, finding_id, actor)
                if finding.target_id != current_target.id:
                    raise SessionError("Finding belongs to a different session target.")
                baseline = queue_db.scalar(
                    select(Assessment)
                    .join(FindingEvidence, FindingEvidence.assessment_id == Assessment.id)
                    .where(
                        FindingEvidence.finding_id == finding.id,
                        Assessment.organization_id == actor.organization_id,
                        Assessment.target_id == current_target.id,
                        Assessment.status.in_(["completed", "completed_with_errors"]),
                    )
                    .order_by(Assessment.created_at.desc())
                )
                if baseline is None:
                    raise SessionError("Finding has no completed baseline assessment to retest.")
                launch_request = AssessmentInput.model_validate(
                    {
                        "target_id": current_target.id,
                        "idempotency_key": str(uuid.uuid4()),
                        "expected_scope_version": current_target.scope_version,
                        "retest_of": baseline.id,
                        "profile": baseline.profile,
                        "config": baseline.scope_snapshot.get("scan_config", {}),
                    }
                )
                result = launch(launch_request, queue_db, actor)
                queue_db.commit()
                return f"Queued assessment {result['id']} to retest finding {finding.id} (full approved profile)."

        def get_playbook(finding_id: str) -> str:
            with sessions() as queue_db:
                actor, _ = authenticate(queue_db, request.cookies.get(COOKIE))
                finding = owned(queue_db, Finding, finding_id, actor)
                from packages.reporting.reports import _reproduction_playbook, _verification_oracle

                evidence_data = {}
                if finding.evidence and isinstance(finding.evidence[0].data, dict):
                    evidence_data = finding.evidence[0].data
                finding_dict = {
                    "id": finding.id,
                    "title": finding.title,
                    "category": finding.category,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "status": finding.status,
                    "affected_url": finding.affected_url,
                    "description": finding.description,
                    "remediation": finding.remediation,
                    "poc": evidence_data.get("poc") or {},
                }
                pb = _reproduction_playbook(finding_dict, session.target_url)
                vo = _verification_oracle(finding_dict)
                return (
                    f"================================================================================\n"
                    f"SHARAY REPLICATION PLAYBOOK: {finding.title}\n"
                    f"================================================================================\n"
                    f"Asset: {finding.affected_url or session.target_url}\n"
                    f"Category: {finding.category} | Severity: {finding.severity} | Status: {finding.status}\n\n"
                    f"[REPLICATION STEPS]\n{pb}\n\n"
                    f"[VERIFICATION ORACLE]\n{vo}\n"
                    f"================================================================================"
                )

        def replay_poc(finding_id: str) -> str:
            with sessions() as queue_db:
                actor, _ = authenticate(queue_db, request.cookies.get(COOKIE))
                finding = owned(queue_db, Finding, finding_id, actor)
                from packages.reporting.poc_engine import synthesize_research_grade_poc

                evidence_data = {}
                if finding.evidence and isinstance(finding.evidence[0].data, dict):
                    evidence_data = finding.evidence[0].data
                finding_dict = {
                    "id": finding.id,
                    "title": finding.title,
                    "category": finding.category,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "status": finding.status,
                    "affected_url": finding.affected_url,
                    "description": finding.description,
                    "remediation": finding.remediation,
                    "poc": evidence_data.get("poc") or {},
                }
                snap_dir = os.path.abspath(".aegis/evidence/screenshots")
                poc_obj = synthesize_research_grade_poc(
                    finding_dict,
                    session.target_url,
                    evidence_data=evidence_data,
                    output_snapshot_dir=snap_dir,
                )
                return poc_obj.to_formatted_dossier()

        def run_exploit(finding_id: str) -> str:
            from packages.scanner_adapters.integrations.metasploit import resolve_metasploit_exploit

            with sessions() as queue_db:
                actor, _ = authenticate(queue_db, request.cookies.get(COOKIE))
                finding = owned(queue_db, Finding, finding_id, actor)
                category = (finding.category or "").lower()
                title = (finding.title or "").lower()
                cve = getattr(finding, "cve", None) or ""
                desc = getattr(finding, "description", "") or ""

                resolved = resolve_metasploit_exploit(
                    cve=cve, category=category, title=title, description=desc
                )
                if resolved:
                    mod = resolved["fullname"]
                    action = resolved.get("default_action", "check")
                else:
                    mod = "auxiliary/scanner/http/title"
                    action = "run"

                return session.execute(
                    f"msf {mod} {action}",
                    scope=scope,
                    operator=operator,
                    owned=operator_authorized,
                    retest=retest_finding,
                    playbook=get_playbook,
                    poc=replay_poc,
                )

        try:
            session.write(
                payload.data.encode("utf-8"),
                sender=payload.sender,
                handler=lambda command: session.execute(
                    command,
                    scope=scope,
                    operator=operator,
                    owned=operator_authorized,
                    retest=retest_finding,
                    playbook=get_playbook,
                    poc=replay_poc,
                    exploit=run_exploit,
                ),
            )
        except SessionError as exc:
            raise HTTPException(409, str(exc)) from exc
        audit(
            db,
            organization_id,
            operator["id"],
            "session.input",
            session.id,
            {
                "sender": payload.sender,
                "bytes": len(payload.data.encode("utf-8")),
                "last_event": session.flight_log[-1] if session.flight_log else {},
            },
        )
        return {"status": "ok", "ownership_state": session.ownership_state}

    @app.post("/api/v1/interactive/sessions/{session_id}/ownership")
    def set_session_ownership(session_id: str, payload: SessionOwnershipInput, user: Actor):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")
        if payload.state == OwnershipState.AGENT_OWNED.value:
            session.release_to_agent()
        elif payload.state == OwnershipState.HUMAN_OWNED.value:
            session.preempt_by_human()
        elif payload.state == OwnershipState.SHARED.value:
            session.set_shared()
        return {"status": "ok", "ownership_state": session.ownership_state}

    @app.post("/api/v1/interactive/sessions/{session_id}/exploit-gate/confirm")
    def confirm_exploit_gate(session_id: str, payload: ExploitGateConfirmation, db: DB, user: Actor):
        """Enforce Pre-Notification Active Exploit Gate (D4) and verify ALLOW_ACTIVE_EXPLOIT."""
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")
        if not payload.operator_confirmed or payload.auto_proceed:
            raise HTTPException(
                403, "Explicit operator confirmation is required; automatic authorization is unavailable"
            )
        target = owned(db, Target, session.target_id, user)
        if payload.target_id != target.id or payload.target_url != session.target_url:
            raise HTTPException(422, "Exploit request must match the session target and URL")
        if owned(db, Project, target.project_id, user).archived:
            raise HTTPException(409, "Project is archived")
        if not target.authorized_by or target.verification_status not in {
            "verified_lab",
            "operator_authorized",
        }:
            raise HTTPException(403, "Target is no longer authorized")
        if target.scope_version != session.scope_version or target.url != session.target_url:
            raise HTTPException(409, "Scope changed; review current authorization")
        try:
            validate_execution_scope(
                target.scope, target.url, owned=target.verification_status == "operator_authorized"
            )
        except (PolicyError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from None
        # The current scope schema permits diagnostics only (intrusive=False) and
        # has no immutable ALLOW_ACTIVE_EXPLOIT authorization contract.
        reason = "Approved scope does not permit active exploits; ALLOW_ACTIVE_EXPLOIT authorization is unavailable"
        audit(
            db,
            user.organization_id,
            user.id,
            "exploit.gate_rejected",
            target.id,
            {"session_id": session.id, "exploit_type": payload.exploit_type, "reason": reason},
        )
        db.commit()
        raise HTTPException(403, reason)

    @app.post("/api/v1/interactive/sessions/{session_id}/resize")
    def resize_interactive_session(session_id: str, payload: SessionResizeInput, user: Actor):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")
        session.resize(payload.cols, payload.rows)
        return {"status": "ok"}

    @app.post("/api/v1/interactive/sessions/{session_id}/terminate")
    def terminate_interactive_session(session_id: str, db: DB, user: Actor):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session:
            raise HTTPException(404, "Interactive session not found")
        session.terminate(reason=f"operator_terminated_by_{user.id}")
        audit(
            db,
            user.organization_id,
            user.id,
            "session.terminated",
            session.target_id,
            {"session_id": session.id, "flight_log_count": len(session.flight_log)},
        )
        db.commit()
        return {"status": "terminated"}

    @app.get("/api/v1/interactive/sessions/{session_id}/asciinema")
    def export_interactive_session_asciinema(session_id: str, user: Actor):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session:
            raise HTTPException(404, "Interactive session not found")
        cast_data = session.export_asciinema(title=f"SHARAY Operator Session {session.id}")
        return Response(content=cast_data, media_type="application/x-asciicast")

    @app.get("/api/v1/interactive/sessions/{session_id}/collaborate/operators")
    def get_session_operators(session_id: str, user: Actor):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")
        if not session.coordinator:
            return {"primary_controller_id": session.created_by, "operators": []}
        return {
            "primary_controller_id": session.coordinator.primary_controller_id,
            "operators": [
                {
                    "operator_id": op.operator_id,
                    "username": op.username,
                    "role": op.role,
                    "color_hex": op.color_hex,
                    "last_seen": op.last_seen,
                    "is_active": op.is_active,
                }
                for op in session.coordinator.operators.values()
            ],
            "handoff_count": len(session.coordinator.handoff_ledger),
        }

    @app.post("/api/v1/interactive/sessions/{session_id}/collaborate/join")
    def join_session_collaboration(session_id: str, payload: SessionCollaborateJoinInput, user: Actor):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")
        if not session.coordinator:
            session.coordinator = MultiOperatorSessionCoordinator(session.id, session.target_url)
        presence = session.coordinator.join_session(
            operator_id=user.id,
            username=user.username,
            as_primary=payload.as_primary,
            color_hex=payload.color_hex,
        )
        return {
            "status": "joined",
            "operator_id": presence.operator_id,
            "role": presence.role,
            "primary_controller_id": session.coordinator.primary_controller_id,
        }

    @app.post("/api/v1/interactive/sessions/{session_id}/collaborate/leave")
    def leave_session_collaboration(session_id: str, user: Actor):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")
        if session.coordinator:
            session.coordinator.leave_session(user.id)
        return {"status": "left"}

    @app.post("/api/v1/interactive/sessions/{session_id}/collaborate/transfer")
    def transfer_session_control(session_id: str, payload: SessionCollaborateTransferInput, user: Actor):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")
        if not session.coordinator:
            raise HTTPException(400, "Session collaboration coordinator not initialized")
        success = session.coordinator.transfer_control(
            current_controller_id=user.id,
            target_operator_id=payload.target_operator_id,
            reason=payload.reason,
        )
        if not success:
            raise HTTPException(
                403, "Transfer rejected: caller is not the primary controller or target is inactive"
            )
        return {
            "status": "transferred",
            "primary_controller_id": session.coordinator.primary_controller_id,
        }

    @app.post("/api/v1/interactive/sessions/{session_id}/collaborate/takeover")
    def takeover_session_control(session_id: str, payload: SessionCollaborateTakeoverInput, user: Actor):
        require_role(user, *CONTROL_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")
        if not session.coordinator:
            session.coordinator = MultiOperatorSessionCoordinator(session.id, session.target_url)
        session.coordinator.join_session(user.id, user.username, as_primary=False)
        success = session.coordinator.preempt_takeover(
            requesting_operator_id=user.id,
            justification=payload.justification,
            is_lead=True,
        )
        if not success:
            raise HTTPException(403, "Preemptive takeover failed")
        return {
            "status": "preempted",
            "primary_controller_id": session.coordinator.primary_controller_id,
        }

    @app.post("/api/v1/interactive/sessions/{session_id}/copilot")
    def copilot_autocomplete_and_suggestions(session_id: str, payload: SessionCopilotInput, user: Actor):
        require_role(user, *SCAN_ROLES)
        session = terminal_manager.get_session(session_id, user.organization_id)
        if not session or not session.is_alive():
            raise HTTPException(404, "Interactive session not found or has terminated")
        completions = []
        if payload.partial_cmd is not None:
            completions = session.copilot.get_completions(
                payload.partial_cmd, target_origin=session.target_url
            )
        suggestion = None
        if payload.last_output:
            suggestion = session.copilot.get_copilot_suggestion(
                payload.last_output, detected_vuln_classes=payload.detected_vuln_classes
            )
        return {
            "completions": completions,
            "suggestion": suggestion,
        }

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

    @app.get("/api/v1/assessments/{assessment_id}/topology-3d")
    def get_assessment_topology_3d(assessment_id: str, db: DB, user: Actor):
        require_role(user, *SCAN_ROLES)
        assessment = owned(db, Assessment, assessment_id, user)
        target = owned(db, Target, assessment.target_id, user)
        findings_query = select(Finding).where(Finding.target_id == target.id)
        findings_list = list(db.scalars(findings_query))

        graph = WebGLForceGraph3D()
        t_node = graph.add_node(
            target.id,
            target.url,
            "target",
            Vector3D(0.0, 0.0, 0.0),
        )
        gw_node = graph.add_node(
            f"gw-{target.id}",
            "Entry Gateway",
            "entrypoint",
            Vector3D(0.0, 50.0, 0.0),
        )
        graph.add_edge(gw_node.id, t_node.id)

        for idx, f in enumerate(findings_list):
            is_critical = f.severity in {"CRITICAL", "HIGH"}
            f_node = graph.add_node(
                f.id,
                f.title,
                "vulnerability",
                Vector3D((idx + 1) * 20.0, (idx % 3) * 15.0, (idx % 2) * 10.0),
                is_chokepoint=is_critical,
            )
            graph.add_edge(gw_node.id, f_node.id, is_min_cut=is_critical)
            graph.add_edge(f_node.id, t_node.id)

        graph.step_simulation(dt=0.2)
        return graph.export_webgl_payload()

    @app.get("/api/v1/findings/virtualized")
    def get_findings_virtualized(
        db: DB,
        user: Actor,
        scroll_top: int = Query(0, ge=0),
        container_height: int = Query(400, ge=50, le=2000),
        row_height: int = Query(40, ge=10, le=200),
        search: str = Query(""),
        severity: str | None = Query(None),
        sort_by: str = Query("id"),
        descending: bool = Query(False),
    ):
        require_role(user, *SCAN_ROLES)
        query = select(Finding).where(Finding.organization_id == user.organization_id)
        raw_findings = [finding_view(db, f) for f in db.scalars(query)]
        sorted_filtered = VirtualizedTableEngine.filter_and_sort(
            raw_findings,
            search_query=search,
            severity_filter=severity,
            sort_by=sort_by,
            descending=descending,
        )
        window = VirtualizedTableEngine.calculate_window(
            sorted_filtered,
            scroll_top_px=scroll_top,
            container_height_px=container_height,
            row_height_px=row_height,
        )
        return dataclasses.asdict(window)

    @app.post("/api/v1/findings/bulk-triage")
    def bulk_triage_findings(payload: BulkTriageInput, db: DB, user: Actor):
        require_role(user, *SCAN_ROLES)
        query = select(Finding).where(
            Finding.id.in_(payload.finding_ids),
            Finding.organization_id == user.organization_id,
        )
        matched_findings = list(db.scalars(query))
        if not matched_findings:
            raise HTTPException(404, "No matching findings found")

        t_status = getattr(TriageStatus, payload.status, TriageStatus.CONFIRMED)
        triaged_count = bulk_triage_engine.bulk_triage(
            [f.id for f in matched_findings],
            t_status,
            actor=user.username,
            justification=payload.justification,
        )

        from aegis.models import FindingHistory

        for f in matched_findings:
            f.status = payload.status.lower()
            db.add(
                FindingHistory(finding_id=f.id, status=f.status, actor=user.id, reason=payload.justification)
            )
            audit(db, user.organization_id, user.id, "finding.bulk_triaged", f.id, {"status": f.status})

        db.commit()
        return {
            "status": "ok",
            "updated_count": triaged_count,
            "new_status": payload.status,
        }

    @app.post("/api/v1/views/saved")
    def save_custom_view(payload: SavedViewInput, user: Actor):
        require_role(user, *SCAN_ROLES)
        bulk_triage_engine.save_view(payload.name, payload.filters, actor=user.username)
        return {"status": "saved", "name": payload.name}

    @app.get("/api/v1/views/saved/{name}")
    def get_custom_view(name: str, user: Actor):
        require_role(user, *SCAN_ROLES)
        view = bulk_triage_engine.get_view(name)
        if not view:
            raise HTTPException(404, f"Saved view '{name}' not found")
        return view

    @app.get("/api/v1/integrations")
    def integrations(user: Actor):
        supervisor = getattr(app.state, "supervisor", None)
        return {
            "items": active_integrations(),
            "worker": "ready" if supervisor and supervisor.alive() else "unavailable",
            "ai": {
                "status": "ready",
                "reason": "Adversarial reasoning & attack graph engine active",
                "provider": "switchable (Gemini / Claude / OpenAI)",
            },
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

    @app.post("/api/v1/source-analysis")
    def source_analysis(payload: SourceAnalysisInput, db: DB, user: Actor):
        require_role(user, *SCAN_ROLES)
        from services.source_analysis_worker.assess import (
            SourceAnalysisError,
            analyze_source_tree,
            resolve_within,
        )

        try:
            root = resolve_within(payload.path, settings.source_root)
        except SourceAnalysisError as exc:
            raise HTTPException(400, str(exc)) from None
        result = analyze_source_tree(root)
        audit(
            db,
            user.organization_id,
            user.id,
            "source_analysis.run",
            str(root),
            {"findings": len(result["findings"]), "packages": len(result["packages"])},
        )
        db.commit()
        return {**result, "root": str(root)}

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

    @app.post("/api/v1/audit/notarize")
    def notarize_audit_chain(db: DB, user: Actor):
        from aegis.audit import AuditNotaryService

        require_role(user, *CONTROL_ROLES)
        notary = AuditNotaryService()
        receipt = notary.notarize_chain(db, user.organization_id)
        if receipt is None:
            raise HTTPException(404, "No audit events found to notarize")
        return receipt

    @app.get("/api/v1/audit/export")
    def export_audit_ledger(db: DB, user: Actor):
        from aegis.audit import SignedAuditLedgerExporter

        require_role(user, *CONTROL_ROLES)
        events_list = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.organization_id == user.organization_id)
            .order_by(AuditEvent.id.asc())
        ).all()

        exporter = SignedAuditLedgerExporter()
        for e in events_list:
            exporter.append_event(
                entry_id=str(e.id),
                actor=e.actor,
                action=e.action,
                target=e.resource_id,
                details=e.detail if isinstance(e.detail, dict) else {},
                now=e.created_at,
            )
        return exporter.generate_signed_export()

    @app.post("/api/v1/lifecycle/retention")
    def enforce_retention(db: DB, user: Actor, assessment_days: int = 90, evidence_days: int = 14):
        from aegis.lifecycle import DataLifecycleManager, RetentionPolicy
        from aegis.models import FindingEvidence, Observation

        require_role(user, *CONTROL_ROLES)
        policy = RetentionPolicy(
            assessment_retention_days=assessment_days,
            raw_evidence_retention_days=evidence_days,
        )
        asmt_rows = db.scalars(
            select(Assessment).where(Assessment.organization_id == user.organization_id)
        ).all()
        obs_rows = db.scalars(
            select(Observation).where(Observation.organization_id == user.organization_id)
        ).all()
        fe_rows = db.scalars(
            select(FindingEvidence)
            .join(Assessment, Assessment.id == FindingEvidence.assessment_id)
            .where(Assessment.organization_id == user.organization_id)
        ).all()

        asmts_data = [{"id": a.id, "created_at": a.created_at} for a in asmt_rows]
        obs_data = [
            {
                "id": o.id,
                "assessment_id": o.assessment_id,
                "observed_at": o.observed_at,
                "evidence_hash": o.evidence_hash,
            }
            for o in obs_rows
        ]
        fe_data = [
            {"id": f.id, "assessment_id": f.assessment_id, "evidence_hash": f.evidence_hash} for f in fe_rows
        ]

        manager = DataLifecycleManager()
        report, _ = manager.enforce_retention(
            assessments=asmts_data,
            observations=obs_data,
            finding_evidence=fe_data,
            policy=policy,
            organization_id=user.organization_id,
        )
        return report.to_dict()

    def report_data(assessment_id: str, db: Session, user: User) -> dict:
        row = owned(db, Assessment, assessment_id, user)
        if row.status not in TERMINAL:
            raise HTTPException(409, "Wait for the assessment to stop before generating a report")
        detail = assessment(assessment_id, db, user)
        project = owned(db, Project, row.project_id, user)
        target = owned(db, Target, row.target_id, user)
        snapshot = row.scope_snapshot
        if not isinstance(snapshot, dict) or not snapshot.get("target_url"):
            raise HTTPException(409, "Historical target scope is unavailable")
        historical_target = {
            "id": target.id,
            "project_id": row.project_id,
            "url": snapshot["target_url"],
            "scope": {key: value for key, value in snapshot.items() if key in ScopePolicy.model_fields},
            "scope_version": row.scope_version,
            "verification_status": snapshot.get("verification_status", "not_recorded"),
            "authorized_by": snapshot.get("authorized_by"),
            "approved_at": timestamp(snapshot.get("approved_at")),
            "created_at": timestamp(target.created_at),
        }
        return {
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

    @app.get("/api/v1/reports/{assessment_id}")
    def report(assessment_id: str, db: DB, user: Actor, format: str = "html"):
        data = report_data(assessment_id, db, user)
        body, content_type = render_report(data, format)
        extension = "md" if format == "markdown" else ("zip" if format in {"bundle", "zip"} else format)
        return Response(
            body,
            media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="sharay-{assessment_id}.{extension}"'},
        )

    @app.get("/api/v1/assessments/{assessment_id}/bundle")
    def assessment_bundle(assessment_id: str, db: DB, user: Actor):
        from packages.reporting.bundle import EvidenceBundleBuilder

        data = report_data(assessment_id, db, user)
        bundle_bytes = EvidenceBundleBuilder.build_bundle(assessment_id, data)
        return Response(
            bundle_bytes,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="sharay-{assessment_id}-evidence.zip"'},
        )

    @app.get("/api/v1/assessments/{assessment_id}/executive-dashboard")
    def executive_dashboard(assessment_id: str, db: DB, user: Actor):
        from packages.reporting.trends import ExecutiveDashboardGenerator, FindingRecord

        data = report_data(assessment_id, db, user)
        findings = [FindingRecord.from_dict(f) for f in data.get("findings", [])]
        obs = data.get("observations", [])
        target_name = data.get("target", {}).get("url") or "Target"
        return ExecutiveDashboardGenerator.generate_dashboard(
            findings=findings,
            total_endpoints_discovered=max(len(obs), 1),
            total_endpoints_tested=max(len(obs), 1),
            target_name=target_name,
        )

    @app.get("/api/v1/assessments/{assessment_id}/trends")
    def assessment_trends(assessment_id: str, db: DB, user: Actor, prev_id: str | None = None):
        from packages.reporting.trends import AssessmentTrendEngine, FindingRecord

        curr_data = report_data(assessment_id, db, user)
        curr_findings = [FindingRecord.from_dict(f) for f in curr_data.get("findings", [])]

        prev_findings: list[FindingRecord] = []
        prior_id = prev_id
        if not prior_id:
            curr_row = owned(db, Assessment, assessment_id, user)
            prior = (
                db.query(Assessment)
                .filter(
                    Assessment.target_id == curr_row.target_id,
                    Assessment.id != curr_row.id,
                    Assessment.status.in_(TERMINAL),
                    Assessment.created_at < curr_row.created_at,
                )
                .order_by(Assessment.created_at.desc())
                .first()
            )
            if prior:
                prior_id = prior.id

        if prior_id:
            try:
                prev_data = report_data(prior_id, db, user)
                prev_findings = [FindingRecord.from_dict(f) for f in prev_data.get("findings", [])]
            except Exception:
                prev_findings = []

        diff = AssessmentTrendEngine.compute_differential(
            prev_assessment_id=prior_id or "none",
            prev_findings=prev_findings,
            curr_assessment_id=assessment_id,
            curr_findings=curr_findings,
        )
        return diff.to_dict()

    @app.post("/api/v1/findings/{finding_id}/ticket")
    def push_ticket(
        finding_id: str,
        db: DB,
        user: Actor,
        platform: str = "github",
        project_key: str = "SEC",
    ):
        from packages.reporting.integrations import TicketingPushEngine
        from packages.reporting.trends import FindingRecord

        finding_row = owned(db, Finding, finding_id, user)
        f_dict = finding_view(db, finding_row)
        finding_record = FindingRecord.from_dict(f_dict)

        if not hasattr(app.state, "ticketing_engine") or app.state.ticketing_engine is None:
            app.state.ticketing_engine = TicketingPushEngine()

        result = app.state.ticketing_engine.push_finding_ticket(
            finding=finding_record,
            platform=platform,
            project_key=project_key,
        )
        return result

    @app.post("/api/v1/reports/{assessment_id}", status_code=202)
    def submit_report_job(assessment_id: str, db: DB, user: Actor, format: str = "pdf"):
        data = report_data(assessment_id, db, user)
        mgr = report_manager()
        try:
            job = mgr.submit_render_job(assessment_id, format, data)
        except RuntimeError as exc:
            raise HTTPException(503, "Report renderer is unavailable") from exc
        import json as _json

        return Response(
            _json.dumps(job.to_dict()),
            status_code=202,
            media_type="application/json",
            headers={"Location": f"/api/v1/reports/jobs/{job.job_id}"},
        )

    @app.get("/api/v1/reports/jobs/{job_id}")
    def get_report_job(job_id: str, db: DB, user: Actor):
        mgr = report_manager()
        job = mgr.get_job(job_id)
        if not job:
            raise HTTPException(404, "Report rendering job not found")
        owned(db, Assessment, job.assessment_id, user)
        return job.to_dict()

    @app.get("/api/v1/reports/jobs/{job_id}/download")
    def download_report_job(job_id: str, db: DB, user: Actor):
        mgr = report_manager()
        job = mgr.get_job(job_id)
        if not job:
            raise HTTPException(404, "Report rendering job not found")
        owned(db, Assessment, job.assessment_id, user)
        if job.status != "completed" or not job.output_path:
            raise HTTPException(409, f"Report is not ready (status: {job.status})")
        try:
            content = Path(job.output_path).read_bytes()
        except OSError as exc:
            raise HTTPException(409, "Report artifact is unavailable; request regeneration") from exc
        if not job.sha256_hash or hashlib.sha256(content).hexdigest() != job.sha256_hash:
            raise HTTPException(409, "Report artifact failed its SHA-256 integrity check")
        ext = "md" if job.format == "markdown" else job.format
        return Response(
            content,
            media_type=job.content_type or "application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="sharay-{job.assessment_id}.{ext}"',
                "X-Report-SHA256": job.sha256_hash or "",
            },
        )

    @app.post("/api/v1/workspace/probe")
    def workspace_probe(data: WorkspaceProbeInput, db: DB, user: Actor):
        require_role(user, *SCAN_ROLES)
        target = owned(db, Target, data.target_id, user)
        if owned(db, Project, target.project_id, user).archived:
            raise HTTPException(409, "Project is archived")
        if (
            target.verification_status not in {"verified_lab", "operator_authorized"}
            or not target.authorized_by
        ):
            raise HTTPException(403, "Target must be approved by operator before interactive probing")

        workspace = InteractiveWorkspace(default_timeout=data.timeout)
        try:
            result = workspace.execute_probe(
                scope=target.scope,
                target_url=data.url,
                method=data.method,
                headers=data.headers,
                query_params=data.query_params,
                body=data.body,
                output_prefix=data.output_prefix,
                output_suffix=data.output_suffix,
            )
        except PolicyError as exc:
            raise HTTPException(422, str(exc)) from None
        except Exception as exc:
            raise HTTPException(502, f"Target probe failed: {exc}") from None

        audit(
            db,
            user.organization_id,
            user.id,
            "workspace.probe_executed",
            target.id,
            {
                "url": result.target_url,
                "method": result.method,
                "status_code": result.status_code,
                "duration_ms": result.duration_ms,
                "fingerprint": result.fingerprint,
            },
        )
        return result.to_dict()

    def ai_provider_state():
        from services.ai_analysis_worker.providers import build, config_from_environment, secret

        state = {
            "active_provider": "none",
            "model": "",
            "api_key_configured": False,
            "share_assessment_data": False,
            "supported_providers": ["google", "anthropic", "openai"],
            "status": "unavailable",
            "reason": "AI provider configuration could not be loaded.",
        }
        try:
            cfg = config_from_environment()
        except Exception:
            return state, None
        state.update(
            active_provider=cfg.provider, model=cfg.model, share_assessment_data=cfg.share_assessment_data
        )
        if cfg.provider == "none":
            state.update(
                status="available",
                reason="No AI provider is configured; deterministic analysis is available.",
            )
            return state, None
        try:
            secret(cfg)
        except Exception:
            state["reason"] = "AI provider credential is unavailable or invalid."
            return state, None
        state["api_key_configured"] = True
        if not cfg.share_assessment_data:
            state["reason"] = "Assessment data sharing is disabled."
            return state, None
        try:
            provider = build(cfg)
        except Exception:
            state["reason"] = "AI provider could not be initialized."
            return state, None
        state.update(
            status="ready", reason="Provider configuration is valid; connectivity has not been checked."
        )
        return state, provider

    def verified_ai_findings(findings):
        from aegis.worker import _finding_status

        verified = []
        for finding in findings:
            status = finding.get("status")
            if not isinstance(status, str) or status not in {
                "confirmed",
                "reopened",
                "accepted_risk",
                "remediation_in_progress",
            }:
                continue
            evidence = finding.get("evidence", [])
            snapshot = evidence[-1].get("data") if evidence and isinstance(evidence[-1], dict) else None
            if isinstance(snapshot, dict) and _finding_status(snapshot) == "confirmed":
                verified.append(finding)
        return verified

    @app.get("/api/v1/ai/status")
    def ai_status(user: Actor):
        state, _provider = ai_provider_state()
        return state

    @app.get("/api/v1/ai/investigations/{assessment_id}")
    def get_ai_investigation(assessment_id: str, db: DB, user: Actor):
        row = owned(db, Assessment, assessment_id, user)
        asmt_data = assessment(assessment_id, db, user)
        observations = asmt_data.get("observations", [])
        findings = verified_ai_findings(asmt_data.get("findings", []))
        target_url = row.scope_snapshot.get("target_url", "")

        from services.ai_analysis_worker.reasoning import (
            AttackGraph,
            generate_defensive_root_cause_analysis,
        )

        graph = AttackGraph()
        raw_obs: list[dict[str, Any]] = [
            d
            for o in observations
            if isinstance(o, dict) and isinstance(d := o.get("data", o.get("facts", o)), dict)
        ]
        graph.ingest(raw_obs, findings)

        analysis = generate_defensive_root_cause_analysis(
            graph=graph,
            findings=findings,
            observations=raw_obs,
            target_url=target_url,
            provider=None,
        )
        return {
            "assessment_id": assessment_id,
            "created_at": timestamp(row.created_at),
            "excluded_unverified_findings": len(asmt_data.get("findings", [])) - len(findings),
            **analysis,
        }

    @app.post("/api/v1/ai/investigate/{assessment_id}")
    def run_ai_investigation(assessment_id: str, db: DB, user: Actor):
        from types import SimpleNamespace

        require_role(user, *SCAN_ROLES)
        row = owned(db, Assessment, assessment_id, user)
        asmt_data = assessment(assessment_id, db, user)
        observations = asmt_data.get("observations", [])
        findings = verified_ai_findings(asmt_data.get("findings", []))
        target_url = row.scope_snapshot.get("target_url", "")

        from services.ai_analysis_worker.reasoning import (
            AttackGraph,
            generate_defensive_root_cause_analysis,
        )

        provider_state, active_provider = ai_provider_state()
        provider_failed = False
        if active_provider is not None:
            delegate = active_provider

            def propose(prompt):
                nonlocal provider_failed
                try:
                    response = delegate.propose(prompt)
                    if not isinstance(response, bytes) or not response.strip():
                        raise ValueError("AI provider returned no usable text")
                    return response
                except Exception:
                    provider_failed = True
                    raise

            active_provider = SimpleNamespace(name=delegate.name, propose=propose)

        graph = AttackGraph()
        raw_obs: list[dict[str, Any]] = [
            d
            for o in observations
            if isinstance(o, dict) and isinstance(d := o.get("data", o.get("facts", o)), dict)
        ]
        graph.ingest(raw_obs, findings)

        analysis = generate_defensive_root_cause_analysis(
            graph=graph,
            findings=findings,
            observations=raw_obs,
            target_url=target_url,
            provider=active_provider,
        )
        if provider_failed:
            active_provider = None
            provider_state.update(
                status="failed", reason="AI provider request failed; deterministic analysis was returned."
            )

        audit(
            db,
            user.organization_id,
            user.id,
            "ai.investigation_executed",
            assessment_id,
            {
                "target_url": target_url,
                "nodes_count": len(graph.nodes),
                "edges_count": len(graph.edges),
                "posture_score": analysis.get("posture_score"),
                "provider": active_provider.name if active_provider else "deterministic_engine",
                "provider_status": provider_state["status"],
            },
        )

        return {
            "assessment_id": assessment_id,
            "created_at": timestamp(row.created_at),
            "excluded_unverified_findings": len(asmt_data.get("findings", [])) - len(findings),
            "provider_status": provider_state["status"],
            "provider_reason": provider_state["reason"],
            **analysis,
        }

    @app.get("/api/v1/onboarding/state")
    def get_onboarding_state(user: Actor):
        from aegis.onboarding import get_onboarding_wizard

        wizard = get_onboarding_wizard(user.organization_id)
        state = wizard.state
        return {
            "current_step": state.current_step.value,
            "owner_username": state.owner_username,
            "mfa_enrolled": state.mfa_enrolled,
            "container_engine": state.container_engine,
            "container_verified": state.container_verified,
            "egress_verified": state.egress_verified,
            "seed_assessment_id": state.seed_assessment_id,
            "completed_at": state.completed_at,
            "step_history": state.step_history,
        }

    @app.post("/api/v1/onboarding/advance")
    def advance_onboarding_state(payload: OnboardingAdvanceInput, user: Actor, db: Session = Depends(get_db)):
        require_role(user, *CONTROL_ROLES)
        from aegis.onboarding import OnboardingStep, get_onboarding_wizard

        wizard = get_onboarding_wizard(user.organization_id)
        try:
            target_step = OnboardingStep(payload.step)
        except ValueError:
            raise HTTPException(400, f"Invalid onboarding step: {payload.step}")
        ok, msg = wizard.advance_step(target_step, payload.data)
        if not ok:
            raise HTTPException(400, msg)
        audit(
            db,
            user.organization_id,
            user.id,
            "onboarding.step_advanced",
            payload.step,
            {"new_step": wizard.state.current_step.value, "message": msg},
        )
        db.commit()
        return {
            "success": True,
            "message": msg,
            "current_step": wizard.state.current_step.value,
        }

    @app.post("/api/v1/system/update/check")
    def check_system_update(payload: UpdateCheckInput, user: Actor):
        require_role(user, *SCAN_ROLES)
        from aegis.onboarding import ZeroTelemetryUpdateManager

        mgr = ZeroTelemetryUpdateManager()
        manifest = mgr.check_for_update(payload.manifest_json)
        return {
            "has_update": manifest is not None,
            "manifest": (
                {
                    "version": manifest.version,
                    "release_date": manifest.release_date,
                    "sha256_hash": manifest.sha256_hash,
                    "binary_url": manifest.binary_url,
                    "mandatory_update": manifest.mandatory_update,
                    "signature": manifest.signature,
                }
                if manifest
                else None
            ),
        }

    @app.post("/api/v1/system/update/apply")
    def apply_system_update(payload: UpdateApplyInput, user: Actor, db: Session = Depends(get_db)):
        require_role(user, *CONTROL_ROLES)
        from aegis.onboarding import ReleaseManifest, ZeroTelemetryUpdateManager

        mgr = ZeroTelemetryUpdateManager()
        try:
            binary_bytes = base64.b64decode(payload.binary_bytes_b64)
            manifest = ReleaseManifest(
                version=payload.manifest["version"],
                release_date=payload.manifest["release_date"],
                sha256_hash=payload.manifest["sha256_hash"],
                binary_url=payload.manifest["binary_url"],
                mandatory_update=payload.manifest.get("mandatory_update", False),
                signature=payload.manifest["signature"],
            )
        except Exception as exc:
            raise HTTPException(400, f"Invalid update payload: {exc}")

        ok, msg = mgr.apply_update_staged(binary_bytes, manifest, payload.target_install_path)
        if not ok:
            raise HTTPException(400, msg)
        audit(
            db,
            user.organization_id,
            user.id,
            "system.update_applied",
            manifest.version,
            {"target_path": payload.target_install_path, "message": msg},
        )
        db.commit()
        return {"success": True, "message": msg, "version": manifest.version}

    output = ROOT / "apps" / "web" / "out"
    if output.is_dir():
        app.mount("/", StaticFiles(directory=output, html=True), name="desktop_ui")
    return app
