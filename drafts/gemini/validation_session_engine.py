"""Validation, session governance, impact verification and cleanup engine.

Extends SHARAY's detection pipeline across the 8-stage authorized assessment workflow:
Detection -> Technical Validation -> Authorized Validation -> Interactive Session ->
Post-Validation Boundary Assessment -> Impact Verification -> Reporting -> Cleanup.

Safety invariants:
- No weaponized payloads, exploit strings, covert persistence, credential harvesting,
  destructive actions or unauthorized lateral movement.
- Every validation action and session interaction is checked at execution time against
  the target's `ScopePolicy`, `scope_version`, time window and explicit operator approval.
- Impact verification explicitly separates `theoretical_impact`, `observed_impact` and
  `not_yet_tested_impact`; initial confirmation never assumes maximum severity.
- All retained text passes through `packages.reporting.redact`.
"""

import hashlib
import json
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from packages.reporting import redact
from packages.security_policies import PolicyError, ScopePolicy, check_url


def _strict_bool(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("Permission and safety flags must be actual booleans.")
    return value


RequiredTrue = Annotated[Literal[True], BeforeValidator(_strict_bool)]
ForbiddenFalse = Annotated[Literal[False], BeforeValidator(_strict_bool)]
Identifier = Annotated[
    str, Field(strict=True, min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
]
Digest = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]
SeverityLevel = Literal["critical", "high", "medium", "low", "info", "unknown"]
ConfirmationState = Literal["confirmed", "suspected", "refuted", "inconclusive"]
SelectionMode = Literal["manual", "ai_assisted"]
SessionState = Literal["requested", "approved", "active", "terminated", "expired", "revoked"]
CleanupState = Literal["pending_cleanup", "cleanup_verified", "cleanup_failed_operator_action_required"]
VulnerabilityClass = Literal[
    "sql_injection",
    "xss",
    "ssrf",
    "xxe",
    "command_injection",
    "auth_bypass",
    "access_control",
    "server_side",
    "client_side",
    "api_vulnerability",
]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ValidationTechnique(StrictContract):
    """An approved, non-destructive verification method registered in the platform catalog."""

    technique_id: Identifier
    vulnerability_class: VulnerabilityClass
    display_name: str = Field(strict=True, min_length=1, max_length=160)
    cwe_ids: tuple[str, ...]
    adapter_id: Literal["safe_http", "nmap", "zap", "nuclei", "semgrep", "gitleaks", "metasploit"]
    requires_operator_approval: RequiredTrue = True
    non_destructive: RequiredTrue = True
    preconditions: tuple[str, ...]
    verification_mechanism: str = Field(strict=True, min_length=1, max_length=300)


VALIDATION_CATALOG: dict[str, ValidationTechnique] = {
    "val.sqli.boolean_state_comparison": ValidationTechnique(
        technique_id="val.sqli.boolean_state_comparison",
        vulnerability_class="sql_injection",
        display_name="Read-only parameter state & error-envelope comparison",
        cwe_ids=("89", "CWE-89"),
        adapter_id="zap",
        preconditions=("http_endpoint_in_scope", "query_or_body_parameter_identified"),
        verification_mechanism="Compare deterministic response status/structure between baseline and benign syntax-check inputs without modifying rows.",
    ),
    "val.xss.context_reflection_check": ValidationTechnique(
        technique_id="val.xss.context_reflection_check",
        vulnerability_class="xss",
        display_name="Canary token output-encoding and CSP context verification",
        cwe_ids=("79", "CWE-79"),
        adapter_id="zap",
        preconditions=("http_endpoint_in_scope", "reflected_or_stored_sink_identified"),
        verification_mechanism="Verify whether an alphanumeric canary and benign delimiter characters are reflected unencoded in HTML/attribute/script context.",
    ),
    "val.ssrf.loopback_canary_check": ValidationTechnique(
        technique_id="val.ssrf.loopback_canary_check",
        vulnerability_class="ssrf",
        display_name="Scoped loopback listener canary verification",
        cwe_ids=("918", "CWE-918"),
        adapter_id="nuclei",
        preconditions=("url_parameter_identified", "loopback_canary_listener_active"),
        verification_mechanism="Verify whether the target initiates a request to an authorized local loopback canary endpoint within the engagement scope.",
    ),
    "val.xxe.entity_resolution_check": ValidationTechnique(
        technique_id="val.xxe.entity_resolution_check",
        vulnerability_class="xxe",
        display_name="Internal parameter-entity parser configuration check",
        cwe_ids=("611", "CWE-611"),
        adapter_id="nuclei",
        preconditions=("xml_content_type_accepted",),
        verification_mechanism="Check whether the XML parser resolves a benign local entity definition without reading sensitive host files.",
    ),
    "val.cmdi.argument_boundary_check": ValidationTechnique(
        technique_id="val.cmdi.argument_boundary_check",
        vulnerability_class="command_injection",
        display_name="Non-destructive argument-quoting and status-code boundary check",
        cwe_ids=("77", "78", "CWE-77", "CWE-78"),
        adapter_id="nuclei",
        preconditions=("command_backed_parameter_identified",),
        verification_mechanism="Compare command-argument validation errors against benign metacharacter rejection without executing shell commands.",
    ),
    "val.auth.session_token_state_check": ValidationTechnique(
        technique_id="val.auth.session_token_state_check",
        vulnerability_class="auth_bypass",
        display_name="Unauthenticated vs authenticated state-transition verification",
        cwe_ids=("287", "306", "CWE-287", "CWE-306"),
        adapter_id="safe_http",
        preconditions=("protected_route_identified",),
        verification_mechanism="Verify whether a protected endpoint returns authorized state without a valid session credential.",
    ),
    "val.access.principal_boundary_check": ValidationTechnique(
        technique_id="val.access.principal_boundary_check",
        vulnerability_class="access_control",
        display_name="Cross-principal resource authorization boundary verification",
        cwe_ids=("284", "639", "862", "CWE-284", "CWE-639", "CWE-862"),
        adapter_id="safe_http",
        preconditions=("two_authorized_test_principals_configured",),
        verification_mechanism="Verify whether test principal A can read test principal B's synthetic laboratory resource.",
    ),
    "val.server.auxiliary_service_verification": ValidationTechnique(
        technique_id="val.server.auxiliary_service_verification",
        vulnerability_class="server_side",
        display_name="Approved Metasploit auxiliary service banner & configuration verification",
        cwe_ids=("16", "200", "CWE-16", "CWE-200"),
        adapter_id="metasploit",
        preconditions=("service_port_in_scope", "approved_auxiliary_module_ref"),
        verification_mechanism="Run an operator-approved non-intrusive Metasploit auxiliary scanner module to confirm service version and configuration state.",
    ),
    "val.client.framing_and_cookie_posture": ValidationTechnique(
        technique_id="val.client.framing_and_cookie_posture",
        vulnerability_class="client_side",
        display_name="Browser header & Set-Cookie attribute semantics verification",
        cwe_ids=("1021", "1004", "693", "CWE-1021", "CWE-1004", "CWE-693"),
        adapter_id="safe_http",
        preconditions=("http_endpoint_in_scope",),
        verification_mechanism="Verify effective CSP frame-ancestors, X-Frame-Options, X-Content-Type-Options nosniff, and RFC 6265bis HttpOnly/Secure flags.",
    ),
    "val.api.schema_and_method_boundary": ValidationTechnique(
        technique_id="val.api.schema_and_method_boundary",
        vulnerability_class="api_vulnerability",
        display_name="API method allowlist and mass-assignment schema verification",
        cwe_ids=("285", "915", "CWE-285", "CWE-915"),
        adapter_id="zap",
        preconditions=("api_endpoint_in_scope",),
        verification_mechanism="Verify whether undeclared fields or unpermitted HTTP methods are rejected by the API schema validator.",
    ),
}

_CATEGORY_TO_CLASS: dict[str, VulnerabilityClass] = {
    "sql_injection": "sql_injection",
    "sqli": "sql_injection",
    "xss": "xss",
    "cross_site_scripting": "xss",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "command_injection": "command_injection",
    "cmdi": "command_injection",
    "auth_bypass": "auth_bypass",
    "authentication": "auth_bypass",
    "access_control": "access_control",
    "idor": "access_control",
    "authorization": "access_control",
    "server_side": "server_side",
    "service_exposure": "server_side",
    "client_side": "client_side",
    "http_headers": "client_side",
    "missing_csp": "client_side",
    "missing_frame_policy": "client_side",
    "missing_nosniff": "client_side",
    "cookie_httponly": "client_side",
    "api_vulnerability": "api_vulnerability",
    "api": "api_vulnerability",
}


def _clean_text(value: str, what: str, limit: int = 300) -> str:
    if not isinstance(value, str) or not value.strip() or not value.isprintable():
        raise ValueError(f"{what} must be non-empty printable text.")
    cleaned = redact(value.strip())
    if len(cleaned) > limit:
        raise ValueError(f"{what} exceeds the {limit}-character limit.")
    return cleaned


def _canonical_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def correlate_finding(finding: dict[str, Any]) -> list[ValidationTechnique]:
    """Correlate a scanner/advisory finding with applicable non-destructive validation methods."""
    if not isinstance(finding, dict):
        raise ValueError("Finding must be a dictionary.")
    raw_cwe = str(finding.get("cwe_id") or "").strip()
    raw_category = str(finding.get("category") or finding.get("check_id") or "").strip().lower()
    vuln_class = _CATEGORY_TO_CLASS.get(raw_category)
    matched: list[ValidationTechnique] = []
    for technique in VALIDATION_CATALOG.values():
        if (raw_cwe and raw_cwe in technique.cwe_ids) or (
            vuln_class and technique.vulnerability_class == vuln_class
        ):
            matched.append(technique)
    return matched


class SelectedValidationPlan(StrictContract):
    finding_id: Identifier
    technique_id: Identifier
    vulnerability_class: VulnerabilityClass
    selection_mode: SelectionMode
    selected_by: Identifier
    operator_approval_ref: Identifier
    target_url: str = Field(strict=True, min_length=1, max_length=2048)
    expected_scope_version: int = Field(strict=True, ge=1)
    rationale: str = Field(strict=True, min_length=1, max_length=300)


def select_validation_method(
    finding: dict[str, Any],
    technique_id: str,
    *,
    selection_mode: SelectionMode,
    selected_by: str,
    operator_approval_ref: str,
    target_url: str,
    expected_scope_version: int,
    rationale: str,
) -> SelectedValidationPlan:
    """Select an approved validation method manually or with AI assistance (never bypassing approval)."""
    if technique_id not in VALIDATION_CATALOG:
        raise ValueError("Validation technique is not in the approved catalog.")
    applicable = {tech.technique_id for tech in correlate_finding(finding)}
    if applicable and technique_id not in applicable:
        raise ValueError("Selected validation technique does not match the finding's vulnerability class.")
    technique = VALIDATION_CATALOG[technique_id]
    finding_id = str(finding.get("id") or finding.get("fingerprint") or "")
    return SelectedValidationPlan(
        finding_id=finding_id,
        technique_id=technique.technique_id,
        vulnerability_class=technique.vulnerability_class,
        selection_mode=selection_mode,
        selected_by=selected_by,
        operator_approval_ref=operator_approval_ref,
        target_url=target_url,
        expected_scope_version=expected_scope_version,
        rationale=_clean_text(rationale, "Validation rationale", 300),
    )


class ValidationExecutionRecord(StrictContract):
    """Structured record of a controlled validation execution and its observed evidence."""

    finding_id: Identifier
    technique_id: Identifier
    vulnerability_class: VulnerabilityClass
    selection_mode: SelectionMode
    operator_approval_ref: Identifier
    target_url: str
    scope_version: int = Field(strict=True, ge=1)
    preconditions_met: tuple[str, ...]
    confirmation_state: ConfirmationState
    observed_response_summary: str = Field(strict=True, min_length=1, max_length=400)
    resulting_privilege_context: str = Field(strict=True, min_length=1, max_length=160)
    affected_resources: tuple[str, ...]
    executed_at: str
    evidence_hash: Digest
    non_destructive: RequiredTrue = True
    intrusive_payload_used: ForbiddenFalse = False


def execute_validation_step(
    plan: SelectedValidationPlan,
    scope: ScopePolicy | dict[str, Any],
    *,
    current_scope_version: int,
    preconditions_met: list[str],
    confirmation_state: ConfirmationState,
    observed_response_summary: str,
    resulting_privilege_context: str,
    affected_resources: list[str],
) -> ValidationExecutionRecord:
    """Validate scope, version and preconditions at execution time and capture tamper-evident evidence."""
    if current_scope_version != plan.expected_scope_version:
        raise PolicyError("Target scope version changed since validation approval; re-approval is required.")
    destination = check_url(scope, plan.target_url)
    technique = VALIDATION_CATALOG[plan.technique_id]
    cleaned_preconditions = tuple(_clean_text(p, "Precondition", 120) for p in preconditions_met)
    missing = set(technique.preconditions) - set(cleaned_preconditions)
    if missing and confirmation_state == "confirmed":
        raise ValueError(
            "A finding cannot be marked confirmed when required validation preconditions are unmet."
        )
    cleaned_summary = _clean_text(observed_response_summary, "Observed response summary", 400)
    cleaned_privilege = _clean_text(resulting_privilege_context, "Resulting privilege context", 160)
    cleaned_resources = tuple(_clean_text(r, "Affected resource", 200) for r in affected_resources)
    if confirmation_state == "confirmed" and not cleaned_resources:
        raise ValueError("Confirmed validation requires at least one konkret affected resource.")
    executed_at = datetime.now(UTC).isoformat(timespec="seconds")
    evidence_hash = _canonical_hash(
        {
            "finding_id": plan.finding_id,
            "technique_id": plan.technique_id,
            "target_url": destination.url,
            "scope_version": current_scope_version,
            "preconditions_met": list(cleaned_preconditions),
            "confirmation_state": confirmation_state,
            "observed_response_summary": cleaned_summary,
            "resulting_privilege_context": cleaned_privilege,
            "affected_resources": list(cleaned_resources),
            "executed_at": executed_at,
        }
    )
    return ValidationExecutionRecord(
        finding_id=plan.finding_id,
        technique_id=plan.technique_id,
        vulnerability_class=plan.vulnerability_class,
        selection_mode=plan.selection_mode,
        operator_approval_ref=plan.operator_approval_ref,
        target_url=destination.url,
        scope_version=current_scope_version,
        preconditions_met=cleaned_preconditions,
        confirmation_state=confirmation_state,
        observed_response_summary=cleaned_summary,
        resulting_privilege_context=cleaned_privilege,
        affected_resources=cleaned_resources,
        executed_at=executed_at,
        evidence_hash=evidence_hash,
    )


class BoundaryObservation(StrictContract):
    """Non-destructive post-validation observation of privileges, resources and isolation."""

    interaction_id: Identifier
    category: Literal[
        "privilege_context",
        "accessible_resource_boundary",
        "data_exposure_metadata",
        "isolation_control_validation",
    ]
    action_description: str = Field(strict=True, min_length=1, max_length=240)
    principal_identified: str = Field(strict=True, min_length=1, max_length=120)
    permission_boundary_result: Literal["enforced", "crossed_within_scope", "indeterminate"]
    resource_identifier: str = Field(strict=True, min_length=1, max_length=200)
    exposure_metadata_summary: str = Field(strict=True, min_length=1, max_length=300)
    observed_at: str
    evidence_hash: Digest
    raw_sensitive_data_retained: ForbiddenFalse = False
    destructive_or_persistent: ForbiddenFalse = False


class AssessmentSession(StrictContract):
    """Authorized interactive assessment session bound to an active target scope."""

    session_id: Identifier
    finding_id: Identifier
    target_url: str
    scope_version: int = Field(strict=True, ge=1)
    operator_approval_ref: Identifier
    mechanism: Literal["laboratory_http_session", "metasploit_session_handle", "authorized_api_token"]
    external_session_ref: Identifier | None = None
    state: SessionState
    principal: str = Field(strict=True, min_length=1, max_length=120)
    privilege_level: Literal["unauthenticated", "standard_user", "service_account", "administrative"]
    isolation_boundary: str = Field(strict=True, min_length=1, max_length=160)
    started_at: float
    last_heartbeat_at: float
    expires_at: float
    ended_at: float | None = None
    termination_reason: str | None = None
    observations: tuple[BoundaryObservation, ...] = ()
    covert_persistence: ForbiddenFalse = False
    credential_harvesting: ForbiddenFalse = False
    unauthorized_lateral_movement: ForbiddenFalse = False
    destructive_actions: ForbiddenFalse = False

    @property
    def duration_seconds(self) -> float:
        end = self.ended_at if self.ended_at is not None else self.last_heartbeat_at
        return max(0.0, round(end - self.started_at, 3))


class CleanupArtifact(StrictContract):
    """Artifact or session handle registered during validation that must be cleaned up."""

    artifact_id: Identifier
    session_id: Identifier | None = None
    kind: Literal["session_handle", "temporary_record", "canary_probe", "staging_file"]
    location: str = Field(strict=True, min_length=1, max_length=240)
    state: CleanupState = "pending_cleanup"
    verification_detail: str = Field(default="", strict=True, max_length=240)
    verified_at: str | None = None


class ImpactAssessment(StrictContract):
    """Explicit separation of theoretical impact, observed impact and untested impact."""

    finding_id: Identifier
    vulnerability_class: VulnerabilityClass
    scanner_reported_severity: SeverityLevel
    effective_severity: SeverityLevel
    theoretical_impact: tuple[str, ...] = Field(min_length=1, max_length=10)
    observed_impact: tuple[str, ...]
    not_yet_tested_impact: tuple[str, ...]
    privileges_demonstrated: str = Field(strict=True, min_length=1, max_length=160)
    isolation_boundary_holding: bool = Field(strict=True)
    severity_rationale: str = Field(strict=True, min_length=1, max_length=400)
    evidence_hashes: tuple[Digest, ...]

    @model_validator(mode="after")
    def verify_honest_severity(self):
        if not self.observed_impact and self.effective_severity in ("critical", "high"):
            raise ValueError("Effective severity cannot be high or critical when zero impact was observed.")
        return self


class AssessmentSessionManager:
    """Govern authorized interactive sessions, boundary checks, audit chains and cleanup."""

    def __init__(self, scope: ScopePolicy | dict[str, Any], *, scope_version: int = 1) -> None:
        self._scope = scope if isinstance(scope, ScopePolicy) else ScopePolicy.model_validate(scope)
        self._scope_version = scope_version
        self._sessions: dict[str, AssessmentSession] = {}
        self._cleanup: dict[str, CleanupArtifact] = {}
        self._audit_chain: list[dict[str, Any]] = []

    @property
    def audit_chain(self) -> list[dict[str, Any]]:
        return list(self._audit_chain)

    def _append_audit(self, action: str, resource_id: str, detail: dict[str, Any], now: float) -> str:
        prev_hash = self._audit_chain[-1]["event_hash"] if self._audit_chain else "0" * 64
        event_payload = {
            "action": action,
            "resource_id": resource_id,
            "detail": detail,
            "created_at": round(now, 3),
            "previous_hash": prev_hash,
        }
        event_hash = _canonical_hash(event_payload)
        self._audit_chain.append(event_payload | {"event_hash": event_hash})
        return event_hash

    def verify_audit_integrity(self) -> bool:
        previous = "0" * 64
        for event in self._audit_chain:
            payload = {k: v for k, v in event.items() if k != "event_hash"}
            if payload.get("previous_hash") != previous or _canonical_hash(payload) != event["event_hash"]:
                return False
            previous = event["event_hash"]
        return True

    def open_session(
        self,
        *,
        session_id: str,
        validation_record: ValidationExecutionRecord,
        operator_approval_ref: str,
        mechanism: Literal["laboratory_http_session", "metasploit_session_handle", "authorized_api_token"],
        principal: str,
        privilege_level: Literal["unauthenticated", "standard_user", "service_account", "administrative"],
        isolation_boundary: str,
        max_duration_seconds: float = 900.0,
        external_session_ref: str | None = None,
        now_epoch: float | None = None,
    ) -> AssessmentSession:
        """Open a bounded interactive assessment session from a confirmed validation record."""
        if validation_record.confirmation_state != "confirmed":
            raise PolicyError("An interactive session requires a confirmed validation record.")
        if validation_record.scope_version != self._scope_version:
            raise PolicyError("Validation record scope version does not match current target scope.")
        destination = check_url(self._scope, validation_record.target_url)
        now = now_epoch if now_epoch is not None else datetime.now(UTC).timestamp()
        scope_expiry = self._scope.expires_at.timestamp()
        if now >= scope_expiry:
            raise PolicyError("Cannot open a session after the target scope has expired.")
        if max_duration_seconds <= 0 or max_duration_seconds > 3600:
            raise ValueError("Session duration must be between 1 and 3600 seconds.")
        expires_at = min(now + max_duration_seconds, scope_expiry)
        session = AssessmentSession(
            session_id=session_id,
            finding_id=validation_record.finding_id,
            target_url=destination.url,
            scope_version=self._scope_version,
            operator_approval_ref=operator_approval_ref,
            mechanism=mechanism,
            external_session_ref=external_session_ref,
            state="active",
            principal=_clean_text(principal, "Session principal", 120),
            privilege_level=privilege_level,
            isolation_boundary=_clean_text(isolation_boundary, "Isolation boundary", 160),
            started_at=now,
            last_heartbeat_at=now,
            expires_at=expires_at,
        )
        self._sessions[session_id] = session
        artifact_id = f"cleanup.{session_id}"
        self._cleanup[artifact_id] = CleanupArtifact(
            artifact_id=artifact_id,
            session_id=session_id,
            kind="session_handle",
            location=f"{mechanism}:{external_session_ref or session_id}",
        )
        self._append_audit(
            "session.opened",
            session_id,
            {
                "finding_id": session.finding_id,
                "mechanism": mechanism,
                "principal": session.principal,
                "privilege_level": privilege_level,
                "scope_version": self._scope_version,
                "expires_at": expires_at,
            },
            now,
        )
        return session

    def record_boundary_observation(
        self,
        session_id: str,
        *,
        interaction_id: str,
        category: Literal[
            "privilege_context",
            "accessible_resource_boundary",
            "data_exposure_metadata",
            "isolation_control_validation",
        ],
        action_description: str,
        permission_boundary_result: Literal["enforced", "crossed_within_scope", "indeterminate"],
        resource_identifier: str,
        exposure_metadata_summary: str,
        now_epoch: float | None = None,
    ) -> AssessmentSession:
        """Execute a controlled, non-destructive post-validation check within an active session."""
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"Unknown session: {session_id}")
        now = now_epoch if now_epoch is not None else datetime.now(UTC).timestamp()
        if session.state != "active":
            raise PolicyError(f"Session {session_id} is {session.state} and cannot execute interactions.")
        if session.scope_version != self._scope_version:
            revoked = session.model_copy(
                update={
                    "state": "revoked",
                    "ended_at": now,
                    "termination_reason": "scope_version_updated",
                }
            )
            self._sessions[session_id] = revoked
            self._append_audit("session.revoked", session_id, {"reason": "scope_version_updated"}, now)
            raise PolicyError("Session revoked because the target scope version changed.")
        if now >= session.expires_at or now >= self._scope.expires_at.timestamp():
            expired = session.model_copy(
                update={
                    "state": "expired",
                    "ended_at": now,
                    "termination_reason": "session_or_scope_expired",
                }
            )
            self._sessions[session_id] = expired
            self._append_audit("session.expired", session_id, {"reason": "session_or_scope_expired"}, now)
            raise PolicyError("Session has expired.")

        cleaned_action = _clean_text(action_description, "Action description", 240)
        cleaned_resource = _clean_text(resource_identifier, "Resource identifier", 200)
        cleaned_exposure = _clean_text(exposure_metadata_summary, "Exposure metadata summary", 300)
        observed_at = datetime.fromtimestamp(now, tz=UTC).isoformat(timespec="seconds")
        ev_hash = _canonical_hash(
            {
                "session_id": session_id,
                "interaction_id": interaction_id,
                "category": category,
                "action_description": cleaned_action,
                "principal": session.principal,
                "permission_boundary_result": permission_boundary_result,
                "resource_identifier": cleaned_resource,
                "exposure_metadata_summary": cleaned_exposure,
                "observed_at": observed_at,
            }
        )
        observation = BoundaryObservation(
            interaction_id=interaction_id,
            category=category,
            action_description=cleaned_action,
            principal_identified=session.principal,
            permission_boundary_result=permission_boundary_result,
            resource_identifier=cleaned_resource,
            exposure_metadata_summary=cleaned_exposure,
            observed_at=observed_at,
            evidence_hash=ev_hash,
        )
        updated = session.model_copy(
            update={
                "last_heartbeat_at": now,
                "observations": (*session.observations, observation),
            }
        )
        self._sessions[session_id] = updated
        self._append_audit(
            "session.interaction",
            session_id,
            {
                "interaction_id": interaction_id,
                "category": category,
                "permission_boundary_result": permission_boundary_result,
                "evidence_hash": ev_hash,
            },
            now,
        )
        return updated

    def renew_session(
        self, session_id: str, *, additional_seconds: float, operator_approval_ref: str, now_epoch: float
    ) -> AssessmentSession:
        """Extend an active session within the target's authorized scope window."""
        session = self._sessions[session_id]
        if session.state != "active":
            raise PolicyError("Only an active session may be renewed.")
        if session.scope_version != self._scope_version:
            raise PolicyError("Cannot renew a session after a scope version change.")
        if additional_seconds <= 0 or additional_seconds > 1800:
            raise ValueError("Renewal increment must be between 1 and 1800 seconds.")
        scope_expiry = self._scope.expires_at.timestamp()
        if now_epoch >= session.expires_at or now_epoch >= scope_expiry:
            raise PolicyError("Cannot renew an expired session.")
        new_expiry = min(session.expires_at + additional_seconds, scope_expiry)
        updated = session.model_copy(
            update={
                "last_heartbeat_at": now_epoch,
                "expires_at": new_expiry,
                "operator_approval_ref": operator_approval_ref,
            }
        )
        self._sessions[session_id] = updated
        self._append_audit(
            "session.renewed",
            session_id,
            {"expires_at": new_expiry, "operator_approval_ref": operator_approval_ref},
            now_epoch,
        )
        return updated

    def update_scope_version(self, new_scope_version: int, *, now_epoch: float) -> list[str]:
        """Revoke all active sessions immediately when the target's scope is edited."""
        if new_scope_version <= self._scope_version:
            raise ValueError("New scope version must be greater than current scope version.")
        self._scope_version = new_scope_version
        revoked_ids: list[str] = []
        for sid, session in list(self._sessions.items()):
            if session.state == "active":
                self._sessions[sid] = session.model_copy(
                    update={
                        "state": "revoked",
                        "ended_at": now_epoch,
                        "termination_reason": f"scope_updated_to_v{new_scope_version}",
                    }
                )
                revoked_ids.append(sid)
                self._append_audit(
                    "session.revoked",
                    sid,
                    {"reason": f"scope_updated_to_v{new_scope_version}"},
                    now_epoch,
                )
        return revoked_ids

    def terminate_session(
        self, session_id: str, *, reason: str, verify_cleanup: bool = True, now_epoch: float | None = None
    ) -> AssessmentSession:
        """Terminate a session, record its total duration, and verify session-handle cleanup."""
        session = self._sessions[session_id]
        now = now_epoch if now_epoch is not None else datetime.now(UTC).timestamp()
        cleaned_reason = _clean_text(reason, "Termination reason", 200)
        terminated = session.model_copy(
            update={
                "state": "terminated" if session.state == "active" else session.state,
                "last_heartbeat_at": now,
                "ended_at": session.ended_at or now,
                "termination_reason": session.termination_reason or cleaned_reason,
            }
        )
        self._sessions[session_id] = terminated
        artifact_id = f"cleanup.{session_id}"
        if artifact_id in self._cleanup:
            self._cleanup[artifact_id] = self._cleanup[artifact_id].model_copy(
                update={
                    "state": "cleanup_verified"
                    if verify_cleanup
                    else "cleanup_failed_operator_action_required",
                    "verification_detail": "Session handle closed and verified."
                    if verify_cleanup
                    else "Session handle termination could not be confirmed; operator action required.",
                    "verified_at": datetime.fromtimestamp(now, tz=UTC).isoformat(timespec="seconds"),
                }
            )
        self._append_audit(
            "session.terminated",
            session_id,
            {
                "duration_seconds": terminated.duration_seconds,
                "reason": terminated.termination_reason,
                "cleanup_verified": verify_cleanup,
            },
            now,
        )
        return terminated

    def register_artifact(
        self,
        *,
        artifact_id: str,
        session_id: str | None,
        kind: Literal["session_handle", "temporary_record", "canary_probe", "staging_file"],
        location: str,
    ) -> CleanupArtifact:
        artifact = CleanupArtifact(
            artifact_id=artifact_id,
            session_id=session_id,
            kind=kind,
            location=_clean_text(location, "Artifact location", 240),
        )
        self._cleanup[artifact_id] = artifact
        return artifact

    def verify_artifact_cleanup(
        self, artifact_id: str, *, removed: bool, detail: str, now_epoch: float | None = None
    ) -> CleanupArtifact:
        now = now_epoch if now_epoch is not None else datetime.now(UTC).timestamp()
        artifact = self._cleanup[artifact_id]
        updated = artifact.model_copy(
            update={
                "state": "cleanup_verified" if removed else "cleanup_failed_operator_action_required",
                "verification_detail": _clean_text(detail, "Cleanup verification detail", 240),
                "verified_at": datetime.fromtimestamp(now, tz=UTC).isoformat(timespec="seconds"),
            }
        )
        self._cleanup[artifact_id] = updated
        self._append_audit(
            "cleanup.verified" if removed else "cleanup.failed",
            artifact_id,
            {"state": updated.state, "location": updated.location},
            now,
        )
        return updated

    @property
    def cleanup_complete(self) -> bool:
        return all(item.state == "cleanup_verified" for item in self._cleanup.values())

    def evaluate_impact(
        self,
        validation_record: ValidationExecutionRecord,
        session: AssessmentSession | None,
        *,
        scanner_reported_severity: SeverityLevel,
        theoretical_impact: list[str],
        not_yet_tested_impact: list[str],
    ) -> ImpactAssessment:
        """Compute verified impact from actual validation and session boundary observations."""
        observed: list[str] = []
        evidence_hashes: list[str] = [validation_record.evidence_hash]
        isolation_holding = True
        privileges = validation_record.resulting_privilege_context

        if validation_record.confirmation_state == "confirmed":
            observed.append(
                f"Validated {validation_record.vulnerability_class} via {validation_record.technique_id} on {', '.join(validation_record.affected_resources)}."
            )
        if session is not None:
            privileges = f"{session.principal} ({session.privilege_level})"
            for obs in session.observations:
                evidence_hashes.append(obs.evidence_hash)
                if obs.permission_boundary_result == "crossed_within_scope":
                    observed.append(
                        f"{obs.category}: {obs.exposure_metadata_summary} ({obs.resource_identifier})"
                    )
                    if obs.category == "isolation_control_validation":
                        isolation_holding = False
                elif obs.permission_boundary_result == "enforced":
                    observed.append(
                        f"Boundary enforced on {obs.resource_identifier}: {obs.exposure_metadata_summary}"
                    )

        if validation_record.confirmation_state != "confirmed" or not observed:
            effective: SeverityLevel = "info" if validation_record.confirmation_state == "refuted" else "low"
            rationale = "Vulnerability was not confirmed or produced no demonstrable boundary impact."
        elif not isolation_holding or (session and session.privilege_level == "administrative"):
            effective = "critical" if not isolation_holding else "high"
            rationale = (
                "Observed administrative privilege context or crossed isolation boundary within scope."
            )
        elif session and any(
            o.permission_boundary_result == "crossed_within_scope" for o in session.observations
        ):
            effective = (
                "high" if session.privilege_level in ("service_account", "standard_user") else "medium"
            )
            rationale = "Validation confirmed access and crossed a resource permission boundary, while container/host isolation held."
        else:
            effective = "medium" if scanner_reported_severity in ("critical", "high", "medium") else "low"
            rationale = "Initial flaw confirmed, but downstream permission and isolation boundaries held against further access."

        return ImpactAssessment(
            finding_id=validation_record.finding_id,
            vulnerability_class=validation_record.vulnerability_class,
            scanner_reported_severity=scanner_reported_severity,
            effective_severity=effective,
            theoretical_impact=tuple(_clean_text(i, "Theoretical impact", 240) for i in theoretical_impact),
            observed_impact=tuple(observed),
            not_yet_tested_impact=tuple(
                _clean_text(i, "Untested impact", 240) for i in not_yet_tested_impact
            ),
            privileges_demonstrated=privileges,
            isolation_boundary_holding=isolation_holding,
            severity_rationale=rationale,
            evidence_hashes=tuple(evidence_hashes),
        )

    def workflow_report(
        self,
        *,
        finding: dict[str, Any],
        validation_record: ValidationExecutionRecord,
        session_id: str | None,
        impact: ImpactAssessment,
    ) -> dict[str, Any]:
        """Reconstruct the complete 8-stage Detection-to-Cleanup lifecycle for SHARAY reporting."""
        session = self._sessions.get(session_id) if session_id else None
        return {
            "finding_id": validation_record.finding_id,
            "stages": {
                "1_detection": {
                    "source": finding.get("source", "scanner"),
                    "category": finding.get("category"),
                    "cwe_id": finding.get("cwe_id"),
                    "initial_severity": finding.get("severity", "unknown"),
                },
                "2_technical_validation": {
                    "technique_id": validation_record.technique_id,
                    "selection_mode": validation_record.selection_mode,
                    "preconditions_met": list(validation_record.preconditions_met),
                },
                "3_authorized_validation_execution": {
                    "confirmation_state": validation_record.confirmation_state,
                    "operator_approval_ref": validation_record.operator_approval_ref,
                    "observed_response_summary": validation_record.observed_response_summary,
                    "evidence_hash": validation_record.evidence_hash,
                },
                "4_interactive_session": None
                if session is None
                else {
                    "session_id": session.session_id,
                    "mechanism": session.mechanism,
                    "state": session.state,
                    "principal": session.principal,
                    "privilege_level": session.privilege_level,
                    "duration_seconds": session.duration_seconds,
                    "termination_reason": session.termination_reason,
                },
                "5_post_validation_assessment": []
                if session is None
                else [obs.model_dump() for obs in session.observations],
                "6_impact_verification": impact.model_dump(),
                "7_cleanup_verification": {
                    "cleanup_complete": self.cleanup_complete,
                    "artifacts": [item.model_dump() for item in self._cleanup.values()],
                },
                "8_audit_provenance": {
                    "audit_events_count": len(self._audit_chain),
                    "audit_chain_valid": self.verify_audit_integrity(),
                    "head_event_hash": self._audit_chain[-1]["event_hash"] if self._audit_chain else None,
                },
            },
        }


__all__ = [
    "AssessmentSession",
    "AssessmentSessionManager",
    "BoundaryObservation",
    "CleanupArtifact",
    "ImpactAssessment",
    "SelectedValidationPlan",
    "VALIDATION_CATALOG",
    "ValidationExecutionRecord",
    "ValidationTechnique",
    "correlate_finding",
    "execute_validation_step",
    "select_validation_method",
]
