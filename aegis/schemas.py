"""Versioned API input contracts."""

from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

from packages.security_policies import PolicyError, ScopePolicy


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Input):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=1, max_length=256)
    # TOTP code or a backup code, required only when the account has MFA enabled.
    code: str | None = Field(default=None, max_length=16)


class MemberInput(Input):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=12, max_length=256)
    role: str


class ProjectInput(Input):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=4000)


class ProjectUpdate(Input):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    archived: bool | None = None


class TargetInput(Input):
    url: str = Field(min_length=1, max_length=2048)
    scope: ScopePolicy


class TargetScopeUpdate(TargetInput):
    expected_scope_version: int = Field(strict=True, ge=1)


class ApprovalInput(Input):
    acknowledgement: str
    expected_scope_version: int = Field(strict=True, ge=1)


class ScanConfig(Input):
    mode: Literal["passive", "standard", "adaptive", "aggressive"] = "adaptive"
    # Requests/second; omission inherits the approved scope, never an adapter default.
    rate: float | None = Field(
        default=None,
        strict=True,
        gt=0,
        le=5000,
        allow_inf_nan=False,
        validation_alias=AliasChoices("rate", "rate_limit"),
    )
    depth: int = Field(
        default=2, strict=True, ge=1, le=5, validation_alias=AliasChoices("depth", "crawler_depth")
    )
    # Default stays small so ordinary targets are quick; the ceiling is high so an operator can opt into
    # full coverage of a large app (e.g. a 2740-endpoint benchmark) without the request being rejected.
    crawler_max_pages: int = Field(default=30, strict=True, ge=5, le=5000)
    # Per-stage execution budget (seconds). Each scan stage gets its own timeout — not a slice of a
    # shared pool — so stages never starve each other. Capped at 600s so a single hung stage can never
    # wedge the whole scan for longer than 10 minutes; 0/unset = default.
    stage_timeout_seconds: int = Field(default=0, strict=True, ge=0, le=600)
    severities: str = Field(default="medium,high,critical", max_length=64)
    tags: str | None = Field(
        default=None, max_length=512, pattern=r"^[a-z0-9_][a-z0-9_-]*(?:,[a-z0-9_][a-z0-9_-]*)*$"
    )
    tools: list[
        Literal[
            "nmap",
            "crawler",
            "sensitive",
            "diff",
            "nuclei",
            "zap",
            "metasploit",
            "browser",
            "schema",
            "auth_matrix",
            "payload_forge",
            "reproducer",
            "ffuf",
            "dalfox",
            "katana",
            # Tools offered in the operator UI and dispatched by scan_comprehensive; previously
            # omitted here, so selecting any of them in the UI failed launch validation (P1-1).
            "cve",
            "graphql",
            "websocket",
            "wordlist",
            # Native-arm64 nuclei verification stage; replaces the emulated Metasploit slot.
            "verification",
        ]
    ] = Field(default_factory=list, max_length=20)

    @field_validator("severities")
    @classmethod
    def valid_severities(cls, value):
        tokens = value.split(",")
        if len(tokens) != len(set(tokens)) or not set(tokens) <= {
            "info",
            "low",
            "medium",
            "high",
            "critical",
        }:
            raise ValueError("Use unique severity names")
        return value

    @model_validator(mode="after")
    def valid_tools(self):
        if len(self.tools) != len(set(self.tools)):
            raise ValueError("Tool selections must be unique")
        if self.mode == "passive" and self.tools:
            raise ValueError("Passive mode cannot select active tools")
        return self

    def within_scope(self, scope: ScopePolicy | dict) -> "ScanConfig":
        policy = scope if isinstance(scope, ScopePolicy) else ScopePolicy.model_validate(scope)
        # The effective rate may never exceed the approved ceiling. A requested rate only lowers it;
        # it can never raise it above policy.request_rate (which the field already bounds at 5000).
        requested = policy.request_rate if self.rate is None else self.rate
        return self.model_copy(update={"rate": min(requested, policy.request_rate)})

    def require_local_profile(self, profile: str) -> None:
        if profile not in {"safe_http", "approved_templates", "comprehensive"}:
            raise PolicyError(f"Unsupported assessment profile: {profile}")


class AssessmentInput(Input):
    target_id: str
    idempotency_key: str = Field(min_length=8, max_length=100)
    expected_scope_version: int = Field(strict=True, ge=1)
    retest_of: str | None = None
    # External profiles remain represented while their execution controls await review.
    profile: Literal["safe_http", "approved_templates", "comprehensive"] = "safe_http"
    config: ScanConfig | None = None


class FindingUpdate(Input):
    status: str


class WorkspaceProbeInput(Input):
    target_id: str
    url: str
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    output_prefix: str | None = None
    output_suffix: str | None = None
    timeout: float = 10.0


class CreateSessionInput(Input):
    target_id: str
    cols: int = Field(default=80, ge=10, le=400)
    rows: int = Field(default=24, ge=5, le=200)


class SessionInputData(Input):
    data: str = Field(max_length=16384)
    sender: str = Field(default="human", pattern="^(human|agent)$")


class SessionResizeInput(Input):
    cols: int = Field(ge=10, le=400)
    rows: int = Field(ge=5, le=200)


class SessionOwnershipInput(Input):
    state: str = Field(pattern="^(AGENT_OWNED|HUMAN_OWNED|SHARED)$")


class ExploitGateConfirmation(Input):
    exploit_type: str = Field(max_length=64)
    target_id: str
    target_url: str
    auto_proceed: bool = False
    operator_confirmed: bool = Field(default=False, strict=True)


class SessionCollaborateJoinInput(Input):
    as_primary: bool = False
    color_hex: str = Field(default="#3b82f6", max_length=16)


class SessionCollaborateTransferInput(Input):
    target_operator_id: str
    reason: str = Field(default="voluntary_handoff", max_length=512)


class SessionCollaborateTakeoverInput(Input):
    justification: str = Field(min_length=3, max_length=512)


class SessionCopilotInput(Input):
    partial_cmd: str | None = Field(default=None, max_length=2048)
    last_output: str | None = Field(default=None, max_length=16384)
    detected_vuln_classes: list[str] | None = None


class BulkTriageInput(Input):
    finding_ids: list[str] = Field(min_length=1)
    status: str = Field(pattern="^(OPEN|IN_REVIEW|CONFIRMED|RESOLVED|FALSE_POSITIVE)$")
    justification: str = Field(default="Bulk triage update", max_length=1000)


class SavedViewInput(Input):
    name: str = Field(min_length=1, max_length=128)
    filters: dict[str, Any] = Field(default_factory=dict)


class OnboardingAdvanceInput(Input):
    step: str = Field(min_length=1, max_length=64)
    data: dict[str, Any] = Field(default_factory=dict)


class CredentialInput(Input):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    kind: Literal["cookie", "header", "bearer", "basic"]
    value: str = Field(min_length=1, max_length=8192)
    # Required for kind="header"/"cookie": the header or cookie name to carry the value.
    header_name: str | None = Field(default=None, max_length=80)
    # Optional: group credentials into a named operator identity for dual-identity IDOR/BOLA testing.
    # subject_id is the resource id that identity owns (used for cross-tenant targeting).
    identity: str | None = Field(default=None, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    subject_id: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def header_name_required(self):
        if self.kind in ("header", "cookie") and not (self.header_name and self.header_name.strip()):
            raise ValueError("header_name is required for header/cookie credentials")
        return self


class SourceAnalysisInput(Input):
    path: str = Field(min_length=1, max_length=4096)
    # When given, source findings are persisted under this target as a source-profile assessment so
    # they join the normal lifecycle (Findings list, reports, retests). Omitted = ad-hoc result only.
    target_id: str | None = None


class UpdateCheckInput(Input):
    manifest_json: str = Field(min_length=2)


class UpdateApplyInput(Input):
    binary_bytes_b64: str = Field(min_length=1)
    manifest: dict[str, Any]
    target_install_path: str = Field(min_length=1)
