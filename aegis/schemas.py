"""Versioned API input contracts."""

from typing import Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

from packages.security_policies import PolicyError, ScopePolicy


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Input):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=1, max_length=256)


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
    crawler_max_pages: int = Field(default=30, strict=True, ge=5, le=100)
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
        ]
    ] = Field(default_factory=list, max_length=15)

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
        rate = policy.request_rate if self.rate is None else self.rate
        return self.model_copy(update={"rate": min(rate, 5000.0)})

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
