"""SHARAY's typed proposal boundary; these contracts never execute a tool.

Adapters translate a fixed operation identifier into their own reviewed argv.
Proposals cannot contain commands, arguments, URLs, scripts, console input or
free-form flags. Metadata and readiness MUST come from the trusted control
plane, never from the proposer. A decision is not a network scope check: an
implemented runner must still validate every destination and redirect.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator

AdapterId = Literal["safe_http", "nmap", "zap", "nuclei", "semgrep", "gitleaks", "metasploit"]
Operation = Literal[
    "safe_http.inspect",
    "nmap.inventory",
    "zap.passive",
    "nuclei.approved_templates",
    "semgrep.static",
    "gitleaks.static",
    "metasploit.catalog",
    "metasploit.approved_auxiliary",
]
Profile = Literal[
    "safe_http",
    "bounded_inventory",
    "passive_web",
    "approved_templates",
    "static",
    "catalog",
    "approved_auxiliary",
]
Risk = Literal["passive", "low", "moderate"]
CapabilityState = Literal["implemented", "planned", "missing", "blocked"]
EvidenceKind = Literal["structured_observations", "redacted_static_results", "catalog_metadata"]
RunnerCapability = Literal[
    "non_root",
    "fixed_argv_without_shell",
    "clean_environment",
    "exec_allowlist",
    "filesystem_read_allowlist",
    "scratch_only_writes",
    "network_denied_by_default",
    "loopback_port_egress",
    "live_destination_egress",
    "deadline_and_cancellation_group_kill",
    "bounded_output",
    "process_escape_containment",
    "exact_loopback_address",
    "escape_containment_for_forking_tools",
    "memory_limit",
    "process_count_limit",
    "aggregate_scratch_quota",
    "file_metadata_privacy",
]
REQUIRED_RUNNER_CONTROLS: frozenset[RunnerCapability] = frozenset(
    {
        "non_root",
        "fixed_argv_without_shell",
        "clean_environment",
        "exec_allowlist",
        "filesystem_read_allowlist",
        "scratch_only_writes",
        "network_denied_by_default",
        "deadline_and_cancellation_group_kill",
        "bounded_output",
        "process_escape_containment",
        "memory_limit",
        "process_count_limit",
        "aggregate_scratch_quota",
    }
)
Reference = Annotated[
    str, Field(strict=True, min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
]
Digest = Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{64}$")]


def _strict_boolean(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("Permission flags must be actual booleans.")
    return value


Required = Annotated[Literal[True], BeforeValidator(_strict_boolean)]
Forbidden = Annotated[Literal[False], BeforeValidator(_strict_boolean)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionBudget(Contract):
    max_seconds: int = Field(default=60, strict=True, ge=1, le=300)
    max_requests: int = Field(default=5, strict=True, ge=0, le=100)
    max_concurrency: Literal[1] = 1
    max_evidence_bytes: int = Field(default=65536, strict=True, ge=1, le=1048576)

    @field_validator("max_concurrency", mode="before")
    @classmethod
    def strict_concurrency(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Concurrency must be an integer.")
        return value


class CancellationContract(Contract):
    token_ref: Reference
    propagate_to_children: Required = True
    terminate_after_seconds: int = Field(default=3, strict=True, ge=1, le=10)


class EvidenceContract(Contract):
    sink_ref: Reference
    kind: EvidenceKind
    redact_secrets: Required = True
    retain_raw_response_body: Forbidden = False
    integrity_hash: Literal["sha256"] = "sha256"


# Every operation has fixed profile, risk, evidence type and execution boundary.
# These are dispatch identifiers, not scanner options or executable commands.
OPERATION_RULES: dict[Operation, tuple[AdapterId, Profile, Risk, EvidenceKind, str]] = {
    "safe_http.inspect": ("safe_http", "safe_http", "low", "structured_observations", "loopback"),
    "nmap.inventory": ("nmap", "bounded_inventory", "low", "structured_observations", "live"),
    "zap.passive": ("zap", "passive_web", "low", "structured_observations", "live"),
    "nuclei.approved_templates": (
        "nuclei",
        "approved_templates",
        "moderate",
        "structured_observations",
        "live",
    ),
    "semgrep.static": ("semgrep", "static", "passive", "redacted_static_results", "source"),
    "gitleaks.static": ("gitleaks", "static", "passive", "redacted_static_results", "source"),
    "metasploit.catalog": ("metasploit", "catalog", "passive", "catalog_metadata", "catalog"),
    "metasploit.approved_auxiliary": (
        "metasploit",
        "approved_auxiliary",
        "moderate",
        "structured_observations",
        "live",
    ),
}


class ScannerAdapterMetadata(Contract):
    adapter_id: AdapterId
    display_name: str = Field(min_length=1, max_length=120, strict=True)
    version: str | None = Field(default=None, max_length=80, strict=True)
    capability_state: CapabilityState
    dependency_state: Literal["available", "missing", "unknown"] = "unknown"
    executable_detected: bool = Field(default=False, strict=True)
    execution_enabled: bool = Field(default=False, strict=True)
    supported_operations: list[Operation] = Field(min_length=1, max_length=2)
    limitation: str = Field(default="", max_length=1000, strict=True)

    @model_validator(mode="after")
    def adapter_operations(self):
        if len(set(self.supported_operations)) != len(self.supported_operations):
            raise ValueError("Duplicate adapter operations are forbidden.")
        if any(OPERATION_RULES[operation][0] != self.adapter_id for operation in self.supported_operations):
            raise ValueError("An operation must belong to the declared adapter.")
        return self


class ProposedToolAction(Contract):
    adapter_id: AdapterId
    operation: Operation
    scope_ref: Reference
    authorized_target_ref: Reference
    profile: Profile
    risk: Risk
    approval_required: Required = True
    approval_ref: Reference | None = None
    budget: ExecutionBudget
    cancellation: CancellationContract
    evidence: EvidenceContract
    template_set_ref: Reference | None = None
    auxiliary_module_ref: Reference | None = None
    intrusive: Forbidden = False

    @model_validator(mode="after")
    def coherent_operation(self):
        adapter, profile, risk, evidence, boundary = OPERATION_RULES[self.operation]
        if (self.adapter_id, self.profile, self.risk, self.evidence.kind) != (
            adapter,
            profile,
            risk,
            evidence,
        ):
            raise ValueError("Adapter, profile, risk and evidence must match the fixed operation.")
        if boundary in {"live", "loopback"} and self.budget.max_requests < 1:
            raise ValueError("Network inspection requires a positive bounded request budget.")
        if boundary in {"source", "catalog"} and self.budget.max_requests != 0:
            raise ValueError("Static/catalog operations cannot request network access.")
        if (self.template_set_ref is not None) != (self.operation == "nuclei.approved_templates"):
            raise ValueError("Only Nuclei's approved-template operation requires a template-set reference.")
        if (self.auxiliary_module_ref is not None) != (self.operation == "metasploit.approved_auxiliary"):
            raise ValueError("Only the approved auxiliary operation requires a catalog module reference.")
        return self


class ExecutionReadiness(Contract):
    """Authoritative control-plane state, never model/user supplied readiness.

    Runner controls describe the chosen execution profile, not host availability.
    In particular, non-forking containment cannot attest a fork-enabled run.
    """

    scope_ref: Reference
    authorized_target_ref: Reference
    scope_hash: Digest | None = None
    scope_active: bool = Field(default=False, strict=True)
    target_authorized: bool = Field(default=False, strict=True)
    approval_ref: Reference | None = None
    approved_by_ref: Reference | None = None
    approved_operations: list[Operation] = Field(default_factory=list, max_length=8)
    approved_budget: ExecutionBudget = Field(default_factory=ExecutionBudget)
    loopback_policy_configured: bool = Field(default=False, strict=True)
    target_is_literal_loopback: bool = Field(default=False, strict=True)
    live_policy_configured: bool = Field(default=False, strict=True)
    source_policy_configured: bool = Field(default=False, strict=True)
    runner_enforced: list[RunnerCapability] = Field(
        default_factory=list,
        max_length=17,
        strict=True,
        description="Controls verified by the trusted server for this exact runner profile and invocation.",
    )
    dedicated_worker_ready: bool = Field(default=False, strict=True)
    cancellation_token_ref: Reference | None = None
    evidence_sink_ref: Reference | None = None
    approved_template_set_refs: list[Reference] = Field(default_factory=list, max_length=100)
    approved_auxiliary_module_refs: list[Reference] = Field(default_factory=list, max_length=100)

    @field_validator("runner_enforced")
    @classmethod
    def unique_runner_controls(cls, value: list[RunnerCapability]) -> list[RunnerCapability]:
        if len(set(value)) != len(value):
            raise ValueError("Duplicate runner controls are forbidden.")
        return value


DecisionCode = Literal[
    "adapter_mismatch",
    "capability_unimplemented",
    "dependency_unavailable",
    "execution_disabled",
    "operation_unsupported",
    "scope_reference_mismatch",
    "scope_inactive",
    "target_unauthorized",
    "scope_snapshot_missing",
    "approval_missing",
    "operation_unapproved",
    "budget_exceeded",
    "cancellation_unconfigured",
    "evidence_unconfigured",
    "loopback_policy_unconfigured",
    "live_policy_unconfigured",
    "source_policy_unconfigured",
    "isolation_controls_missing",
    "egress_unenforced",
    "worker_unavailable",
    "template_set_unapproved",
    "auxiliary_module_unapproved",
]


class AuthorizationDecision(Contract):
    allowed: bool = Field(strict=True)
    operation: Operation
    scope_ref: Reference
    authorized_target_ref: Reference
    reason_codes: list[DecisionCode]
    execution_operation: Operation | None = None
    approval_required: Required = True
    policy_version: Literal["tool-contract-v1"] = "tool-contract-v1"

    @model_validator(mode="after")
    def coherent_decision(self):
        if self.allowed == bool(self.reason_codes):
            raise ValueError("Allowed decisions have no rejection reasons; denied decisions require reasons.")
        if self.execution_operation != (self.operation if self.allowed else None):
            raise ValueError("Only allowed decisions can include their exact execution operation.")
        return self


def evaluate_tool_action(
    action: ProposedToolAction,
    metadata: ScannerAdapterMetadata,
    readiness: ExecutionReadiness,
) -> AuthorizationDecision:
    """Deny unless independent capability, scope, approval and runner gates pass."""
    reasons: list[DecisionCode] = []

    def require(condition: bool, reason: DecisionCode) -> None:
        if not condition:
            reasons.append(reason)

    require(action.adapter_id == metadata.adapter_id, "adapter_mismatch")
    require(metadata.capability_state == "implemented", "capability_unimplemented")
    require(metadata.dependency_state == "available", "dependency_unavailable")
    require(metadata.execution_enabled, "execution_disabled")
    require(action.operation in metadata.supported_operations, "operation_unsupported")
    require(
        (action.scope_ref, action.authorized_target_ref)
        == (readiness.scope_ref, readiness.authorized_target_ref),
        "scope_reference_mismatch",
    )
    require(readiness.scope_active, "scope_inactive")
    require(readiness.target_authorized, "target_unauthorized")
    require(readiness.scope_hash is not None, "scope_snapshot_missing")
    require(
        action.approval_ref is not None
        and action.approval_ref == readiness.approval_ref
        and readiness.approved_by_ref is not None,
        "approval_missing",
    )
    require(action.operation in readiness.approved_operations, "operation_unapproved")
    require(
        all(
            getattr(action.budget, field) <= getattr(readiness.approved_budget, field)
            for field in ExecutionBudget.model_fields
        ),
        "budget_exceeded",
    )
    require(action.cancellation.token_ref == readiness.cancellation_token_ref, "cancellation_unconfigured")
    require(action.evidence.sink_ref == readiness.evidence_sink_ref, "evidence_unconfigured")
    require(readiness.dedicated_worker_ready, "worker_unavailable")
    boundary = OPERATION_RULES[action.operation][4]
    if boundary == "loopback":
        require(
            readiness.loopback_policy_configured and readiness.target_is_literal_loopback,
            "loopback_policy_unconfigured",
        )
    else:
        require(REQUIRED_RUNNER_CONTROLS.issubset(readiness.runner_enforced), "isolation_controls_missing")
    if boundary == "live":
        if readiness.target_is_literal_loopback:
            require(readiness.loopback_policy_configured, "loopback_policy_unconfigured")
            require(
                {"loopback_port_egress", "exact_loopback_address"}.issubset(readiness.runner_enforced),
                "egress_unenforced",
            )
        else:
            require(readiness.live_policy_configured, "live_policy_unconfigured")
            require("live_destination_egress" in readiness.runner_enforced, "egress_unenforced")
    if boundary == "source":
        require(readiness.source_policy_configured, "source_policy_unconfigured")
    if action.operation == "nuclei.approved_templates":
        require(action.template_set_ref in readiness.approved_template_set_refs, "template_set_unapproved")
    if action.operation == "metasploit.approved_auxiliary":
        require(
            action.auxiliary_module_ref in readiness.approved_auxiliary_module_refs,
            "auxiliary_module_unapproved",
        )
    return AuthorizationDecision(
        allowed=not reasons,
        operation=action.operation,
        scope_ref=action.scope_ref,
        authorized_target_ref=action.authorized_target_ref,
        reason_codes=reasons,
        execution_operation=action.operation if not reasons else None,
    )


def adapter_roadmap() -> list[ScannerAdapterMetadata]:
    """Capabilities and dependencies are separate; presence never enables a tool."""
    adapters: list[AdapterId] = ["safe_http", "nmap", "zap", "nuclei", "semgrep", "gitleaks", "metasploit"]
    return [
        ScannerAdapterMetadata(
            adapter_id=adapter,
            display_name=adapter,
            capability_state="implemented" if adapter == "safe_http" else "planned",
            dependency_state="available" if adapter == "safe_http" else "unknown",
            execution_enabled=adapter == "safe_http",
            supported_operations=[
                operation for operation, rule in OPERATION_RULES.items() if rule[0] == adapter
            ],
            limitation="Existing approved loopback-only HTTP adapter; no OS sandbox."
            if adapter == "safe_http"
            else "Product dispatch is disabled pending verified integration and per-run isolation controls; detection of an executable is insufficient authorization.",
        )
        for adapter in adapters
    ]


__all__ = [
    "AuthorizationDecision",
    "CancellationContract",
    "EvidenceContract",
    "ExecutionBudget",
    "ExecutionReadiness",
    "ProposedToolAction",
    "Reference",
    "REQUIRED_RUNNER_CONTROLS",
    "RunnerCapability",
    "ScannerAdapterMetadata",
    "adapter_roadmap",
    "evaluate_tool_action",
]
