import unittest

from pydantic import ValidationError

from packages.shared_schemas import (
    AuthorizationDecision,
    ExecutionReadiness,
    ProposedToolAction,
    ScannerAdapterMetadata,
    adapter_roadmap,
    evaluate_tool_action,
)

# Snapshot of the kernel-probed controls reported by Claude's partial Seatbelt backend.
# This unit fixture does not launch a process or claim to attest the current host.
SEATBELT_REPORTED_CONTROLS = [
    "exec_allowlist",
    "filesystem_read_allowlist",
    "scratch_only_writes",
    "network_denied_by_default",
    "loopback_port_egress",
    "process_escape_containment",
    "exact_loopback_address",
    "process_count_limit",
    "aggregate_scratch_quota",
]

# Synthetic trusted-server context for contract tests; no runner supplies all of these today.
FULL_RUNNER_CONTROLS = [
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
    "loopback_port_egress",
    "exact_loopback_address",
    "live_destination_egress",
]
NETWORK_OPERATIONS = [
    "nmap.inventory",
    "zap.passive",
    "nuclei.approved_templates",
    "metasploit.approved_auxiliary",
]


def proposal(operation="nmap.inventory"):
    choices = {
        "safe_http.inspect": ("safe_http", "safe_http", "low", "structured_observations", 5),
        "nmap.inventory": ("nmap", "bounded_inventory", "low", "structured_observations", 5),
        "zap.passive": ("zap", "passive_web", "low", "structured_observations", 5),
        "nuclei.approved_templates": (
            "nuclei",
            "approved_templates",
            "moderate",
            "structured_observations",
            5,
        ),
        "semgrep.static": ("semgrep", "static", "passive", "redacted_static_results", 0),
        "gitleaks.static": ("gitleaks", "static", "passive", "redacted_static_results", 0),
        "metasploit.catalog": ("metasploit", "catalog", "passive", "catalog_metadata", 0),
        "metasploit.approved_auxiliary": (
            "metasploit",
            "approved_auxiliary",
            "moderate",
            "structured_observations",
            5,
        ),
    }
    adapter, profile, risk, evidence_kind, requests = choices[operation]
    result = {
        "adapter_id": adapter,
        "operation": operation,
        "scope_ref": "scope:approved-v1",
        "authorized_target_ref": "target:verified-123",
        "profile": profile,
        "risk": risk,
        "approval_ref": "approval:owner-123",
        "budget": {"max_seconds": 30, "max_requests": requests},
        "cancellation": {"token_ref": "cancel:assessment-123"},
        "evidence": {"sink_ref": "evidence:assessment-123", "kind": evidence_kind},
    }
    if operation == "nuclei.approved_templates":
        result["template_set_ref"] = "templates:reviewed-set-v1"
    if operation == "metasploit.approved_auxiliary":
        result["auxiliary_module_ref"] = "catalog:reviewed-read-only-module"
    return result


def ready(operation="nmap.inventory"):
    return {
        "scope_ref": "scope:approved-v1",
        "authorized_target_ref": "target:verified-123",
        "scope_hash": "a" * 64,
        "scope_active": True,
        "target_authorized": True,
        "approval_ref": "approval:owner-123",
        "approved_by_ref": "user:owner-123",
        "approved_operations": [operation],
        "live_policy_configured": True,
        "source_policy_configured": True,
        "runner_enforced": FULL_RUNNER_CONTROLS.copy(),
        "loopback_policy_configured": True,
        "target_is_literal_loopback": True,
        "dedicated_worker_ready": True,
        "cancellation_token_ref": "cancel:assessment-123",
        "evidence_sink_ref": "evidence:assessment-123",
        "approved_template_set_refs": ["templates:reviewed-set-v1"],
        "approved_auxiliary_module_refs": ["catalog:reviewed-read-only-module"],
    }


def implemented_metadata(operation="nmap.inventory"):
    data = proposal(operation)
    return ScannerAdapterMetadata(
        adapter_id=data["adapter_id"],
        display_name=data["adapter_id"],
        capability_state="implemented",
        dependency_state="available",
        executable_detected=True,
        execution_enabled=True,
        supported_operations=[operation],
    )


class ToolContractTests(unittest.TestCase):
    def evaluate(self, operation="nmap.inventory", context=None, metadata=None):
        return evaluate_tool_action(
            ProposedToolAction.model_validate(proposal(operation)),
            metadata or implemented_metadata(operation),
            ExecutionReadiness.model_validate(ready(operation) if context is None else context),
        )

    def test_default_readiness_denies_and_emits_no_execution_operation(self):
        context = {"scope_ref": "scope:approved-v1", "authorized_target_ref": "target:verified-123"}
        decision = self.evaluate(context=context)
        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.execution_operation)
        self.assertIn("live_policy_unconfigured", decision.reason_codes)
        self.assertIn("isolation_controls_missing", decision.reason_codes)
        self.assertIn("egress_unenforced", decision.reason_codes)
        self.assertIn("approval_missing", decision.reason_codes)

    def test_live_policy_and_runner_controls_are_independent_required_gates(self):
        for change in [{"live_policy_configured": False}, {"runner_enforced": []}]:
            with self.subTest(change=change):
                decision = self.evaluate(context=ready() | {"target_is_literal_loopback": False} | change)
                self.assertFalse(decision.allowed)
                self.assertIsNone(decision.execution_operation)

    def test_every_live_operation_denies_when_live_policy_unconfigured(self):
        for operation in NETWORK_OPERATIONS:
            with self.subTest(operation=operation):
                decision = self.evaluate(
                    operation,
                    ready(operation) | {"live_policy_configured": False, "target_is_literal_loopback": False},
                )
                self.assertFalse(decision.allowed)
                self.assertIn("live_policy_unconfigured", decision.reason_codes)

    def test_controlled_fixture_branch_does_not_require_live_policy(self):
        for operation in NETWORK_OPERATIONS:
            with self.subTest(operation=operation):
                context = ready(operation) | {
                    "live_policy_configured": False,
                    "runner_enforced": [c for c in FULL_RUNNER_CONTROLS if c != "live_destination_egress"],
                }
                self.assertTrue(self.evaluate(operation, context).allowed)
                live_decision = self.evaluate(operation, context | {"target_is_literal_loopback": False})
                self.assertFalse(live_decision.allowed)
                self.assertIn("live_policy_unconfigured", live_decision.reason_codes)
                self.assertIn("egress_unenforced", live_decision.reason_codes)
                for change in [
                    {"loopback_policy_configured": False},
                    {"runner_enforced": [c for c in FULL_RUNNER_CONTROLS if c != "loopback_port_egress"]},
                    {"runner_enforced": [c for c in FULL_RUNNER_CONTROLS if c != "exact_loopback_address"]},
                ]:
                    with self.subTest(change=change):
                        self.assertFalse(self.evaluate(operation, context | change).allowed)

    def test_live_policy_cannot_replace_destination_egress_enforcement(self):
        for operation in NETWORK_OPERATIONS:
            with self.subTest(operation=operation):
                decision = self.evaluate(
                    operation,
                    ready(operation)
                    | {
                        "target_is_literal_loopback": False,
                        "runner_enforced": [
                            c for c in FULL_RUNNER_CONTROLS if c != "live_destination_egress"
                        ],
                    },
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason_codes, ["egress_unenforced"])

    def test_current_seatbelt_capabilities_cannot_authorize_live_or_external_fixture_tools(self):
        context = ready() | {"runner_enforced": SEATBELT_REPORTED_CONTROLS.copy()}
        self.assertIn("exact_loopback_address", context["runner_enforced"])
        self.assertNotIn("memory_limit", context["runner_enforced"])
        self.assertNotIn("live_destination_egress", context["runner_enforced"])
        fixture_decision = self.evaluate(context=context)
        self.assertFalse(fixture_decision.allowed)
        self.assertIn("isolation_controls_missing", fixture_decision.reason_codes)
        live_decision = self.evaluate(context=context | {"target_is_literal_loopback": False})
        self.assertFalse(live_decision.allowed)
        self.assertIn("isolation_controls_missing", live_decision.reason_codes)
        self.assertIn("egress_unenforced", live_decision.reason_codes)

    def test_each_common_runner_control_is_required_for_every_external_operation(self):
        controls = [
            c
            for c in FULL_RUNNER_CONTROLS
            if c not in {"loopback_port_egress", "exact_loopback_address", "live_destination_egress"}
        ]
        for operation in [*NETWORK_OPERATIONS, "semgrep.static", "gitleaks.static", "metasploit.catalog"]:
            for missing in controls:
                with self.subTest(operation=operation, missing=missing):
                    decision = self.evaluate(
                        operation,
                        ready(operation)
                        | {"runner_enforced": [c for c in FULL_RUNNER_CONTROLS if c != missing]},
                    )
                    self.assertFalse(decision.allowed)
                    self.assertIsNone(decision.execution_operation)
                    self.assertIn("isolation_controls_missing", decision.reason_codes)

    def test_runner_controls_reject_unknown_duplicate_coerced_and_legacy_values(self):
        for change in [
            {"isolated_runner_configured": True},
            {"runner_enforced": ["arbitrary_backend_permission"]},
            {"runner_enforced": ["new_session_escape_containment"]},
            {"runner_enforced": ["non_root", "non_root"]},
            {"runner_enforced": [True]},
            {"runner_enforced": ("non_root",)},
            {"runner_enforced": "non_root"},
        ]:
            with self.subTest(change=change), self.assertRaises(ValidationError):
                ExecutionReadiness.model_validate(ready() | change)

    def test_installed_executable_does_not_enable_planned_missing_or_blocked_capability(self):
        for state in ["planned", "missing", "blocked"]:
            with self.subTest(state=state):
                metadata = implemented_metadata().model_copy(update={"capability_state": state})
                decision = self.evaluate(metadata=metadata)
                self.assertFalse(decision.allowed)
                self.assertIn("capability_unimplemented", decision.reason_codes)
        self.assertFalse(
            self.evaluate(
                metadata=implemented_metadata().model_copy(update={"execution_enabled": False})
            ).allowed
        )

    def test_missing_or_unknown_dependency_denies_implemented_adapter(self):
        for state in ["missing", "unknown"]:
            with self.subTest(state=state):
                metadata = implemented_metadata().model_copy(update={"dependency_state": state})
                decision = self.evaluate(metadata=metadata)
                self.assertFalse(decision.allowed)
                self.assertIn("dependency_unavailable", decision.reason_codes)

    def test_schema_rejects_shell_argv_console_exploit_and_intrusive_payloads(self):
        changes = [
            {"command": "nmap; arbitrary-shell"},
            {"argv": ["nmap", "-A", "unapproved-host"]},
            {"shell": True},
            {"console_input": "use exploit/example"},
            {"operation": "metasploit.exploit"},
            {"payload": "destructive"},
            {"intrusive": True},
            {"approval_required": False},
            {"approval_required": 1},
            {"scope_ref": "https://example.com"},
            {"authorized_target_ref": "127.0.0.1; shell"},
            {"risk": "unrestricted"},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValidationError):
                ProposedToolAction.model_validate(proposal() | change)

    def test_operation_profile_risk_and_adapter_cannot_be_downgraded(self):
        for change in [{"risk": "passive"}, {"profile": "catalog"}, {"adapter_id": "metasploit"}]:
            with self.subTest(change=change), self.assertRaises(ValidationError):
                ProposedToolAction.model_validate(proposal() | change)
        with self.assertRaises(ValidationError):
            ScannerAdapterMetadata(
                adapter_id="nmap",
                display_name="nmap",
                capability_state="planned",
                supported_operations=["metasploit.approved_auxiliary"],
            )

    def test_scope_target_expiry_snapshot_and_approval_are_independently_checked(self):
        changes = [
            {"scope_ref": "scope:different"},
            {"authorized_target_ref": "target:different"},
            {"scope_active": False},
            {"scope_hash": None},
            {"target_authorized": False},
            {"approval_ref": "approval:different"},
            {"approved_by_ref": None},
            {"approved_operations": []},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(self.evaluate(context=ready() | change).allowed)

    def test_budget_validation_rejects_unbounded_and_malformed_limits(self):
        for budget in [
            {"max_seconds": 301},
            {"max_requests": 101},
            {"max_concurrency": 2},
            {"max_concurrency": True},
            {"max_seconds": "30"},
            {"max_seconds": True},
            {"max_evidence_bytes": 1048577},
        ]:
            with self.subTest(budget=budget), self.assertRaises(ValidationError):
                ProposedToolAction.model_validate(proposal() | {"budget": budget})
        decision = self.evaluate(context=ready() | {"approved_budget": {"max_seconds": 10}})
        self.assertFalse(decision.allowed)
        self.assertIn("budget_exceeded", decision.reason_codes)

    def test_cancellation_and_evidence_sink_must_be_configured_and_redaction_cannot_be_disabled(self):
        for change in [
            {"cancellation_token_ref": None},
            {"evidence_sink_ref": None},
            {"dedicated_worker_ready": False},
        ]:
            with self.subTest(change=change):
                self.assertFalse(self.evaluate(context=ready() | change).allowed)
        raw = proposal()
        for change in [{"redact_secrets": False}, {"retain_raw_response_body": True}, {"redact_secrets": 1}]:
            with self.subTest(change=change), self.assertRaises(ValidationError):
                ProposedToolAction.model_validate(raw | {"evidence": raw["evidence"] | change})

    def test_template_and_auxiliary_references_require_independent_allowlists(self):
        for operation, field, expected in [
            ("nuclei.approved_templates", "approved_template_set_refs", "template_set_unapproved"),
            (
                "metasploit.approved_auxiliary",
                "approved_auxiliary_module_refs",
                "auxiliary_module_unapproved",
            ),
        ]:
            with self.subTest(operation=operation):
                decision = self.evaluate(operation, ready(operation) | {field: []})
                self.assertFalse(decision.allowed)
                self.assertIn(expected, decision.reason_codes)
        with self.assertRaises(ValidationError):
            ProposedToolAction.model_validate(
                proposal("metasploit.approved_auxiliary")
                | {"auxiliary_module_ref": "exploit/windows/example"}
            )

    def test_static_tools_require_isolation_source_policy_and_zero_network_budget(self):
        for operation in ["semgrep.static", "gitleaks.static"]:
            with self.subTest(operation=operation):
                self.assertFalse(
                    self.evaluate(operation, ready(operation) | {"source_policy_configured": False}).allowed
                )
                self.assertFalse(self.evaluate(operation, ready(operation) | {"runner_enforced": []}).allowed)
                with self.assertRaises(ValidationError):
                    ProposedToolAction.model_validate(proposal(operation) | {"budget": {"max_requests": 1}})

    def test_source_and_catalog_require_network_denial_without_any_egress_grant(self):
        for operation in ["semgrep.static", "gitleaks.static", "metasploit.catalog"]:
            with self.subTest(operation=operation):
                context = ready(operation) | {
                    "live_policy_configured": False,
                    "loopback_policy_configured": False,
                    "runner_enforced": [
                        c
                        for c in FULL_RUNNER_CONTROLS
                        if c
                        not in {"loopback_port_egress", "exact_loopback_address", "live_destination_egress"}
                    ],
                }
                self.assertTrue(self.evaluate(operation, context).allowed)
                decision = self.evaluate(
                    operation,
                    context
                    | {
                        "runner_enforced": [
                            c for c in context["runner_enforced"] if c != "network_denied_by_default"
                        ]
                    },
                )
                self.assertFalse(decision.allowed)
                self.assertIn("isolation_controls_missing", decision.reason_codes)

    def test_loopback_operation_keeps_explicit_lab_policy_and_worker_gate(self):
        operation = "safe_http.inspect"
        context = ready(operation) | {"live_policy_configured": False, "runner_enforced": []}
        self.assertTrue(self.evaluate(operation, context).allowed)
        self.assertFalse(self.evaluate(operation, context | {"target_is_literal_loopback": False}).allowed)
        self.assertFalse(self.evaluate(operation, context | {"dedicated_worker_ready": False}).allowed)

    def test_authorized_decision_contains_only_reviewed_dispatch_identifier(self):
        decision = self.evaluate()
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.execution_operation, "nmap.inventory")
        self.assertEqual(decision.reason_codes, [])
        self.assertNotIn("argv", decision.model_dump())
        self.assertNotIn("command", decision.model_dump())
        self.assertEqual(decision, self.evaluate())

        for changed in [
            {"allowed": False},
            {"execution_operation": "metasploit.catalog"},
            {"reason_codes": ["approval_missing"]},
        ]:
            with self.subTest(changed=changed), self.assertRaises(ValidationError):
                AuthorizationDecision.model_validate(decision.model_dump() | changed)

    def test_roadmap_keeps_external_integrations_planned_and_disabled(self):
        for metadata in adapter_roadmap():
            if metadata.adapter_id == "safe_http":
                self.assertEqual(metadata.capability_state, "implemented")
            else:
                self.assertEqual(metadata.capability_state, "planned")
                self.assertFalse(metadata.execution_enabled)
                self.assertIsNone(metadata.version)


if __name__ == "__main__":
    unittest.main()
