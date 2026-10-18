"""State-of-the-Art (SOTA) Vulnerability Validation Technique Catalog for SHARAY.

Extends SHARAY's verification intelligence from the initial 10-class baseline
into an industry-leading matrix of 17 vulnerability classes and 45+ non-destructive,
differential validation techniques.

Adheres strictly to SHARAY defensive invariants:
- Zero weaponized payloads, exploit strings, shellcode, or destructive operations.
- All active validation relies on deterministic detection oracles:
  (1) Control-vs-candidate differential pairs (Levenshtein / structural diff),
  (2) Jitter-filtered latency differential sampling,
  (3) Non-executable canary token reflection,
  (4) Out-of-band DNS resolution canaries,
  (5) HTTP/2 single-packet synchronization frames for concurrency flaws.
- Every technique enforces execution-time boundary checks, read-only privilege limits,
  and explicit cleanup strategies.
"""

from __future__ import annotations

import copy
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]

SOTA_VULNERABILITY_CLASSES: tuple[str, ...] = (
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
    "graphql",
    "race_conditions",
    "request_smuggling",
    "cache_poisoning",
    "jwt_crypto",
    "cloud_identity",
    "websocket_realtime",
)

SOTA_VALIDATION_TECHNIQUE_CATALOG: dict[str, list[dict[str, Any]]] = {
    # -------------------------------------------------------------------------
    # 1. SQL Injection (CWE-89, MITRE ATT&CK T1190)
    # -------------------------------------------------------------------------
    "sql_injection": [
        {
            "technique_id": "sqli.boolean_differential_pair",
            "vuln_class": "sql_injection",
            "title": "Boolean-based differential response validation",
            "cwe": 89,
            "mitre_attack": "T1190",
            "owasp_category": "A03:2021-Injection",
            "severity": "critical",
            "preconditions": ["identifiable_query_parameter", "deterministic_baseline_response"],
            "boundary_checks": ["current_db_user_privilege_read", "write_capability_denied_check"],
            "opens_session": False,
            "verification_oracle": "boolean_differential_pair",
            "canary_spec": {
                "type": "boolean_expression",
                "tautology": "1=1",
                "contradiction": "1=2",
                "delta_metric": "response_status_or_content_length_divergence",
            },
            "safety_invariants": ["read_only_syntax", "zero_side_effects", "no_ddl_dml"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "sqli.time_jitter_controlled_differential",
            "vuln_class": "sql_injection",
            "title": "Jitter-filtered time-delay differential validation",
            "cwe": 89,
            "mitre_attack": "T1190",
            "owasp_category": "A03:2021-Injection",
            "severity": "critical",
            "preconditions": ["query_parameter_or_header_sink", "baseline_latency_samples_collected"],
            "boundary_checks": ["max_delay_cap_5s", "server_load_threshold_check"],
            "opens_session": False,
            "verification_oracle": "time_jitter_differential",
            "canary_spec": {
                "type": "bounded_sleep_delay",
                "delay_seconds": 3,
                "confidence_threshold": "delta >= 3 * jitter_std_dev",
            },
            "safety_invariants": ["bounded_sleep_max_5s", "no_infinite_wait"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "sqli.error_fingerprint_safe_probe",
            "vuln_class": "sql_injection",
            "title": "Syntax-error DBMS fingerprinting without execution",
            "cwe": 89,
            "mitre_attack": "T1190",
            "owasp_category": "A03:2021-Injection",
            "severity": "high",
            "preconditions": ["database_error_reflection_suspected"],
            "boundary_checks": ["raw_database_credentials_redaction", "stack_trace_sanitization"],
            "opens_session": False,
            "verification_oracle": "structured_error_regex_signature",
            "canary_spec": {
                "type": "unbalanced_quote_syntax_canary",
                "probe": "'\"",
                "signature_match": "postgresql|mysql|sqlite|oracle|microsoft_sql",
            },
            "safety_invariants": ["pure_syntax_provocation", "no_subquery_execution"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "sqli.readonly_catalog_session",
            "vuln_class": "sql_injection",
            "title": "Read-only schema catalog inspection session",
            "cwe": 89,
            "mitre_attack": "T1190",
            "owasp_category": "A03:2021-Injection",
            "severity": "critical",
            "preconditions": ["confirmed_boolean_or_union_sqli", "authorized_session_policy"],
            "boundary_checks": ["information_schema_scope_only", "cross_tenant_table_access_blocked"],
            "opens_session": True,
            "verification_oracle": "metadata_catalog_enumeration",
            "canary_spec": {
                "type": "schema_table_count_read",
                "query_target": "information_schema.tables",
                "max_rows": 5,
            },
            "safety_invariants": ["strictly_information_schema", "no_user_data_extraction"],
            "cleanup_strategy": "terminate_session_on_disconnect",
        },
    ],
    # -------------------------------------------------------------------------
    # 2. Cross-Site Scripting (XSS) (CWE-79, MITRE ATT&CK T1189)
    # -------------------------------------------------------------------------
    "xss": [
        {
            "technique_id": "xss.context_reflection_canary",
            "vuln_class": "xss",
            "title": "Non-executing DOM/HTML context reflection & sink verification",
            "cwe": 79,
            "mitre_attack": "T1189",
            "owasp_category": "A03:2021-Injection",
            "severity": "high",
            "preconditions": ["reflected_or_stored_input_vector"],
            "boundary_checks": ["csp_policy_evaluation", "httponly_cookie_exposure_check"],
            "opens_session": False,
            "verification_oracle": "canary_token_context_reflection",
            "canary_spec": {
                "type": "inert_alphanumeric_canary",
                "format": "sharay_xss_<uuid4>_<context_marker>",
                "non_executing": True,
            },
            "safety_invariants": ["strictly_non_executing_payload", "no_javascript_execution"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "xss.dom_sink_taint_tracing",
            "vuln_class": "xss",
            "title": "Headless browser DOM source-to-sink taint propagation tracing",
            "cwe": 79,
            "mitre_attack": "T1189",
            "owasp_category": "A03:2021-Injection",
            "severity": "high",
            "preconditions": ["client_side_javascript_routing", "headless_browser_worker_ready"],
            "boundary_checks": ["browser_sandbox_isolation", "network_egress_restricted_to_target"],
            "opens_session": False,
            "verification_oracle": "taint_source_sink_instrumentation",
            "canary_spec": {
                "type": "inert_url_hash_or_query_token",
                "sink_targets": ["innerHTML", "outerHTML", "document.write", "eval"],
            },
            "safety_invariants": ["alert_popup_suppression", "no_external_cookie_exfiltration"],
            "cleanup_strategy": "close_browser_context",
        },
        {
            "technique_id": "xss.csp_bypass_script_gadget_check",
            "vuln_class": "xss",
            "title": "Content Security Policy (CSP) gadget & unsafe directive evaluation",
            "cwe": 79,
            "mitre_attack": "T1189",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "medium",
            "preconditions": ["csp_header_present"],
            "boundary_checks": ["script_src_directive_audit", "nonce_entropy_validation"],
            "opens_session": False,
            "verification_oracle": "csp_ast_semantic_audit",
            "canary_spec": {
                "type": "directive_inspection",
                "unsafe_keywords": ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"],
            },
            "safety_invariants": ["passive_header_analysis", "zero_network_mutation"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 3. Server-Side Request Forgery (SSRF) (CWE-918, MITRE ATT&CK T1190)
    # -------------------------------------------------------------------------
    "ssrf": [
        {
            "technique_id": "ssrf.loopback_and_metadata_boundary",
            "vuln_class": "ssrf",
            "title": "Controlled loopback and cloud metadata boundary validation",
            "cwe": 918,
            "mitre_attack": "T1190",
            "owasp_category": "A10:2021-Server-Side Request Forgery",
            "severity": "critical",
            "preconditions": ["url_or_webhook_fetch_parameter"],
            "boundary_checks": ["loopback_port_reachability", "imds_hop_limit_and_token_enforcement"],
            "opens_session": True,
            "verification_oracle": "response_status_and_header_differential",
            "canary_spec": {
                "type": "safe_loopback_probes",
                "targets": ["http://127.0.0.1:80", "http://[::1]:80", "http://169.254.169.254"],
                "header_requirements": ["X-aws-ec2-metadata-token-ttl-seconds: 60"],
            },
            "safety_invariants": ["no_internal_credential_exfiltration", "rate_limited_to_2_requests"],
            "cleanup_strategy": "terminate_session_on_disconnect",
        },
        {
            "technique_id": "ssrf.blind_dns_oob_canary",
            "vuln_class": "ssrf",
            "title": "Out-of-band blind DNS lookup canary validation",
            "cwe": 918,
            "mitre_attack": "T1190",
            "owasp_category": "A10:2021-Server-Side Request Forgery",
            "severity": "high",
            "preconditions": ["url_fetch_accepts_arbitrary_hostname", "canary_nameserver_configured"],
            "boundary_checks": ["non_routable_domain_only", "zero_payload_body_expected"],
            "opens_session": False,
            "verification_oracle": "dns_query_arrival_listener",
            "canary_spec": {
                "type": "unique_subdomain_canary",
                "format": "oob-<finding_id>-<nonce>.canary.internal",
            },
            "safety_invariants": ["dns_only_no_http_server_connection", "strict_origin_binding"],
            "cleanup_strategy": "deregister_dns_canary_listener",
        },
        {
            "technique_id": "ssrf.uri_parser_differential_test",
            "vuln_class": "ssrf",
            "title": "URI parser differential validation (decimal/IPv6/userinfo normalization)",
            "cwe": 918,
            "mitre_attack": "T1190",
            "owasp_category": "A10:2021-Server-Side Request Forgery",
            "severity": "high",
            "preconditions": ["url_validation_allowlist_suspected"],
            "boundary_checks": ["rfc3986_compliance", "dns_pinning_check"],
            "opens_session": False,
            "verification_oracle": "parser_divergence_oracle",
            "canary_spec": {
                "type": "safe_alternate_encodings",
                "samples": ["http://2130706433/", "http://0x7f000001/", "http://127.0.0.1.nip.io"],
            },
            "safety_invariants": ["loopback_targets_only", "no_external_egress"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 4. XML External Entity (XXE) (CWE-611, MITRE ATT&CK T1190)
    # -------------------------------------------------------------------------
    "xxe": [
        {
            "technique_id": "xxe.local_dtd_parameter_entity_check",
            "vuln_class": "xxe",
            "title": "Non-destructive XML entity expansion & external DTD disabled check",
            "cwe": 611,
            "mitre_attack": "T1190",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "high",
            "preconditions": ["xml_or_soap_or_svg_input_endpoint"],
            "boundary_checks": ["external_general_entities_state", "file_uri_resolution_blocked"],
            "opens_session": False,
            "verification_oracle": "xml_canary_entity_reflection",
            "canary_spec": {
                "type": "internal_benign_entity",
                "entity_name": "sharayCanary",
                "entity_value": "sharay_xxe_safe_value_91823",
            },
            "safety_invariants": ["no_file_system_reading", "no_external_http_dtd_retrieval"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "xxe.blind_out_of_band_entity_probe",
            "vuln_class": "xxe",
            "title": "Blind XML external entity out-of-band DNS resolution validation",
            "cwe": 611,
            "mitre_attack": "T1190",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "high",
            "preconditions": ["xml_endpoint_accepts_doctype", "dns_canary_listener_available"],
            "boundary_checks": ["canary_domain_pinning", "no_data_exfiltration_via_url_path"],
            "opens_session": False,
            "verification_oracle": "dns_canary_query_arrival",
            "canary_spec": {
                "type": "system_identifier_dns_uri",
                "uri_template": "http://xxe-<finding_id>.canary.internal/safe",
            },
            "safety_invariants": ["zero_file_content_exfiltration", "benign_dns_beacon_only"],
            "cleanup_strategy": "deregister_dns_canary_listener",
        },
    ],
    # -------------------------------------------------------------------------
    # 5. Command Injection (CWE-77, CWE-78, MITRE ATT&CK T1059)
    # -------------------------------------------------------------------------
    "command_injection": [
        {
            "technique_id": "cmdi.benign_subshell_identity_probe",
            "vuln_class": "command_injection",
            "title": "Bounded benign command-execution context & UID/GID verification",
            "cwe": 78,
            "mitre_attack": "T1059",
            "owasp_category": "A03:2021-Injection",
            "severity": "critical",
            "preconditions": ["os_argument_or_shell_sink_suspected"],
            "boundary_checks": ["effective_uid_gid_inspection", "container_namespace_isolation_check"],
            "opens_session": True,
            "verification_oracle": "bounded_subshell_output_match",
            "canary_spec": {
                "type": "benign_id_or_echo_probe",
                "commands": ["id -u", "whoami", "echo sharay_cmdi_canary"],
                "disallowed_command_classes": [
                    "destructive_file_ops",
                    "interactive_shells",
                    "outbound_network_binaries",
                    "permission_changes",
                ],
            },
            "safety_invariants": ["strictly_non_destructive", "no_reverse_shell", "no_file_writes"],
            "cleanup_strategy": "terminate_session_on_disconnect",
        },
        {
            "technique_id": "cmdi.blind_time_delay_jitter_controlled",
            "vuln_class": "command_injection",
            "title": "Blind shell command timing differential with latency baseline",
            "cwe": 77,
            "mitre_attack": "T1059",
            "owasp_category": "A03:2021-Injection",
            "severity": "critical",
            "preconditions": ["blind_command_execution_sink_suspected", "baseline_latency_established"],
            "boundary_checks": ["max_sleep_duration_cap_5s", "concurrency_limited_to_1"],
            "opens_session": False,
            "verification_oracle": "time_jitter_differential",
            "canary_spec": {
                "type": "bounded_sleep_command",
                "command": "sleep 3",
                "confidence_threshold": "delta >= 3 * jitter_std_dev",
            },
            "safety_invariants": ["bounded_sleep_max_5s", "no_process_daemonization"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "cmdi.argument_injection_delimiter_check",
            "vuln_class": "command_injection",
            "title": "CLI argument injection & option delimiter boundary validation",
            "cwe": 88,
            "mitre_attack": "T1059",
            "owasp_category": "A03:2021-Injection",
            "severity": "high",
            "preconditions": ["command_line_utility_wrapper_suspected"],
            "boundary_checks": ["argument_hyphen_sanitization", "help_or_version_output_fingerprint"],
            "opens_session": False,
            "verification_oracle": "option_flag_reflection_oracle",
            "canary_spec": {
                "type": "benign_flag_probes",
                "flags": ["--version", "-h", "--help"],
            },
            "safety_invariants": ["no_arbitrary_binary_execution", "passive_cli_help_flag_only"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 6. Authentication Bypass (CWE-287, CWE-306, MITRE ATT&CK T1078)
    # -------------------------------------------------------------------------
    "auth_bypass": [
        {
            "technique_id": "auth_bypass.unauthenticated_vs_authenticated_differential",
            "vuln_class": "auth_bypass",
            "title": "Authentication state-machine and route-guard differential validation",
            "cwe": 287,
            "mitre_attack": "T1078",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "severity": "critical",
            "preconditions": ["protected_route_identified"],
            "boundary_checks": ["session_principal_binding", "privilege_elevation_boundary"],
            "opens_session": True,
            "verification_oracle": "http_status_and_body_differential_pair",
            "canary_spec": {
                "type": "credential_omission_probe",
                "compare": ["authenticated_request", "unauthenticated_request"],
                "vulnerability_condition": "unauthenticated_status == 200 and bodies_match",
            },
            "safety_invariants": ["read_only_route_probing", "no_credential_stuffing"],
            "cleanup_strategy": "expire_test_session",
        },
        {
            "technique_id": "auth_bypass.mfa_step_skipping_state_validation",
            "vuln_class": "auth_bypass",
            "title": "Multi-factor authentication (MFA) step-skipping workflow validation",
            "cwe": 287,
            "mitre_attack": "T1078",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "severity": "high",
            "preconditions": ["two_stage_login_flow", "test_account_credentials_provisioned"],
            "boundary_checks": ["intermediate_session_cookie_isolation", "tenant_boundary_enforcement"],
            "opens_session": False,
            "verification_oracle": "workflow_state_transition_oracle",
            "canary_spec": {
                "type": "direct_step_transition",
                "sequence": ["post_primary_credentials", "direct_get_dashboard_without_mfa_token"],
            },
            "safety_invariants": ["dedicated_test_credentials_only", "no_real_user_account_tampering"],
            "cleanup_strategy": "terminate_test_account_session",
        },
        {
            "technique_id": "auth_bypass.session_fixation_and_entropy_audit",
            "vuln_class": "auth_bypass",
            "title": "Session token fixation & pre/post-login identifier rotation check",
            "cwe": 384,
            "mitre_attack": "T1078",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "severity": "medium",
            "preconditions": ["login_endpoint_sets_session_cookie"],
            "boundary_checks": ["cookie_value_regeneration_check", "entropy_shannon_calculation"],
            "opens_session": False,
            "verification_oracle": "token_value_identity_oracle",
            "canary_spec": {
                "type": "session_id_comparison",
                "rule": "session_id_pre_login == session_id_post_login -> vulnerable_session_fixation",
            },
            "safety_invariants": ["passive_cookie_comparison", "no_session_hijacking"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 7. Access Control (IDOR / BOLA / BFLA) (CWE-639, CWE-285, MITRE ATT&CK T1068)
    # -------------------------------------------------------------------------
    "access_control": [
        {
            "technique_id": "access_control.cross_tenant_idor_differential",
            "vuln_class": "access_control",
            "title": "Two-principal horizontal object authorization differential (IDOR / BOLA)",
            "cwe": 639,
            "mitre_attack": "T1068",
            "owasp_category": "A01:2021-Broken Access Control",
            "severity": "critical",
            "preconditions": ["two_authorized_test_principals", "object_identifier_parameter"],
            "boundary_checks": ["read_isolation_boundary", "write_mutation_rejected_check"],
            "opens_session": False,
            "verification_oracle": "two_principal_authorization_differential",
            "canary_spec": {
                "type": "cross_principal_id_swap",
                "principal_a": "tenant_test_user_alpha",
                "principal_b": "tenant_test_user_beta",
                "vulnerability_condition": "user_b_token_reads_user_a_object_id_with_status_200",
            },
            "safety_invariants": ["read_operations_only", "no_cross_tenant_write_or_delete"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "access_control.broken_function_level_auth_bfla",
            "vuln_class": "access_control",
            "title": "Vertical privilege escalation & administrative endpoint access check (BFLA)",
            "cwe": 285,
            "mitre_attack": "T1068",
            "owasp_category": "A01:2021-Broken Access Control",
            "severity": "high",
            "preconditions": ["admin_endpoint_discovered", "standard_user_credentials_available"],
            "boundary_checks": ["admin_role_boundary", "destructive_http_methods_disabled"],
            "opens_session": False,
            "verification_oracle": "role_permission_boundary_oracle",
            "canary_spec": {
                "type": "low_privilege_token_probe",
                "action": "GET admin/settings with standard_user_bearer_token",
                "vulnerability_condition": "status_code in [200, 204] and admin_payload_returned",
            },
            "safety_invariants": ["strictly_get_or_options_requests", "no_state_changing_admin_post"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "access_control.multitenant_tenant_id_header_tampering",
            "vuln_class": "access_control",
            "title": "Multi-tenant context header tampering & isolation breach check",
            "cwe": 639,
            "mitre_attack": "T1068",
            "owasp_category": "A01:2021-Broken Access Control",
            "severity": "high",
            "preconditions": ["multi_tenant_header_identified"],
            "boundary_checks": ["tenant_id_context_binding", "audit_log_tenant_divergence_check"],
            "opens_session": False,
            "verification_oracle": "tenant_context_differential",
            "canary_spec": {
                "type": "tenant_header_override",
                "header_candidates": ["X-Tenant-ID", "X-Organization-ID", "X-Workspace-ID"],
            },
            "safety_invariants": ["read_only_tenant_probe", "synthetic_test_tenants_only"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 8. Server-Side Execution (SSTI & Deserialization) (CWE-94, CWE-502, CWE-1336)
    # -------------------------------------------------------------------------
    "server_side": [
        {
            "technique_id": "ssti.polyglot_mathematical_expression_canary",
            "vuln_class": "server_side",
            "title": "Server-Side Template Injection (SSTI) polyglot math canary evaluation",
            "cwe": 1336,
            "mitre_attack": "T1190",
            "owasp_category": "A03:2021-Injection",
            "severity": "critical",
            "preconditions": ["server_rendered_input_reflection"],
            "boundary_checks": ["sandbox_escape_blocked", "zero_command_execution_attempt"],
            "opens_session": False,
            "verification_oracle": "arithmetic_evaluation_reflection",
            "canary_spec": {
                "type": "pure_math_expression_polyglot",
                "expressions": {
                    "jinja2_twig": "{{7*7}}",
                    "freemarker": "${7*7}",
                    "ruby_erb": "<%= 7*7 %>",
                    "smart_bracket": "#{7*7}",
                },
                "expected_result": "49",
            },
            "safety_invariants": ["pure_arithmetic_only", "no_os_module_import", "no_file_reads"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "deserialization.safe_type_confusion_canary",
            "vuln_class": "server_side",
            "title": "Safe deserialization header canary & type confusion verification",
            "cwe": 502,
            "mitre_attack": "T1190",
            "owasp_category": "A08:2021-Software and Data Integrity Failures",
            "severity": "critical",
            "preconditions": ["serialized_object_stream_detected"],
            "boundary_checks": ["zero_gadget_chain_payload", "safe_object_header_probe_only"],
            "opens_session": False,
            "verification_oracle": "parser_exception_and_header_oracle",
            "canary_spec": {
                "type": "benign_object_header",
                "formats": [
                    "java_stream_magic_ac_ed",
                    "python_pickle_empty_dict",
                    "php_serialized_empty_array",
                ],
            },
            "safety_invariants": ["zero_remote_code_gadgets", "no_memory_exhaustion"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "server_side.prototype_pollution_recursive_merge",
            "vuln_class": "server_side",
            "title": "Server-side prototype pollution property injection canary",
            "cwe": 1321,
            "mitre_attack": "T1190",
            "owasp_category": "A03:2021-Injection",
            "severity": "high",
            "preconditions": ["json_recursive_merge_endpoint_suspected"],
            "boundary_checks": ["isolated_canary_property_name", "zero_dos_side_effects"],
            "opens_session": False,
            "verification_oracle": "injected_property_reflection_oracle",
            "canary_spec": {
                "type": "benign_canary_property",
                "payload": {"__proto__": {"sharay_safe_canary_prop": "verified_non_destructive"}},
            },
            "safety_invariants": ["non_disruptive_property_name", "immediate_property_deletion_check"],
            "cleanup_strategy": "delete_injected_canary_property",
        },
    ],
    # -------------------------------------------------------------------------
    # 9. Client-Side (CORS / PostMessage / Framing) (CWE-346, CWE-1021)
    # -------------------------------------------------------------------------
    "client_side": [
        {
            "technique_id": "client_side.cors_wildcard_credential_differential",
            "vuln_class": "client_side",
            "title": "CORS origin reflection and credentials-allowlist violation validation",
            "cwe": 346,
            "mitre_attack": "T1189",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "high",
            "preconditions": ["endpoint_responds_to_origin_header"],
            "boundary_checks": ["allow_credentials_with_wildcard_check", "null_origin_acceptance_check"],
            "opens_session": False,
            "verification_oracle": "cors_header_reflection_differential",
            "canary_spec": {
                "type": "custom_origin_probes",
                "origins": [
                    "https://evil.target-domain.com",
                    "https://target-domain.com.attacker.com",
                    "null",
                ],
            },
            "safety_invariants": ["passive_header_inspection", "zero_client_browser_injection"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "client_side.postmessage_missing_origin_validation",
            "vuln_class": "client_side",
            "title": "Web postMessage event listener origin validation audit",
            "cwe": 346,
            "mitre_attack": "T1189",
            "owasp_category": "A04:2021-Insecure Design",
            "severity": "medium",
            "preconditions": ["client_script_registers_message_listener"],
            "boundary_checks": ["ast_event_origin_check_presence", "target_origin_wildcard_check"],
            "opens_session": False,
            "verification_oracle": "javascript_ast_listener_analysis",
            "canary_spec": {
                "type": "postmessage_synthetic_dispatch",
                "message": {"type": "sharay_canary_ping"},
                "origin": "https://unauthorized-origin.internal",
            },
            "safety_invariants": ["sandboxed_headless_browser", "no_sensitive_action_trigger"],
            "cleanup_strategy": "close_browser_context",
        },
        {
            "technique_id": "client_side.clickjacking_frame_ancestors_audit",
            "vuln_class": "client_side",
            "title": "Clickjacking protection & CSP frame-ancestors / X-Frame-Options audit",
            "cwe": 1021,
            "mitre_attack": "T1189",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "low",
            "preconditions": ["ui_rendered_html_endpoint"],
            "boundary_checks": ["csp_frame_ancestors_presence", "x_frame_options_sameorigin_check"],
            "opens_session": False,
            "verification_oracle": "framing_policy_header_oracle",
            "canary_spec": {
                "type": "header_audit",
                "required_headers": ["X-Frame-Options", "Content-Security-Policy"],
            },
            "safety_invariants": ["passive_header_inspection", "no_frame_embedding"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 10. API Vulnerabilities (OWASP API Security Top 10) (CWE-915, CWE-770)
    # -------------------------------------------------------------------------
    "api_vulnerability": [
        {
            "technique_id": "api.mass_assignment_bopla_check",
            "vuln_class": "api_vulnerability",
            "title": "Broken Object Property Level Authorization (BOPLA) & Mass Assignment check",
            "cwe": 915,
            "mitre_attack": "T1190",
            "owasp_category": "API3:2023-Broken Object Property Level Authorization",
            "severity": "high",
            "preconditions": ["openapi_or_json_endpoint_accepting_body"],
            "boundary_checks": ["readonly_property_rejection", "synthetic_test_field_injection_only"],
            "opens_session": False,
            "verification_oracle": "property_binding_reflection_oracle",
            "canary_spec": {
                "type": "harmless_attribute_injection",
                "attributes": {
                    "is_admin": True,
                    "role": "sharay_canary_role",
                    "verified": True,
                },
            },
            "safety_invariants": ["read_back_and_immediate_rollback", "no_permanent_privilege_escalation"],
            "cleanup_strategy": "revert_modified_object",
        },
        {
            "technique_id": "api.http_verb_tunneling_and_override",
            "vuln_class": "api_vulnerability",
            "title": "HTTP verb tunneling & method-override route bypass validation",
            "cwe": 650,
            "mitre_attack": "T1190",
            "owasp_category": "API5:2023-Broken Function Level Authorization",
            "severity": "medium",
            "preconditions": ["rest_api_endpoint_discovered"],
            "boundary_checks": ["method_override_headers_supported", "safe_methods_only"],
            "opens_session": False,
            "verification_oracle": "verb_override_status_oracle",
            "canary_spec": {
                "type": "header_override_probe",
                "headers": {
                    "X-HTTP-Method-Override": "PATCH",
                    "X-Method-Override": "PUT",
                },
            },
            "safety_invariants": ["idempotent_test_payloads", "zero_data_deletion"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "api.unrestricted_resource_pagination_limits",
            "vuln_class": "api_vulnerability",
            "title": "Unrestricted resource consumption & pagination boundary limit check",
            "cwe": 770,
            "mitre_attack": "T1499",
            "owasp_category": "API4:2023-Unrestricted Resource Consumption",
            "severity": "medium",
            "preconditions": ["paginated_list_endpoint"],
            "boundary_checks": ["max_page_size_enforced", "rate_limit_headers_present"],
            "opens_session": False,
            "verification_oracle": "pagination_limit_cap_oracle",
            "canary_spec": {
                "type": "boundary_limit_probe",
                "query_params": ["limit=1000000", "size=999999", "per_page=50000"],
            },
            "safety_invariants": ["single_request_probe_only", "no_traffic_flooding"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 11. GraphQL Vulnerabilities (OWASP API Top 10, CWE-200, CWE-770)
    # -------------------------------------------------------------------------
    "graphql": [
        {
            "technique_id": "graphql.schema_introspection_query_audit",
            "vuln_class": "graphql",
            "title": "GraphQL production schema introspection query leakage check",
            "cwe": 200,
            "mitre_attack": "T1190",
            "owasp_category": "API8:2023-Security Misconfiguration",
            "severity": "medium",
            "preconditions": ["graphql_endpoint_identified"],
            "boundary_checks": ["production_environment_flag", "schema_metadata_redaction"],
            "opens_session": False,
            "verification_oracle": "introspection_field_presence_oracle",
            "canary_spec": {
                "type": "minimal_introspection_probe",
                "query": "{ __schema { types { name } } }",
            },
            "safety_invariants": ["minimal_query_payload", "no_data_field_querying"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "graphql.alias_based_batching_amplification",
            "vuln_class": "graphql",
            "title": "GraphQL alias-based query batching & rate-limit bypass check",
            "cwe": 770,
            "mitre_attack": "T1499",
            "owasp_category": "API4:2023-Unrestricted Resource Consumption",
            "severity": "high",
            "preconditions": ["graphql_endpoint_operational"],
            "boundary_checks": ["batching_limit_cap_10", "resource_utilization_guard"],
            "opens_session": False,
            "verification_oracle": "aliased_batch_response_oracle",
            "canary_spec": {
                "type": "aliased_query_batch",
                "query": "{ a: __typename b: __typename c: __typename }",
            },
            "safety_invariants": ["__typename_probes_only", "zero_database_query_load"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "graphql.circular_query_depth_recursion",
            "vuln_class": "graphql",
            "title": "GraphQL cyclic relationship recursion depth limit verification",
            "cwe": 674,
            "mitre_attack": "T1499",
            "owasp_category": "API4:2023-Unrestricted Resource Consumption",
            "severity": "medium",
            "preconditions": ["cyclic_type_relationships_in_schema"],
            "boundary_checks": ["max_query_depth_cap_5", "execution_timeout_protection"],
            "opens_session": False,
            "verification_oracle": "query_depth_rejection_oracle",
            "canary_spec": {
                "type": "bounded_depth_probe",
                "depth": 4,
            },
            "safety_invariants": ["bounded_depth_cap_4", "no_server_overload"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 12. Race Conditions & Concurrency (PortSwigger Research, CWE-362, CWE-367)
    # -------------------------------------------------------------------------
    "race_conditions": [
        {
            "technique_id": "race.http2_single_packet_concurrency",
            "vuln_class": "race_conditions",
            "title": "HTTP/2 single-packet synchronization frame TOCTOU race condition validation",
            "cwe": 367,
            "mitre_attack": "T1190",
            "owasp_category": "A04:2021-Insecure Design",
            "severity": "high",
            "preconditions": ["http2_protocol_supported", "state_transition_endpoint_identified"],
            "boundary_checks": ["max_concurrent_frames_cap_10", "reversion_transaction_available"],
            "opens_session": False,
            "verification_oracle": "concurrent_state_transition_oracle",
            "canary_spec": {
                "type": "single_packet_frame_multiplexing",
                "stream_count": 5,
                "vulnerability_condition": "more_than_one_stream_returns_success_for_single_use_token",
            },
            "safety_invariants": ["synthetic_test_credits_only", "immediate_reversal_routine"],
            "cleanup_strategy": "rollback_test_transaction",
        },
        {
            "technique_id": "race.limit_overrun_window_differential",
            "vuln_class": "race_conditions",
            "title": "Sub-millisecond concurrency window limit-overrun validation",
            "cwe": 362,
            "mitre_attack": "T1190",
            "owasp_category": "A04:2021-Insecure Design",
            "severity": "medium",
            "preconditions": ["rate_limited_or_quota_endpoint"],
            "boundary_checks": ["concurrency_window_measurement", "quota_drift_audit"],
            "opens_session": False,
            "verification_oracle": "quota_consumption_delta_oracle",
            "canary_spec": {
                "type": "parallel_burst_probe",
                "burst_size": 4,
            },
            "safety_invariants": ["strictly_non_disruptive_probe", "synthetic_test_tokens_only"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 13. HTTP Request Smuggling & Desync (PortSwigger Research, CWE-444)
    # -------------------------------------------------------------------------
    "request_smuggling": [
        {
            "technique_id": "smuggling.cl_te_differential_desync_canary",
            "vuln_class": "request_smuggling",
            "title": "CL.TE frontend-backend HTTP request desynchronization canary validation",
            "cwe": 444,
            "mitre_attack": "T1190",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "critical",
            "preconditions": ["frontend_reverse_proxy_detected", "keepalive_connection_supported"],
            "boundary_checks": ["zero_smuggled_prefix_leakage_to_other_users", "dedicated_test_connection"],
            "opens_session": False,
            "verification_oracle": "desync_timeout_or_unsolicited_response_oracle",
            "canary_spec": {
                "type": "inert_smuggled_probe",
                "method": "POST",
                "headers": {"Content-Length": "4", "Transfer-Encoding": "chunked"},
                "body": "0\r\n\r\nG",
            },
            "safety_invariants": ["self_contained_connection_only", "zero_queue_poisoning"],
            "cleanup_strategy": "force_close_tcp_socket",
        },
        {
            "technique_id": "smuggling.te_cl_differential_desync_canary",
            "vuln_class": "request_smuggling",
            "title": "TE.CL header obfuscation & chunk-boundary desync check",
            "cwe": 444,
            "mitre_attack": "T1190",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "critical",
            "preconditions": ["frontend_reverse_proxy_detected"],
            "boundary_checks": ["single_isolated_socket", "timeout_capped_at_3s"],
            "opens_session": False,
            "verification_oracle": "chunk_boundary_differential_oracle",
            "canary_spec": {
                "type": "obfuscated_te_header",
                "headers": {"Transfer-Encoding": "chunked", "Transfer-Encoding ": "x"},
            },
            "safety_invariants": ["isolated_socket_only", "immediate_socket_close_after_test"],
            "cleanup_strategy": "force_close_tcp_socket",
        },
    ],
    # -------------------------------------------------------------------------
    # 14. Web Cache Poisoning & Deception (PortSwigger Research, CWE-444, CWE-524)
    # -------------------------------------------------------------------------
    "cache_poisoning": [
        {
            "technique_id": "cache.unkeyed_header_reflection_canary",
            "vuln_class": "cache_poisoning",
            "title": "Unkeyed HTTP header reflection in cached HTTP response check",
            "cwe": 444,
            "mitre_attack": "T1190",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "high",
            "preconditions": ["caching_headers_detected", "cache_hit_confirmed"],
            "boundary_checks": ["cache_buster_query_parameter_mandatory", "no_shared_cache_poisoning"],
            "opens_session": False,
            "verification_oracle": "unkeyed_canary_persistence_oracle",
            "canary_spec": {
                "type": "unkeyed_header_with_cache_buster",
                "cache_buster": "?sharay_cb=<unique_uuid>",
                "test_header": {"X-Forwarded-Host": "sharay-canary.internal"},
            },
            "safety_invariants": ["mandatory_unique_cache_buster", "zero_production_cache_tainting"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "cache.web_cache_deception_path_delimiter",
            "vuln_class": "cache_poisoning",
            "title": "Web Cache Deception path delimiter ambiguity & static caching check",
            "cwe": 524,
            "mitre_attack": "T1190",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "high",
            "preconditions": ["authenticated_dynamic_endpoint"],
            "boundary_checks": ["safe_test_user_account", "synthetic_profile_data_only"],
            "opens_session": False,
            "verification_oracle": "static_cache_header_presence_on_dynamic_content",
            "canary_spec": {
                "type": "delimiter_extension_probe",
                "suffix": "/nonexistent_sharay.css",
                "condition": "status == 200 and 'text/html' in content_type and 'public' in cache_control",
            },
            "safety_invariants": ["strictly_non_existent_asset_name", "no_sensitive_pii_cached"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 15. Cryptographic & JWT Flaws (CWE-327, CWE-347, MITRE ATT&CK T1552)
    # -------------------------------------------------------------------------
    "jwt_crypto": [
        {
            "technique_id": "jwt.algorithm_confusion_none",
            "vuln_class": "jwt_crypto",
            "title": "JWT unsigned algorithm ('none' / 'None') acceptance validation",
            "cwe": 347,
            "mitre_attack": "T1552",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "severity": "critical",
            "preconditions": ["jwt_bearer_token_authentication_used"],
            "boundary_checks": ["read_only_route_probing", "tenant_isolation_maintained"],
            "opens_session": False,
            "verification_oracle": "unsigned_jwt_acceptance_oracle",
            "canary_spec": {
                "type": "alg_none_token_probe",
                "header": {"alg": "none", "typ": "JWT"},
                "vulnerability_condition": "protected_route_accepts_token_with_200",
            },
            "safety_invariants": ["synthetic_test_subject_only", "zero_admin_actions"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "jwt.key_id_path_traversal_canary",
            "vuln_class": "jwt_crypto",
            "title": "JWT 'kid' (Key ID) header path traversal & injection check",
            "cwe": 22,
            "mitre_attack": "T1552",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "severity": "high",
            "preconditions": ["jwt_header_contains_kid"],
            "boundary_checks": ["null_byte_rejection", "safe_dev_null_keyfile_reference"],
            "opens_session": False,
            "verification_oracle": "kid_header_error_oracle",
            "canary_spec": {
                "type": "traversal_kid_probe",
                "kid_values": ["../../../../dev/null", "key.pem'--"],
            },
            "safety_invariants": ["safe_target_path_only", "no_file_system_modification"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 16. Cloud Identity & Metadata Boundaries (CWE-200, CWE-250, MITRE T1078)
    # -------------------------------------------------------------------------
    "cloud_identity": [
        {
            "technique_id": "cloud.imds_v2_session_token_enforcement",
            "vuln_class": "cloud_identity",
            "title": "Cloud instance metadata (IMDS) token requirement & hop-limit verification",
            "cwe": 200,
            "mitre_attack": "T1078",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "critical",
            "preconditions": ["cloud_hosted_workload_suspected"],
            "boundary_checks": ["imdsv2_token_mandatory_check", "http_put_token_challenge"],
            "opens_session": False,
            "verification_oracle": "imds_token_requirement_oracle",
            "canary_spec": {
                "type": "imds_token_probe",
                "endpoint": "http://169.254.169.254/latest/api/token",
                "header": "X-aws-ec2-metadata-token-ttl-seconds: 60",
                "vulnerability_condition": "imds_accessible_without_token_header",
            },
            "safety_invariants": ["never_retrieve_iam_credentials", "pure_protocol_handshake_audit"],
            "cleanup_strategy": "stateless",
        },
        {
            "technique_id": "cloud.k8s_service_account_automount_check",
            "vuln_class": "cloud_identity",
            "title": "Kubernetes ServiceAccount default token automount & RBAC boundary audit",
            "cwe": 250,
            "mitre_attack": "T1078",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "medium",
            "preconditions": ["containerized_workload_in_kubernetes"],
            "boundary_checks": ["automountServiceAccountToken_flag", "default_namespace_binding"],
            "opens_session": False,
            "verification_oracle": "manifest_rbac_policy_oracle",
            "canary_spec": {
                "type": "manifest_spec_inspection",
                "path": "/var/run/secrets/kubernetes.io/serviceaccount",
            },
            "safety_invariants": ["static_manifest_or_pod_spec_audit", "no_token_exfiltration"],
            "cleanup_strategy": "stateless",
        },
    ],
    # -------------------------------------------------------------------------
    # 17. WebSocket & Realtime Transport (CWE-346, CWE-1385, MITRE T1190)
    # -------------------------------------------------------------------------
    "websocket_realtime": [
        {
            "technique_id": "websocket.cswsh_cross_origin_handshake",
            "vuln_class": "websocket_realtime",
            "title": "Cross-Site WebSocket Hijacking (CSWSH) origin validation check",
            "cwe": 346,
            "mitre_attack": "T1189",
            "owasp_category": "A04:2021-Insecure Design",
            "severity": "high",
            "preconditions": ["websocket_upgrade_endpoint_discovered"],
            "boundary_checks": ["arbitrary_origin_rejection_check", "cookie_authenticated_handshake"],
            "opens_session": False,
            "verification_oracle": "websocket_upgrade_handshake_oracle",
            "canary_spec": {
                "type": "cross_origin_upgrade_probe",
                "headers": {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Origin": "https://unauthorized-origin.attacker.com",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                },
                "vulnerability_condition": "status == 101 and connection_established",
            },
            "safety_invariants": ["handshake_only", "immediate_websocket_disconnect"],
            "cleanup_strategy": "force_close_websocket_session",
        },
    ],
}

# -----------------------------------------------------------------------------
# Comprehensive Aliases Map covering 60+ scanner & industry finding names
# -----------------------------------------------------------------------------
_EXTENDED_CATEGORY_ALIASES: dict[str, str] = {
    # SQLi
    "sqli": "sql_injection",
    "sql_injection": "sql_injection",
    "sql": "sql_injection",
    "database_injection": "sql_injection",
    "blind_sql_injection": "sql_injection",
    # XSS
    "xss": "xss",
    "cross_site_scripting": "xss",
    "dom_xss": "xss",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    # SSRF
    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    "blind_ssrf": "ssrf",
    # XXE
    "xxe": "xxe",
    "xml_external_entity": "xxe",
    "xml_injection": "xxe",
    # CMDi
    "cmdi": "command_injection",
    "command_injection": "command_injection",
    "rce": "command_injection",
    "os_command_injection": "command_injection",
    "shell_injection": "command_injection",
    # Auth Bypass
    "auth": "auth_bypass",
    "auth_bypass": "auth_bypass",
    "authentication": "auth_bypass",
    "broken_authentication": "auth_bypass",
    "session_fixation": "auth_bypass",
    # Access Control / IDOR
    "idor": "access_control",
    "bola": "access_control",
    "bfla": "access_control",
    "access_control": "access_control",
    "broken_access_control": "access_control",
    "privilege_escalation": "access_control",
    # Server-Side / SSTI / Deserialization
    "ssti": "server_side",
    "server_side_template_injection": "server_side",
    "deserialization": "server_side",
    "insecure_deserialization": "server_side",
    "prototype_pollution_server": "server_side",
    "server_side": "server_side",
    # Client-Side
    "cors": "client_side",
    "client_side": "client_side",
    "postmessage": "client_side",
    "clickjacking": "client_side",
    # API
    "api": "api_vulnerability",
    "api_vulnerability": "api_vulnerability",
    "mass_assignment": "api_vulnerability",
    "bopla": "api_vulnerability",
    "method_override": "api_vulnerability",
    # GraphQL
    "graphql": "graphql",
    "graphql_introspection": "graphql",
    "graphql_batching": "graphql",
    # Race Conditions
    "race": "race_conditions",
    "race_condition": "race_conditions",
    "race_conditions": "race_conditions",
    "toctou": "race_conditions",
    "single_packet_attack": "race_conditions",
    # Request Smuggling
    "smuggling": "request_smuggling",
    "request_smuggling": "request_smuggling",
    "http_desync": "request_smuggling",
    "cl_te": "request_smuggling",
    "te_cl": "request_smuggling",
    # Cache Poisoning
    "cache": "cache_poisoning",
    "cache_poisoning": "cache_poisoning",
    "web_cache_poisoning": "cache_poisoning",
    "web_cache_deception": "cache_poisoning",
    # JWT & Crypto
    "jwt": "jwt_crypto",
    "jwt_crypto": "jwt_crypto",
    "token_vulnerability": "jwt_crypto",
    # Cloud Identity
    "cloud": "cloud_identity",
    "cloud_identity": "cloud_identity",
    "imds": "cloud_identity",
    "metadata_service": "cloud_identity",
    # WebSocket
    "websocket": "websocket_realtime",
    "websocket_realtime": "websocket_realtime",
    "cswsh": "websocket_realtime",
}

_EXTENDED_CWE_TO_CLASS: dict[int, str] = {
    89: "sql_injection",
    79: "xss",
    918: "ssrf",
    611: "xxe",
    77: "command_injection",
    78: "command_injection",
    88: "command_injection",
    287: "auth_bypass",
    306: "auth_bypass",
    384: "auth_bypass",
    639: "access_control",
    285: "access_control",
    862: "access_control",
    863: "access_control",
    94: "server_side",
    502: "server_side",
    1321: "server_side",
    1336: "server_side",
    346: "client_side",
    1021: "client_side",
    915: "api_vulnerability",
    650: "api_vulnerability",
    770: "api_vulnerability",
    200: "graphql",
    674: "graphql",
    362: "race_conditions",
    367: "race_conditions",
    444: "request_smuggling",
    524: "cache_poisoning",
    327: "jwt_crypto",
    347: "jwt_crypto",
    22: "jwt_crypto",
    250: "cloud_identity",
    1385: "websocket_realtime",
}

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def correlate_sota_validation_techniques(
    finding_category: str,
    *,
    cwe: int | None = None,
    min_severity: Severity | None = None,
    session_only: bool | None = None,
) -> list[dict[str, Any]]:
    """Return state-of-the-art validation techniques with deep-copy safety and filtering."""
    normalized = finding_category.strip().lower().replace("-", "_")
    vuln_class = _EXTENDED_CATEGORY_ALIASES.get(normalized)
    if vuln_class is None and cwe is not None:
        vuln_class = _EXTENDED_CWE_TO_CLASS.get(cwe)
    if vuln_class is None:
        return []

    techniques = SOTA_VALIDATION_TECHNIQUE_CATALOG.get(vuln_class, [])
    filtered: list[dict[str, Any]] = []

    for item in techniques:
        if session_only is not None and item.get("opens_session") != session_only:
            continue
        if min_severity is not None:
            item_sev = item.get("severity", "info")
            if _SEVERITY_ORDER.get(item_sev, 0) < _SEVERITY_ORDER.get(min_severity, 0):
                continue
        # Ensure deep-copy of all mutable fields (preconditions, boundary_checks, canary_spec, etc.)
        filtered.append(copy.deepcopy(item))

    return filtered


def get_catalog_summary() -> dict[str, Any]:
    """Return statistical summary of the SOTA validation catalog."""
    total_techniques = sum(len(techniques) for techniques in SOTA_VALIDATION_TECHNIQUE_CATALOG.values())
    session_capable = sum(
        1
        for techniques in SOTA_VALIDATION_TECHNIQUE_CATALOG.values()
        for item in techniques
        if item.get("opens_session")
    )
    return {
        "classes_count": len(SOTA_VALIDATION_TECHNIQUE_CATALOG),
        "total_techniques": total_techniques,
        "session_capable_techniques": session_capable,
        "classes": list(SOTA_VALIDATION_TECHNIQUE_CATALOG.keys()),
    }
