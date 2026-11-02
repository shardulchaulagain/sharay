"""Metasploit catalog/auxiliary/session parser and 10-class vulnerability validation catalog (L5/L6/L7).

Parser only: no Metasploit command line is built and nothing has run here. Uses the strict
parsing helpers from `packages.scanner_adapters.integrations._parsing` (no repair, fixed
`ValueError` messages, redaction via `shown`/`label`, and the `MAX_FINDINGS`/`MAX_REPORT_BYTES`
caps). The module catalog and auxiliary report cover inventory and reviewed non-intrusive
checks only; unrestricted shell/console access is never represented here.
Structure adapted from Gemini's reviewed draft.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
from typing import Any

from packages.scanner_adapters.integrations._parsing import (
    MAX_FINDINGS,
    fingerprint,
    http_location,
    label,
    load_json,
    port_suffix,
    shown,
    text,
)

ALLOWED_MODULE_TYPES = {"auxiliary", "post", "exploit", "exploit_check_only", "payload"}
ALLOWED_RANKS = {"manual", "low", "average", "normal", "good", "great", "excellent"}
ALLOWED_OUTCOMES = {
    "confirmed_reproducible",
    "suspected",
    "validation_failed",
    "not_applicable",
}
ALLOWED_SESSION_TYPES = {"shell", "meterpreter", "http_diagnostic", "ssh", "sql_readonly"}
_MODULE_NAME = re.compile(r"^[a-z0-9_]+(?:/[a-z0-9_.-]+){1,8}$")
_CVE_OR_CWE = re.compile(r"^(?:CVE-\d{4}-\d{4,7}|CWE-\d{1,5})$")

VALIDATION_TECHNIQUE_CATALOG: dict[str, list[dict[str, Any]]] = {
    "sql_injection": [
        {
            "technique_id": "sqli.boolean_differential_pair",
            "vuln_class": "sql_injection",
            "title": "Boolean-based differential response validation",
            "preconditions": ["identifiable_query_parameter", "deterministic_baseline_response"],
            "boundary_checks": ["current_db_user_privilege_read", "write_capability_denied_check"],
            "opens_session": False,
        },
        {
            "technique_id": "sqli.readonly_catalog_session",
            "vuln_class": "sql_injection",
            "title": "Read-only metadata catalog inspection session",
            "preconditions": ["confirmed_boolean_or_union_sqli", "authorized_session_policy"],
            "boundary_checks": ["information_schema_scope", "cross_tenant_table_visibility"],
            "opens_session": True,
        },
    ],
    "xss": [
        {
            "technique_id": "xss.context_reflection_canary",
            "vuln_class": "xss",
            "title": "Non-executing DOM/HTML context reflection & sink verification",
            "preconditions": ["reflected_or_stored_input_vector"],
            "boundary_checks": ["csp_policy_evaluation", "httponly_cookie_exposure_check"],
            "opens_session": False,
        }
    ],
    "ssrf": [
        {
            "technique_id": "ssrf.loopback_and_metadata_boundary",
            "vuln_class": "ssrf",
            "title": "Controlled loopback and cloud metadata boundary validation",
            "preconditions": ["url_or_webhook_fetch_parameter"],
            "boundary_checks": ["loopback_port_reachability", "imds_hop_limit_and_token_enforcement"],
            "opens_session": True,
        }
    ],
    "xxe": [
        {
            "technique_id": "xxe.local_dtd_parameter_entity_check",
            "vuln_class": "xxe",
            "title": "Non-destructive XML entity expansion & external DTD disabled check",
            "preconditions": ["xml_or_soap_or_svg_input_endpoint"],
            "boundary_checks": ["external_general_entities_state", "file_uri_resolution_blocked"],
            "opens_session": False,
        }
    ],
    "command_injection": [
        {
            "technique_id": "cmdi.benign_subshell_identity_probe",
            "vuln_class": "command_injection",
            "title": "Bounded benign command-execution context & UID/GID verification",
            "preconditions": ["os_argument_or_shell_sink_suspected"],
            "boundary_checks": ["effective_uid_gid_inspection", "container_namespace_isolation_check"],
            "opens_session": True,
        }
    ],
    "auth_bypass": [
        {
            "technique_id": "auth_bypass.unauthenticated_vs_authenticated_differential",
            "vuln_class": "auth_bypass",
            "title": "Authentication state-machine and token-verification bypass check",
            "preconditions": ["protected_route_identified"],
            "boundary_checks": ["session_principal_binding", "privilege_elevation_boundary"],
            "opens_session": True,
        }
    ],
    "access_control": [
        {
            "technique_id": "access_control.cross_tenant_idor_differential",
            "vuln_class": "access_control",
            "title": "Two-principal horizontal/vertical object authorization check (IDOR/BOLA)",
            "preconditions": ["two_authorized_test_principals", "object_identifier_parameter"],
            "boundary_checks": ["read_isolation_boundary", "write_mutation_rejected_check"],
            "opens_session": False,
        }
    ],
    "server_side": [
        {
            "technique_id": "server_side.template_and_deserialization_canary",
            "vuln_class": "server_side",
            "title": "Server-side template evaluation & safe deserialization canary check",
            "preconditions": ["server_rendered_or_serialized_input"],
            "boundary_checks": ["sandbox_escape_blocked", "environment_variable_redacted_check"],
            "opens_session": False,
        }
    ],
    "client_side": [
        {
            "technique_id": "client_side.cors_and_postmessage_origin_check",
            "vuln_class": "client_side",
            "title": "CORS origin reflection and postMessage origin-validation check",
            "preconditions": ["browser_accessible_endpoint"],
            "boundary_checks": ["allow_credentials_with_wildcard_check", "frame_ancestors_enforcement"],
            "opens_session": False,
        }
    ],
    "api_vulnerability": [
        {
            "technique_id": "api.mass_assignment_and_schema_drift_check",
            "vuln_class": "api_vulnerability",
            "title": "OpenAPI undocumented field binding (BOPLA) and method-override validation",
            "preconditions": ["openapi_or_json_endpoint"],
            "boundary_checks": ["readonly_property_rejection", "rate_limit_header_enforcement"],
            "opens_session": False,
        }
    ],
    "path_traversal": [
        {
            "technique_id": "path_traversal.canonicalised_boundary_read",
            "vuln_class": "path_traversal",
            "title": "Canonicalised path-escape boundary read check",
            "preconditions": ["file_or_path_parameter"],
            "boundary_checks": ["stays_within_document_root", "encoded_dot_segment_rejected"],
            "opens_session": False,
        }
    ],
    "open_redirect": [
        {
            "technique_id": "open_redirect.offsite_target_reflection",
            "vuln_class": "open_redirect",
            "title": "Off-site redirect target reflection check",
            "preconditions": ["redirect_or_return_url_parameter"],
            "boundary_checks": ["offsite_host_allowed", "scheme_downgrade_allowed"],
            "opens_session": False,
        }
    ],
    "request_smuggling": [
        {
            "technique_id": "request_smuggling.cl_te_differential",
            "vuln_class": "request_smuggling",
            "title": "CL.TE / TE.CL non-destructive framing differential",
            "preconditions": ["front_and_back_end_proxy_chain"],
            "boundary_checks": ["header_framing_agreement", "no_cross_request_poisoning"],
            "opens_session": False,
        }
    ],
    "csrf": [
        {
            "technique_id": "csrf.state_change_without_token",
            "vuln_class": "csrf",
            "title": "State-changing request without anti-CSRF token check",
            "preconditions": ["cookie_authenticated_state_changing_endpoint"],
            "boundary_checks": ["anti_csrf_token_required", "samesite_cookie_enforced"],
            "opens_session": False,
        }
    ],
    "clickjacking": [
        {
            "technique_id": "clickjacking.framing_policy_check",
            "vuln_class": "clickjacking",
            "title": "Framing-policy (X-Frame-Options / frame-ancestors) check",
            "preconditions": ["browser_rendered_authenticated_view"],
            "boundary_checks": ["frame_ancestors_restrictive", "x_frame_options_present"],
            "opens_session": False,
        }
    ],
    "prototype_pollution": [
        {
            "technique_id": "prototype_pollution.proto_key_canary",
            "vuln_class": "prototype_pollution",
            "title": "Non-destructive __proto__/constructor key-injection canary",
            "preconditions": ["json_or_query_merge_into_object"],
            "boundary_checks": ["prototype_not_mutated", "no_cross_request_persistence"],
            "opens_session": False,
        }
    ],
}

_CATEGORY_ALIASES: dict[str, str] = {
    "sqli": "sql_injection",
    "sql_injection": "sql_injection",
    "xss": "xss",
    "cross_site_scripting": "xss",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "cmdi": "command_injection",
    "command_injection": "command_injection",
    "rce": "command_injection",
    "auth": "auth_bypass",
    "auth_bypass": "auth_bypass",
    "idor": "access_control",
    "bola": "access_control",
    "access_control": "access_control",
    "ssti": "server_side",
    "server_side": "server_side",
    "cors": "client_side",
    "client_side": "client_side",
    "api": "api_vulnerability",
    "api_vulnerability": "api_vulnerability",
    "path_traversal": "path_traversal",
    "lfi": "path_traversal",
    "directory_traversal": "path_traversal",
    "open_redirect": "open_redirect",
    "redirect": "open_redirect",
    "request_smuggling": "request_smuggling",
    "http_smuggling": "request_smuggling",
    "csrf": "csrf",
    "clickjacking": "clickjacking",
    "ui_redress": "clickjacking",
    "prototype_pollution": "prototype_pollution",
    "proto": "prototype_pollution",
}

_CWE_TO_CLASS: dict[int, str] = {
    89: "sql_injection",
    79: "xss",
    918: "ssrf",
    611: "xxe",
    77: "command_injection",
    78: "command_injection",
    287: "auth_bypass",
    306: "auth_bypass",
    639: "access_control",
    862: "access_control",
    863: "access_control",
    94: "server_side",
    502: "server_side",
    1336: "server_side",
    346: "client_side",
    915: "api_vulnerability",
    22: "path_traversal",
    23: "path_traversal",
    36: "path_traversal",
    601: "open_redirect",
    444: "request_smuggling",
    352: "csrf",
    1021: "clickjacking",
    1321: "prototype_pollution",
}


def correlate_validation_techniques(
    finding_category: str,
    *,
    cwe: int | None = None,
) -> list[dict[str, Any]]:
    """Return approved validation techniques for a finding category or CWE number."""
    normalized = finding_category.strip().lower().replace("-", "_")
    vuln_class = _CATEGORY_ALIASES.get(normalized)
    if vuln_class is None and cwe is not None:
        vuln_class = _CWE_TO_CLASS.get(cwe)
    if vuln_class is None:
        return []
    # Deep-copy the mutable lists so a caller editing the result cannot mutate the module catalog.
    return [
        {
            **item,
            "preconditions": list(item["preconditions"]),
            "boundary_checks": list(item["boundary_checks"]),
        }
        for item in VALIDATION_TECHNIQUE_CATALOG.get(vuln_class, [])
    ]


def _module_fullname(value: Any) -> str:
    raw = text(value, "Metasploit module fullname", 160)
    if not _MODULE_NAME.match(raw) or any(seg in (".", "..") for seg in raw.split("/")):
        raise ValueError("Metasploit module fullname is invalid.")
    return raw


def _target_endpoint(host_val: Any, port_val: Any, what: str) -> str:
    raw_host = text(host_val, f"{what} host", 253)
    try:
        addr = ipaddress.ip_address(raw_host)
    except ValueError:
        raise ValueError(f"{what} host is not an IP address.") from None
    if type(port_val) is not int:
        raise ValueError(f"{what} port is not an integer.")
    suffix = port_suffix(port_val, what)
    return f"[{addr}]{suffix}" if addr.version == 6 else f"{addr}{suffix}"


def parse_metasploit_catalog(data: bytes) -> dict[str, Any]:
    """Parse `metasploit.catalog` JSON output into bounded, secret-redacted catalog entries."""
    doc = load_json(data, "Metasploit catalog")
    if not isinstance(doc, dict) or not isinstance(doc.get("modules"), list):
        raise ValueError("Metasploit catalog must be an object with a modules list.")
    raw_modules = doc["modules"]
    modules: list[dict[str, Any]] = []
    for entry in raw_modules:
        if not isinstance(entry, dict):
            raise ValueError("Metasploit catalog entry is not an object.")
        fullname = _module_fullname(entry.get("fullname"))
        mtype = text(entry.get("type"), "Metasploit module type", 40)
        if mtype not in ALLOWED_MODULE_TYPES:
            raise ValueError("Metasploit module type is not permitted in catalog.")
        rank = text(entry.get("rank"), "Metasploit module rank", 20)
        if rank not in ALLOWED_RANKS:
            raise ValueError("Metasploit module rank is invalid.")
        check_supported = entry.get("check_supported")
        if type(check_supported) is not bool:
            raise ValueError("Metasploit check_supported must be a boolean.")
        refs_raw = entry.get("references", [])
        if not isinstance(refs_raw, list) or len(refs_raw) > 50:
            raise ValueError("Metasploit references must be a bounded list.")
        refs: list[str] = []
        for ref in refs_raw:
            ref_str = text(ref, "Metasploit reference", 40)
            if not _CVE_OR_CWE.match(ref_str):
                raise ValueError("Metasploit reference must be CVE-YYYY-NNNN or CWE-N.")
            refs.append(ref_str)
        if len(modules) < MAX_FINDINGS:
            modules.append(
                {
                    "fullname": shown(fullname),
                    "type": mtype,
                    "rank": rank,
                    "name": label(entry.get("name")) or shown(fullname),
                    "check_supported": check_supported,
                    "references": refs,
                    "fingerprint": fingerprint("msf_catalog", fullname, mtype),
                }
            )
    return {"modules": modules, "truncated": len(raw_modules) > MAX_FINDINGS}


def parse_metasploit_auxiliary_report(data: bytes) -> dict[str, Any]:
    """Parse `metasploit.approved_auxiliary` structured verification output."""
    doc = load_json(data, "Metasploit auxiliary report")
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        raise ValueError("Metasploit auxiliary report must contain a results list.")
    raw_results = doc["results"]
    findings: list[dict[str, Any]] = []
    for item in raw_results:
        if not isinstance(item, dict):
            raise ValueError("Metasploit auxiliary result is not an object.")
        module = _module_fullname(item.get("module"))
        outcome = text(item.get("outcome"), "Metasploit auxiliary outcome", 40)
        if outcome not in ALLOWED_OUTCOMES:
            raise ValueError("Metasploit auxiliary outcome is invalid.")
        if "target_url" in item and item["target_url"] is not None:
            locator = http_location(item.get("target_url"), "Metasploit target_url")
        else:
            locator = _target_endpoint(item.get("target_host"), item.get("target_port"), "Metasploit target")
        session_established = item.get("session_established", False)
        if type(session_established) is not bool:
            raise ValueError("Metasploit session_established must be a boolean.")
        if len(findings) < MAX_FINDINGS:
            findings.append(
                {
                    "module": shown(module),
                    "locator": shown(locator),
                    "outcome": outcome,
                    "session_established": session_established,
                    "summary": label(item.get("summary")) or shown(module),
                    "fingerprint": fingerprint("msf_aux", module, locator),
                }
            )
    return {"findings": findings, "truncated": len(raw_results) > MAX_FINDINGS}


def parse_metasploit_sessions(data: bytes) -> dict[str, Any]:
    """Parse bounded diagnostic session inventory from Metasploit RPC/JSON output."""
    doc = load_json(data, "Metasploit session report")
    if not isinstance(doc, dict) or not isinstance(doc.get("sessions"), list):
        raise ValueError("Metasploit session report must contain a sessions list.")
    raw_sessions = doc["sessions"]
    sessions: list[dict[str, Any]] = []
    for item in raw_sessions:
        if not isinstance(item, dict):
            raise ValueError("Metasploit session entry is not an object.")
        session_id = text(item.get("session_id"), "Metasploit session_id", 64)
        session_type = text(item.get("session_type"), "Metasploit session_type", 40)
        if session_type not in ALLOWED_SESSION_TYPES:
            raise ValueError("Metasploit session_type is not permitted.")
        via_module = _module_fullname(item.get("via_module"))
        peer = _target_endpoint(item.get("peer_host"), item.get("peer_port"), "Metasploit session peer")
        opened_at = item.get("opened_at")
        last_checkin = item.get("last_checkin")
        if (
            not isinstance(opened_at, (int, float))
            or isinstance(opened_at, bool)
            or not isinstance(last_checkin, (int, float))
            or isinstance(last_checkin, bool)
            or (isinstance(opened_at, float) and math.isnan(opened_at))
            or (isinstance(last_checkin, float) and math.isnan(last_checkin))
        ):
            raise ValueError("Metasploit session timestamps must be numbers.")
        # Bound to [0, ~year 2286] before any float math, so a 401-digit int or 1e308 is refused
        # here instead of raising OverflowError or yielding an unbounded duration.
        if not (0 <= opened_at <= last_checkin <= 10_000_000_000):
            raise ValueError("Metasploit session timestamps are out of range or order.")
        duration = round(float(last_checkin - opened_at), 3)
        if len(sessions) < MAX_FINDINGS:
            sessions.append(
                {
                    "session_id": shown(session_id),
                    "session_type": session_type,
                    "via_module": shown(via_module),
                    "peer": shown(peer),
                    "privilege_user": label(item.get("privilege_user"), 80),
                    "duration_seconds": duration,
                    "fingerprint": fingerprint("msf_session", session_id, via_module, peer),
                }
            )
    return {"sessions": sessions, "truncated": len(raw_sessions) > MAX_FINDINGS}


METASPLOIT_OFFENSIVE_CATALOG: list[dict[str, Any]] = [
    {
        "fullname": "exploit/multi/http/log4j_header_injection",
        "cve": "CVE-2021-44228",
        "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "cmd/unix/reverse_bash",
        "options": {"HTTP_METHOD": "GET"},
        "tags": ["log4j", "log4shell", "jndi", "cve-2021-44228"],
    },
    {
        "fullname": "exploit/multi/http/spring_framework_rce_spring4shell",
        "cve": "CVE-2022-22965",
        "title": "Spring Framework ClassLoader Data Binding RCE (Spring4Shell)",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "java/jsp_shell_reverse_tcp",
        "options": {},
        "tags": ["spring", "spring4shell", "classloader", "cve-2022-22965"],
    },
    {
        "fullname": "exploit/multi/http/apache_activemq_upload_jsp",
        "cve": "CVE-2023-46604",
        "title": "Apache ActiveMQ OpenWire Protocol Unmarshaling RCE",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "java/meterpreter/reverse_tcp",
        "options": {},
        "tags": ["activemq", "openwire", "cve-2023-46604"],
    },
    {
        "fullname": "exploit/multi/http/struts2_content_type_ognl",
        "cve": "CVE-2017-5638",
        "title": "Apache Struts 2 Jakarta Multipart Parser OGNL Injection",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "cmd/unix/reverse_bash",
        "options": {},
        "tags": ["struts", "struts2", "ognl", "cve-2017-5638"],
    },
    {
        "fullname": "exploit/unix/webapp/webmin_backdoor",
        "cve": "CVE-2019-15107",
        "title": "Webmin password_change.cgi Backdoor Remote Command Execution",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "cmd/unix/reverse_perl",
        "options": {},
        "tags": ["webmin", "backdoor", "cve-2019-15107"],
    },
    {
        "fullname": "exploit/unix/webapp/drupal_drupalgeddon2",
        "cve": "CVE-2018-7600",
        "title": "Drupal core Form API Remote Code Execution (Drupalgeddon 2)",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "php/meterpreter/reverse_tcp",
        "options": {},
        "tags": ["drupal", "drupalgeddon", "cve-2018-7600"],
    },
    {
        "fullname": "exploit/multi/http/confluence_widget_connector",
        "cve": "CVE-2021-26084",
        "title": "Atlassian Confluence Server OGNL Injection",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "java/jsp_shell_reverse_tcp",
        "options": {},
        "tags": ["confluence", "atlassian", "ognl", "cve-2021-26084"],
    },
    {
        "fullname": "exploit/multi/http/gitlab_file_read_rce",
        "cve": "CVE-2021-22205",
        "title": "GitLab Workhorse Unauthenticated Remote Code Execution",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "cmd/unix/reverse_bash",
        "options": {},
        "tags": ["gitlab", "exiftool", "cve-2021-22205"],
    },
    {
        "fullname": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "cve": "CVE-2014-6271",
        "title": "Apache mod_cgi Bash Environment Variable Injection (Shellshock)",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "cmd/unix/reverse_bash",
        "options": {},
        "tags": ["shellshock", "mod_cgi", "cve-2014-6271"],
    },
    {
        "fullname": "exploit/multi/http/php_cgi_arg_injection",
        "cve": "CVE-2024-4577",
        "title": "PHP-CGI Windows Argument Injection RCE",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "php/meterpreter/reverse_tcp",
        "options": {},
        "tags": ["php-cgi", "php_cgi", "cve-2024-4577", "cve-2012-1823"],
    },
    {
        "fullname": "exploit/multi/http/tomcat_mgr_upload",
        "cve": None,
        "title": "Apache Tomcat Application Manager Authenticated Upload Code Execution",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "java/meterpreter/reverse_tcp",
        "options": {},
        "tags": ["tomcat", "tomcat_mgr"],
    },
    {
        "fullname": "exploit/unix/webapp/wp_admin_shell_upload",
        "cve": None,
        "title": "WordPress Admin Plugin/Theme Upload Shell Execution",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "php/meterpreter/reverse_tcp",
        "options": {},
        "tags": ["wordpress", "wp-admin", "wp_admin"],
    },
    {
        "fullname": "exploit/multi/http/jenkins_metaprogramming",
        "cve": "CVE-2019-1003000",
        "title": "Jenkins Pipeline Metaprogramming Groovy Script RCE",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "java/meterpreter/reverse_tcp",
        "options": {},
        "tags": ["jenkins", "groovy", "cve-2019-1003000"],
    },
    {
        "fullname": "exploit/windows/smb/ms17_010_eternalblue",
        "cve": "CVE-2017-0144",
        "title": "Microsoft SMBv1 Remote Code Execution (EternalBlue)",
        "rank": "great",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "windows/x64/meterpreter/reverse_tcp",
        "options": {},
        "tags": ["eternalblue", "ms17-010", "ms17_010", "cve-2017-0144"],
    },
    {
        "fullname": "auxiliary/admin/dcerpc/cve_2020_1472_zerologon",
        "cve": "CVE-2020-1472",
        "title": "Microsoft Active Directory Netlogon Elevation of Privilege (Zerologon)",
        "rank": "normal",
        "type": "auxiliary",
        "default_action": "run",
        "recommended_payload": None,
        "options": {},
        "tags": ["zerologon", "netlogon", "cve-2020-1472"],
    },
    {
        "fullname": "auxiliary/gather/pulse_secure_file_leak",
        "cve": "CVE-2019-11510",
        "title": "Pulse Secure Connect SSL VPN Arbitrary File Disclosure",
        "rank": "normal",
        "type": "auxiliary",
        "default_action": "run",
        "recommended_payload": None,
        "options": {},
        "tags": ["pulse_secure", "pulsesecure", "cve-2019-11510"],
    },
    {
        "fullname": "auxiliary/scanner/http/blind_sql_query",
        "cve": None,
        "title": "Blind SQL Injection Extraction Probe",
        "rank": "normal",
        "type": "auxiliary",
        "default_action": "run",
        "recommended_payload": None,
        "options": {},
        "tags": ["blind_sql", "sql_injection", "sqli", "cwe-89"],
    },
    {
        "fullname": "exploit/multi/http/generic_http_exec",
        "cve": None,
        "title": "Generic HTTP Command Injection Remote Code Execution",
        "rank": "excellent",
        "type": "exploit",
        "default_action": "check",
        "recommended_payload": "cmd/unix/reverse_bash",
        "options": {},
        "tags": ["command_injection", "cmd_exec", "cmdi", "cwe-78"],
    },
    {
        "fullname": "post/multi/gather/env",
        "cve": None,
        "title": "Multi-Platform Environment Variable Collection",
        "rank": "normal",
        "type": "post",
        "default_action": "run",
        "recommended_payload": None,
        "options": {},
        "tags": ["gather_env", "env_vars"],
    },
    {
        "fullname": "post/linux/gather/enum_network",
        "cve": None,
        "title": "Linux Network Configuration and Interface Enumeration",
        "rank": "normal",
        "type": "post",
        "default_action": "run",
        "recommended_payload": None,
        "options": {},
        "tags": ["enum_network", "network_interfaces"],
    },
]


def resolve_metasploit_exploit(
    *,
    cve: str | None = None,
    category: str = "",
    title: str = "",
    description: str = "",
) -> dict[str, Any] | None:
    """Intelligently map finding characteristics to the most effective Metasploit module."""
    cve_clean = cve.upper().strip() if cve else ""
    if not cve_clean and "CVE-" in title.upper():
        m = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", title.upper())
        if m:
            cve_clean = m.group(1)
    if not cve_clean and "CVE-" in description.upper():
        m = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", description.upper())
        if m:
            cve_clean = m.group(1)

    # 1. Match by exact CVE
    if cve_clean:
        for entry in METASPLOIT_OFFENSIVE_CATALOG:
            if entry.get("cve") and entry["cve"].upper() == cve_clean:
                return dict(entry)

    # 2. Match by keyword / tag in title, category, description with weighted scoring
    search_text = f"{title} {category} {description}".lower()
    best_match = None
    best_score = 0
    for entry in METASPLOIT_OFFENSIVE_CATALOG:
        score = 0
        for tag in entry.get("tags", []):
            if tag in search_text:
                score += len(tag) * 2
        for token in entry["fullname"].split("/"):
            if len(token) > 4 and token in search_text:
                score += len(token)
        if score > best_score:
            best_score = score
            best_match = entry

    if best_match and best_score > 0:
        return dict(best_match)

    # 3. Fallback based on generic vuln class
    norm_cat = category.lower()
    if "sql" in norm_cat or "sqli" in norm_cat:
        for entry in METASPLOIT_OFFENSIVE_CATALOG:
            if entry["fullname"] == "auxiliary/scanner/http/blind_sql_query":
                return dict(entry)
    elif any(k in norm_cat for k in ("command", "rce", "execution")):
        for entry in METASPLOIT_OFFENSIVE_CATALOG:
            if entry["fullname"] == "exploit/multi/http/generic_http_exec":
                return dict(entry)

    return None


def _search_live_module_tree(query: str) -> list[dict[str, Any]] | None:
    """Search the live msfrpcd module tree when SHARAY_MSFRPC_URL is configured and reachable.

    Returns None (so the caller uses the static catalog) when RPC is not available — fail-safe,
    never fabricated. The full ~2,400 exploit / ~1,200 auxiliary tree comes from msfrpcd here.
    """
    rpc_url = os.environ.get("SHARAY_MSFRPC_URL")
    if not rpc_url:
        return None
    try:
        from packages.scanner_adapters.integrations.msf_rpc import connect, probe_msfrpc

        if not probe_msfrpc(rpc_url, timeout=1.0):
            return None
        client = connect(
            rpc_url,
            os.environ.get("SHARAY_MSFRPC_USER", "msf"),
            os.environ.get("SHARAY_MSFRPC_PASS", ""),
        )
        return [
            {
                "fullname": m.fullname,
                "type": m.type,
                "title": m.name,
                "rank": m.rank,
                "cve": next((r for r in m.references if r.upper().startswith("CVE-")), None),
                "tags": [],
                "source": "msfrpc",
            }
            for m in client.search_modules(query)
        ]
    except Exception:
        return None


def search_metasploit_modules(query: str) -> list[dict[str, Any]]:
    """Search the Metasploit module tree by keyword, CVE, or module path.

    Prefers the live msfrpcd module tree when configured; falls back to the static offensive catalog.
    """
    live = _search_live_module_tree(query)
    if live is not None:
        return live
    q = query.lower().strip()
    if not q:
        return [dict(e) for e in METASPLOIT_OFFENSIVE_CATALOG[:15]]
    results = []
    is_rce = q == "rce"
    for entry in METASPLOIT_OFFENSIVE_CATALOG:
        title_lower = entry["title"].lower()
        match = (
            q in entry["fullname"].lower()
            or q in title_lower
            or (is_rce and ("remote code execution" in title_lower or "rce" in title_lower))
            or (entry.get("cve") and q in entry["cve"].lower())
            or any(q in t for t in entry.get("tags", []))
        )
        if match:
            results.append(dict(entry))
    return results


__all__ = [
    "METASPLOIT_OFFENSIVE_CATALOG",
    "VALIDATION_TECHNIQUE_CATALOG",
    "correlate_validation_techniques",
    "parse_metasploit_auxiliary_report",
    "parse_metasploit_catalog",
    "parse_metasploit_sessions",
    "resolve_metasploit_exploit",
    "search_metasploit_modules",
]
