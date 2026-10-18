"""Drop-in release-ready replacement for `packages/scanner_adapters/integrations/metasploit.py`.

Resolves all 4 Metasploit items in `drafts/codex-review/l-half-release-review-20261013.md`
(`entry-9c4c7b1ee96e4cd0`):
1. `parse_metasploit_sessions` (`metasploit.py:325`): Rejects `NaN`/`inf`, negative, out-of-order,
   or >10_000_000_000 timestamps before converting to `float` so 401-digit ints raise `ValueError`
   instead of `OverflowError`.
2. `correlate_validation_techniques` (`metasploit.py:206`): Copies nested `preconditions` and
   `boundary_checks` lists so caller mutations never alter `VALIDATION_TECHNIQUE_CATALOG`.
3. `parse_metasploit_auxiliary_report` (`metasploit.py:301`): Computes `fingerprint("msf_aux", module, locator)`
   without `outcome` so finding identity stays stable across outcome changes.
4. `_module_fullname` (`metasploit.py:211`): Rejects `.` and `..` path segments in module fullnames.
"""

from __future__ import annotations

import ipaddress
import math
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

ALLOWED_MODULE_TYPES = {"auxiliary", "post", "exploit_check_only"}
ALLOWED_RANKS = {"manual", "low", "average", "normal", "good", "great", "excellent"}
ALLOWED_OUTCOMES = {
    "confirmed_reproducible",
    "suspected",
    "validation_failed",
    "not_applicable",
}
ALLOWED_SESSION_TYPES = {"shell", "meterpreter", "http_diagnostic", "ssh", "sql_readonly"}
MAX_EPOCH_SECONDS = 10_000_000_000
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
    if not _MODULE_NAME.match(raw) or any(part in {".", ".."} for part in raw.split("/")):
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
        ):
            raise ValueError("Metasploit session timestamps must be numbers.")
        if (
            (isinstance(opened_at, float) and not math.isfinite(opened_at))
            or (isinstance(last_checkin, float) and not math.isfinite(last_checkin))
            or opened_at < 0
            or last_checkin < opened_at
            or opened_at > MAX_EPOCH_SECONDS
            or last_checkin > MAX_EPOCH_SECONDS
        ):
            raise ValueError("Metasploit session timestamps are out of order.")
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


__all__ = [
    "VALIDATION_TECHNIQUE_CATALOG",
    "correlate_validation_techniques",
    "parse_metasploit_auxiliary_report",
    "parse_metasploit_catalog",
    "parse_metasploit_sessions",
]
