"""Unit tests for the Metasploit catalog/auxiliary/session parser (L6)."""

from __future__ import annotations

import json

import pytest

from packages.scanner_adapters.integrations.metasploit import (
    VALIDATION_TECHNIQUE_CATALOG,
    _module_fullname,
    correlate_validation_techniques,
    parse_metasploit_auxiliary_report,
    parse_metasploit_catalog,
    parse_metasploit_sessions,
    resolve_metasploit_exploit,
    search_metasploit_modules,
)


def test_correlate_validation_techniques_covers_all_classes() -> None:
    expected_classes = {
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
        "path_traversal",
        "open_redirect",
        "request_smuggling",
        "csrf",
        "clickjacking",
        "prototype_pollution",
    }
    assert set(VALIDATION_TECHNIQUE_CATALOG.keys()) == expected_classes
    # Every entry's vuln_class matches its catalog key.
    for cls, items in VALIDATION_TECHNIQUE_CATALOG.items():
        assert items and all(it["vuln_class"] == cls for it in items)
    # New classes resolve by alias and by CWE.
    assert correlate_validation_techniques("lfi")[0]["vuln_class"] == "path_traversal"
    assert correlate_validation_techniques("x", cwe=601)[0]["vuln_class"] == "open_redirect"
    assert correlate_validation_techniques("csrf")[0]["vuln_class"] == "csrf"
    assert correlate_validation_techniques("ui_redress")[0]["vuln_class"] == "clickjacking"
    assert correlate_validation_techniques("x", cwe=1321)[0]["vuln_class"] == "prototype_pollution"

    # Alias lookup
    sqli = correlate_validation_techniques("sqli")
    assert len(sqli) == 2
    assert sqli[0]["technique_id"] == "sqli.boolean_differential_pair"

    # CWE fallback lookup when category is generic
    ssrf = correlate_validation_techniques("unknown_scanner_category", cwe=918)
    assert len(ssrf) == 1
    assert ssrf[0]["vuln_class"] == "ssrf"
    assert ssrf[0]["opens_session"] is True

    # Unknown category and CWE
    assert correlate_validation_techniques("unknown", cwe=99999) == []


def test_parse_metasploit_catalog_valid_and_rejects_bad_module() -> None:
    payload = {
        "modules": [
            {
                "fullname": "auxiliary/scanner/http/http_version",
                "type": "auxiliary",
                "rank": "normal",
                "name": "HTTP Version Detection",
                "check_supported": True,
                "references": ["CVE-2025-12345", "CWE-200"],
            }
        ]
    }
    parsed = parse_metasploit_catalog(json.dumps(payload).encode())
    assert parsed["truncated"] is False
    assert len(parsed["modules"]) == 1
    assert parsed["modules"][0]["fullname"] == "auxiliary/scanner/http/http_version"
    assert parsed["modules"][0]["check_supported"] is True

    bad_payload = {
        "modules": [
            {
                "fullname": "../traversal/module",
                "type": "auxiliary",
                "rank": "normal",
                "check_supported": False,
            }
        ]
    }
    with pytest.raises(ValueError, match="fullname is invalid"):
        parse_metasploit_catalog(json.dumps(bad_payload).encode())


def test_parse_metasploit_auxiliary_report_and_sessions() -> None:
    aux_payload = {
        "results": [
            {
                "module": "auxiliary/scanner/http/title",
                "target_url": "https://127.0.0.1:8443/admin",
                "outcome": "confirmed_reproducible",
                "session_established": True,
                "summary": "Confirmed access with token AKIAIOSFODNN7EXAMPLE",
            },
            {
                "module": "auxiliary/scanner/ssh/ssh_version",
                "target_host": "::1",
                "target_port": 2222,
                "outcome": "suspected",
                "session_established": False,
                "summary": "SSH banner inspected",
            },
        ]
    }
    aux = parse_metasploit_auxiliary_report(json.dumps(aux_payload).encode())
    assert len(aux["findings"]) == 2
    assert aux["findings"][0]["locator"] == "https://127.0.0.1:8443/admin"
    assert "AKIAIOSFODNN7EXAMPLE" not in aux["findings"][0]["summary"]
    assert aux["findings"][1]["locator"] == "[::1]:2222"

    sess_payload = {
        "sessions": [
            {
                "session_id": "msf-sess-1",
                "session_type": "http_diagnostic",
                "via_module": "auxiliary/scanner/http/title",
                "peer_host": "127.0.0.1",
                "peer_port": 8443,
                "privilege_user": "www-data",
                "opened_at": 1791831600.0,
                "last_checkin": 1791831695.5,
            }
        ]
    }
    sess = parse_metasploit_sessions(json.dumps(sess_payload).encode())
    assert len(sess["sessions"]) == 1
    assert sess["sessions"][0]["duration_seconds"] == 95.5
    assert sess["sessions"][0]["peer"] == "127.0.0.1:8443"

    bad_sess = {
        "sessions": [
            {
                "session_id": "msf-sess-2",
                "session_type": "http_diagnostic",
                "via_module": "auxiliary/scanner/http/title",
                "peer_host": "127.0.0.1",
                "peer_port": 8443,
                "opened_at": 200.0,
                "last_checkin": 100.0,
            }
        ]
    }
    for bad_ts in (int("9" * 401), 1e308):
        payload = {
            "sessions": [
                {
                    "session_id": "s",
                    "session_type": "shell",
                    "via_module": "auxiliary/scanner/http/title",
                    "peer_host": "127.0.0.1",
                    "peer_port": 8080,
                    "opened_at": 0,
                    "last_checkin": bad_ts,
                }
            ]
        }
        with pytest.raises(ValueError):
            parse_metasploit_sessions(json.dumps(payload).encode())
    # correlate result is independent of the module catalog
    techniques = correlate_validation_techniques("sql_injection")
    techniques[0]["preconditions"].clear()
    assert correlate_validation_techniques("sql_injection")[0]["preconditions"]
    # module fullnames reject dot segments
    for bad in ("a/../b/c", "a/./b", "a/b/.."):
        with pytest.raises(ValueError):
            _module_fullname(bad)

    with pytest.raises(ValueError, match="out of range or order"):
        parse_metasploit_sessions(json.dumps(bad_sess).encode())


def test_resolve_and_search_offensive_metasploit_modules() -> None:
    # 1. Resolve by exact CVE
    log4j = resolve_metasploit_exploit(cve="CVE-2021-44228")
    assert log4j is not None
    assert log4j["fullname"] == "exploit/multi/http/log4j_header_injection"
    assert log4j["type"] == "exploit"
    assert log4j["default_action"] == "check"

    # 2. Resolve by title with embedded CVE
    spring = resolve_metasploit_exploit(title="Vulnerable Spring Framework CVE-2022-22965")
    assert spring is not None
    assert spring["fullname"] == "exploit/multi/http/spring_framework_rce_spring4shell"

    # 3. Resolve by keyword / service
    activemq = resolve_metasploit_exploit(title="Apache ActiveMQ OpenWire RCE")
    assert activemq is not None
    assert activemq["fullname"] == "exploit/multi/http/apache_activemq_upload_jsp"

    # 4. Fallback by generic SQLi category
    sqli = resolve_metasploit_exploit(category="sql_injection")
    assert sqli is not None
    assert sqli["fullname"] == "auxiliary/scanner/http/blind_sql_query"

    # 5. Search capability
    rce_mods = search_metasploit_modules("rce")
    assert len(rce_mods) >= 3
    assert any("log4j" in m["fullname"] for m in rce_mods)

    cve_mods = search_metasploit_modules("2021-26084")
    assert len(cve_mods) == 1
    assert cve_mods[0]["fullname"] == "exploit/multi/http/confluence_widget_connector"
