"""Live test suite for Multi-Operator Console, Collaboration & Asciinema V2 Export (Sector 8).

Verifies:
1. Multi-operator presence, observer join, and controller promotion on disconnect.
2. Controller handoffs and lead operator preemption with audit trail.
3. HMAC-SHA256 signed per-keystroke ledger attribution.
4. Scoped command autocomplete, history search, and inline AI copilot suggestions.
5. Standard-compliant Asciinema v2 JSONL session recording export.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from aegis.interactive import (
    MultiOperatorSessionCoordinator,
    OperatorRole,
    TerminalAutocompleteAndCopilot,
)


class TestMultiOperatorSession:
    def test_multi_operator_presence_and_handoff(self):
        coord = MultiOperatorSessionCoordinator("sess-test-001", "https://app.target.corp")

        # Operator 1 joins as primary
        op1 = coord.join_session("op-1", "alice", as_primary=True, now=100.0)
        assert op1.role == OperatorRole.PRIMARY_CONTROLLER
        assert coord.primary_controller_id == "op-1"

        # Operator 2 joins as observer
        op2 = coord.join_session("op-2", "bob", as_primary=False, now=101.0)
        assert op2.role == OperatorRole.OBSERVER

        # Voluntary handoff from Alice to Bob
        success = coord.transfer_control("op-1", "op-2", reason="operator_switch", now=102.0)
        assert success is True
        assert coord.primary_controller_id == "op-2"
        assert coord.operators["op-1"].role == OperatorRole.OBSERVER
        assert coord.operators["op-2"].role == OperatorRole.PRIMARY_CONTROLLER

        # Lead preemption: Lead operator Carol joins and takes over with justification
        coord.join_session("op-3", "carol_lead", as_primary=False, now=103.0)
        preempted = coord.preempt_takeover(
            "op-3", justification="Investigating high-severity RCE", is_lead=True, now=104.0
        )
        assert preempted is True
        assert coord.primary_controller_id == "op-3"
        assert coord.operators["op-3"].role == OperatorRole.PRIMARY_CONTROLLER
        assert coord.operators["op-2"].role == OperatorRole.OBSERVER

        # Verify handoff audit ledger
        assert len(coord.handoff_ledger) >= 3
        assert "Investigating high-severity RCE" in coord.handoff_ledger[-1]["reason"]

    def test_per_keystroke_signed_input_attribution(self):
        coord = MultiOperatorSessionCoordinator(
            "sess-test-002", "https://app.target.corp", hmac_secret="secret_test_key"
        )
        coord.join_session("op-alice", "alice", as_primary=True, now=200.0)
        coord.join_session("op-bob", "bob", as_primary=False, now=200.0)

        # Primary Alice writes command
        ok, event = coord.record_input("op-alice", "curl -v https://app.target.corp/api", now=201.0)
        assert ok is True
        assert event is not None
        assert event.sequence_num == 1
        assert event.username == "alice"

        # Verify HMAC signature
        expected_payload = "sess-test-002:1:op-alice:201.0:curl -v https://app.target.corp/api".encode(
            "utf-8"
        )
        expected_sig = hmac.new(b"secret_test_key", expected_payload, hashlib.sha256).hexdigest()
        assert event.signature == expected_sig

        # Observer Bob attempts to write input: rejected!
        ok_bob, event_bob = coord.record_input("op-bob", "rm -rf /", now=202.0)
        assert ok_bob is False
        assert event_bob is None

    def test_terminal_autocomplete_and_ai_copilot(self):
        copilot = TerminalAutocompleteAndCopilot(in_scope_endpoints=["/login", "/dashboard", "/api/v1/auth"])

        # Autocomplete on curl
        suggestions = copilot.get_completions("curl", target_origin="https://target.corp")
        assert any("https://target.corp/login" in s for s in suggestions)
        assert any("https://target.corp/dashboard" in s for s in suggestions)

        # History search
        copilot.add_history("curl -v https://target.corp/login")
        copilot.add_history("check-sqli --technique=error-based")
        matched = copilot.search_history("check-sqli")
        assert len(matched) == 1
        assert matched[0] == "check-sqli --technique=error-based"

        # AI Copilot: detects SQL syntax error in output buffer
        sql_sugg = copilot.get_copilot_suggestion("ORA-00933: SQL command not properly ended")
        assert sql_sugg is not None
        assert sql_sugg["action"] == "SQL Injection Confirmation"
        assert "check-sqli" in sql_sugg["recommended_command"]

        # AI Copilot: detects 401 Unauthorized in output buffer
        auth_sugg = copilot.get_copilot_suggestion("HTTP/1.1 401 Unauthorized - Session Expired")
        assert auth_sugg is not None
        assert auth_sugg["action"] == "Session Renewal"

    def test_asciinema_v2_flight_log_export(self):
        coord = MultiOperatorSessionCoordinator("sess-cast-001", "https://app.target.corp")
        coord.join_session("op-1", "alice", as_primary=True, now=100.0)

        coord.record_input("op-1", "curl https://app.target.corp/\n", now=101.0)
        coord.record_output("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nHello", now=101.5)

        cast_jsonl = coord.export_asciinema_v2(title="Courtroom Evidence Audit")
        lines = cast_jsonl.strip().split("\n")
        assert len(lines) == 3

        # Line 1: Header
        header = json.loads(lines[0])
        assert header["version"] == 2
        assert header["title"] == "Courtroom Evidence Audit"
        assert header["env"]["TARGET_ORIGIN"] == "https://app.target.corp"

        # Line 2: Input event
        inp_event = json.loads(lines[1])
        assert inp_event[1] == "i"
        assert inp_event[2] == "curl https://app.target.corp/\n"

        # Line 3: Output event
        out_event = json.loads(lines[2])
        assert out_event[1] == "o"
        assert "200 OK" in out_event[2]
