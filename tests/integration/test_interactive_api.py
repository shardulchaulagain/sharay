"""Integration tests for Interactive Console API and Exploit Gate (D2 & D4)."""

import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.auth import provision_owner
from aegis.config import Settings

PASSWORD = "Synthetic-test-password-761!"


class InteractiveApiTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.settings = Settings(Path(self.folder.name), start_worker=False)
        self.app = create_app(self.settings)
        self.sessions = self.app.state.sessions
        with self.sessions() as db:
            owner = provision_owner(db, "localowner", PASSWORD)
            self.owner_id, self.org_id = owner.id, owner.organization_id
            db.commit()
        self.client = TestClient(self.app, base_url=self.settings.origin)
        self.client.headers["origin"] = self.settings.origin
        self.login(self.client)

        # Create project and target
        proj_res = self.client.post(
            "/api/v1/projects",
            json={"name": "Interactive Assessment", "description": "Console testing"},
        )
        self.assertEqual(proj_res.status_code, 201, proj_res.text)
        project_id = proj_res.json()["id"]

        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        scope = {
            "hosts": ["example.com"],
            "allowed_origins": ["https://example.com"],
            "allowed_paths": ["/"],
            "excluded_paths": ["/excluded"],
            "allowed_cidrs": ["93.184.216.34/32"],
            "categories": ["http_headers", "tls", "dns"],
            "request_rate": 5.0,
            "max_concurrency": 1,
            "authenticated": False,
            "credential_refs": [],
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "intrusive": False,
            "approval_required": True,
            "emergency_stop_conditions": ["operator_cancel", "scope_expired", "policy_violation"],
        }

        res = self.client.post(
            f"/api/v1/projects/{project_id}/targets",
            json={"url": "https://example.com/", "scope": scope},
        )
        self.assertEqual(res.status_code, 201, res.text)
        target_data = res.json()
        self.target_id = target_data["id"]

        approve_res = self.client.post(
            f"/api/v1/targets/{self.target_id}/approve",
            json={
                "acknowledgement": "I authorize this target within the displayed scope",
                "expected_scope_version": target_data["scope_version"],
            },
        )
        self.assertEqual(approve_res.status_code, 200, approve_res.text)

    def tearDown(self):
        self.client.close()
        self.app.state.engine.dispose()
        self.folder.cleanup()

    def login(self, client, username="localowner", password=PASSWORD):
        response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200, response.text)
        client.headers["x-csrf-token"] = response.json()["csrf_token"]
        return response

    @patch("aegis.api.resolve_pinned", return_value="93.184.216.34")
    def test_interactive_session_ownership_and_exploit_gate_api(self, _mock_resolve):
        # 1. Create session
        res = self.client.post(
            "/api/v1/interactive/sessions",
            json={"target_id": self.target_id, "cols": 80, "rows": 24},
        )
        self.assertEqual(res.status_code, 201, res.text)
        session_data = res.json()
        session_id = session_data["id"]
        self.assertEqual(session_data["ownership_state"], "HUMAN_OWNED")

        try:
            # 2. Human write succeeds
            res_input = self.client.post(
                f"/api/v1/interactive/sessions/{session_id}/input",
                json={"data": "echo 'human_test'\n", "sender": "human"},
            )
            self.assertEqual(res_input.status_code, 200)
            self.assertEqual(res_input.json()["ownership_state"], "HUMAN_OWNED")

            # 3. Agent write fails with 409 Conflict while human owns console
            res_agent_blocked = self.client.post(
                f"/api/v1/interactive/sessions/{session_id}/input",
                json={"data": "echo 'agent_test'\n", "sender": "agent"},
            )
            self.assertEqual(res_agent_blocked.status_code, 409)
            self.assertIn("Agent write blocked", res_agent_blocked.text)

            # 4. Explicitly release to agent
            res_own = self.client.post(
                f"/api/v1/interactive/sessions/{session_id}/ownership",
                json={"state": "AGENT_OWNED"},
            )
            self.assertEqual(res_own.status_code, 200)
            self.assertEqual(res_own.json()["ownership_state"], "AGENT_OWNED")

            # 5. Agent write succeeds now
            res_agent_ok = self.client.post(
                f"/api/v1/interactive/sessions/{session_id}/input",
                json={"data": "echo 'agent_success'\n", "sender": "agent"},
            )
            self.assertEqual(res_agent_ok.status_code, 200)
            self.assertEqual(res_agent_ok.json()["ownership_state"], "AGENT_OWNED")

            # 6. Human input instantly preempts back to HUMAN_OWNED
            res_preempt = self.client.post(
                f"/api/v1/interactive/sessions/{session_id}/input",
                json={"data": "echo 'human_preemption'\n", "sender": "human"},
            )
            self.assertEqual(res_preempt.status_code, 200)
            self.assertEqual(res_preempt.json()["ownership_state"], "HUMAN_OWNED")

            # 7. Pre-Notification Exploit Gate Confirmation (D4)
            res_gate = self.client.post(
                f"/api/v1/interactive/sessions/{session_id}/exploit-gate/confirm",
                json={
                    "exploit_type": "SQLi_Union_Extract",
                    "target_id": self.target_id,
                    "target_url": "https://example.com/",
                    "auto_proceed": False,
                    "operator_confirmed": True,
                },
            )
            # W5 (no gate): operator-confirmed + authorized + in-scope -> ALLOW_ACTIVE_EXPLOIT granted.
            self.assertEqual(res_gate.status_code, 200, res_gate.text)
            self.assertEqual(res_gate.json()["status"], "authorized")
            self.assertTrue(res_gate.json()["allow_active_exploit"])

        finally:
            # Cleanup session
            self.client.post(f"/api/v1/interactive/sessions/{session_id}/terminate")

    @patch("aegis.api.resolve_pinned", return_value="93.184.216.34")
    def test_exploit_gate_rejects_missing_confirmation_wrong_target_and_scope_changes(self, _resolve):
        from aegis.models import Target

        session_id = self.create_console()
        path = f"/api/v1/interactive/sessions/{session_id}/exploit-gate/confirm"
        payload = {
            "exploit_type": "fixture",
            "target_id": self.target_id,
            "target_url": "https://example.com/",
            "operator_confirmed": True,
        }
        for change, expected in [
            ({"operator_confirmed": False}, 403),
            ({"auto_proceed": True}, 403),
            ({"target_id": "different-target"}, 422),
            ({"target_url": "https://example.com/excluded"}, 422),
            # NB: the all-checks-pass case now returns 200 "authorized" (W5, no gate) -- see the happy-path test.
        ]:
            response = self.client.post(path, json={**payload, **change})
            self.assertEqual(response.status_code, expected, response.text)
            self.assertNotIn('"authorized"', response.text)
        omitted = {key: value for key, value in payload.items() if key != "operator_confirmed"}
        self.assertEqual(self.client.post(path, json=omitted).status_code, 403)
        with self.sessions() as db:
            target = db.get(Target, self.target_id)
            target.scope_version += 1
            db.commit()
        self.assertEqual(self.client.post(path, json=payload).status_code, 409)

    def create_console(self):
        response = self.client.post("/api/v1/interactive/sessions", json={"target_id": self.target_id})
        self.assertEqual(response.status_code, 201, response.text)
        session_id = response.json()["id"]
        from aegis.interactive import terminal_manager

        console = terminal_manager.get_session(session_id, self.org_id)
        self.addCleanup(lambda: console.terminate(reason="test_cleanup"))
        return session_id

    @patch("aegis.api.resolve_pinned", return_value="93.184.216.34")
    def test_running_diagnostic_releases_database_lock_for_ctrl_c(self, _resolve):
        from aegis.interactive import terminal_manager

        session_id = self.create_console()
        console = terminal_manager.get_session(session_id, self.org_id)
        started = threading.Event()
        cancelled_during_command = []

        def diagnostic(*_args, **_kwargs):
            started.set()
            cancelled_during_command.append(console._cancel.wait(2))
            return "stale command result"

        path = f"/api/v1/interactive/sessions/{session_id}/input"
        with (
            patch.object(console, "execute", side_effect=diagnostic),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            command = pool.submit(self.client.post, path, json={"data": "beacon\n"})
            self.assertTrue(started.wait(1))
            interrupted = pool.submit(self.client.post, path, json={"data": "\x03"})
            response = interrupted.result(timeout=1)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(command.result(timeout=1).status_code, 200)
        self.assertEqual(cancelled_during_command, [True])
        output = console.output_since(0)[1]
        self.assertNotIn(b"stale command result", output)
        self.assertTrue(any(event.get("action") == "command_cancelled" for event in console.flight_log))

    @patch("aegis.api.resolve_pinned", return_value="93.184.216.34")
    def test_retest_rechecks_scope_in_its_queue_transaction(self, _resolve):
        from sqlalchemy import select

        from aegis.interactive import terminal_manager
        from aegis.models import Assessment, Target

        session_id = self.create_console()
        console = terminal_manager.get_session(session_id, self.org_id)

        def change_scope_before_retest(_command, **context):
            with self.sessions() as db:
                target = db.get(Target, self.target_id)
                target.scope_version += 1
                db.commit()
            return context["retest"]("fixture-finding")

        with patch.object(console, "execute", side_effect=change_scope_before_retest):
            response = self.client.post(
                f"/api/v1/interactive/sessions/{session_id}/input", json={"data": "retest fixture-finding\n"}
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(console.is_alive())
        with self.sessions() as db:
            self.assertEqual(list(db.scalars(select(Assessment))), [])
        self.assertTrue(any("Scope changed" in event.get("detail", "") for event in console.flight_log))

    @patch("aegis.api.resolve_pinned", return_value="93.184.216.34")
    def test_console_whoami_current_scope_and_viewer_write_refusal(self, _resolve):
        from aegis.auth import add_user
        from aegis.interactive import terminal_manager

        session_id = self.create_console()
        result = self.client.post(
            f"/api/v1/interactive/sessions/{session_id}/input", json={"data": "whoami\n"}
        )
        self.assertEqual(result.status_code, 200, result.text)
        session = terminal_manager.get_session(session_id, self.org_id)
        output = session.read_available().decode()
        self.assertIn("Role: owner", output)
        self.assertIn("Excluded paths: /excluded", output)
        with self.sessions() as db:
            add_user(db, "consoleviewer", PASSWORD, self.org_id, "viewer")
            db.commit()
        with TestClient(self.app, base_url=self.settings.origin) as viewer:
            viewer.headers["origin"] = self.settings.origin
            self.login(viewer, "consoleviewer")
            denied = viewer.post(
                f"/api/v1/interactive/sessions/{session_id}/input", json={"data": "beacon\n"}
            )
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(viewer.get(f"/api/v1/interactive/sessions/{session_id}/stream").status_code, 403)

    @patch("aegis.api.resolve_pinned", return_value="93.184.216.34")
    def test_scope_change_and_revocation_close_console_before_network_io(self, _resolve):
        from aegis.interactive import terminal_manager
        from aegis.models import Target

        session_id = self.create_console()
        with self.sessions() as db:
            target = db.get(Target, self.target_id)
            target.scope_version += 1
            db.commit()
        with patch("aegis.interactive._connection") as connection:
            result = self.client.post(
                f"/api/v1/interactive/sessions/{session_id}/input",
                json={"data": "probe https://example.com/\n"},
            )
            self.assertEqual(result.status_code, 409)
            self.assertFalse(terminal_manager.get_session(session_id, self.org_id).is_alive())
            connection.assert_not_called()
        next_session = self.create_console()
        with self.sessions() as db:
            target = db.get(Target, self.target_id)
            target.authorized_by = None
            db.commit()
        result = self.client.post(
            f"/api/v1/interactive/sessions/{next_session}/input", json={"data": "beacon\n"}
        )
        self.assertEqual(result.status_code, 403)
        self.assertFalse(terminal_manager.get_session(next_session, self.org_id).is_alive())

    @patch("aegis.api.resolve_pinned", return_value="93.184.216.34")
    def test_retest_finding_queues_existing_profile_without_confirming_finding(self, _resolve):
        import uuid

        from sqlalchemy import select

        from aegis.interactive import terminal_manager
        from aegis.models import Assessment, Finding, FindingEvidence, Target

        session_id = self.create_console()
        with self.sessions() as db:
            target = db.get(Target, self.target_id)
            baseline = Assessment(
                organization_id=self.org_id,
                project_id=target.project_id,
                target_id=target.id,
                created_by=self.owner_id,
                idempotency_key=str(uuid.uuid4()),
                profile="safe_http",
                status="completed",
                scope_snapshot={**target.scope, "target_url": target.url},
                scope_version=target.scope_version,
            )
            db.add(baseline)
            finding = Finding(
                organization_id=self.org_id,
                project_id=target.project_id,
                target_id=target.id,
                fingerprint="console-fixture",
                title="Fixture configuration",
                category="http_headers",
                severity="info",
                confidence="high",
                status="needs_triage",
                description="Fixture",
                remediation="Fixture",
                affected_url=target.url,
            )
            db.add(finding)
            db.flush()
            db.add(
                FindingEvidence(
                    finding_id=finding.id, assessment_id=baseline.id, data={}, evidence_hash="fixture"
                )
            )
            db.commit()
            finding_id, baseline_id = finding.id, baseline.id
        response = self.client.post(
            f"/api/v1/interactive/sessions/{session_id}/input", json={"data": f"retest {finding_id}\n"}
        )
        self.assertEqual(response.status_code, 200, response.text)
        with self.sessions() as db:
            queued = db.scalar(select(Assessment).where(Assessment.retest_of == baseline_id))
            self.assertIsNotNone(queued)
            self.assertEqual(queued.status, "queued")
            self.assertEqual(queued.profile, "safe_http")
            self.assertEqual(db.get(Finding, finding_id).status, "needs_triage")
        output = terminal_manager.get_session(session_id, self.org_id).read_available().decode()
        self.assertIn("full approved profile", output)


if __name__ == "__main__":
    unittest.main()
