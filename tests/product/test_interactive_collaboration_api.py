"""Product API tests for Interactive Session Collaboration, Asciinema Export & Copilot."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.auth import add_user, provision_owner
from aegis.config import Settings

PASSWORD = "Synthetic-test-password-761!"


class TestInteractiveCollaborationApi(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.settings = Settings(Path(self.folder.name), start_worker=False)
        self.app = create_app(self.settings)
        self.sessions = self.app.state.sessions

        with self.sessions() as db:
            self.owner = provision_owner(db, "testowner", PASSWORD)
            self.second_user = add_user(db, "second_op", PASSWORD, self.owner.organization_id, role="analyst")
            db.commit()

        self.client = TestClient(self.app, base_url=self.settings.origin)
        self.client.headers["origin"] = self.settings.origin

        # Sign in as owner
        res = self.client.post("/api/v1/auth/login", json={"username": "testowner", "password": PASSWORD})
        self.assertEqual(res.status_code, 200)
        self.client.headers["x-csrf-token"] = res.json()["csrf_token"]

        # Create project
        proj = self.client.post(
            "/api/v1/projects", json={"name": "Test Console Project", "description": "Desc"}
        )
        self.assertEqual(proj.status_code, 201)
        self.project_id = proj.json()["id"]

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

        # Create target
        t_res = self.client.post(
            f"/api/v1/projects/{self.project_id}/targets",
            json={"url": "https://example.com/", "scope": scope},
        )
        self.assertEqual(t_res.status_code, 201, t_res.text)
        target_data = t_res.json()
        self.target_id = target_data["id"]

        # Approve target
        appr = self.client.post(
            f"/api/v1/targets/{self.target_id}/approve",
            json={
                "acknowledgement": "I authorize this target within the displayed scope",
                "expected_scope_version": target_data["scope_version"],
            },
        )
        self.assertEqual(appr.status_code, 200, appr.text)

        # Create interactive session with DNS-pinned resolution
        from unittest.mock import patch

        with patch("aegis.api.resolve_pinned", return_value="93.184.216.34"):
            sess_res = self.client.post(
                "/api/v1/interactive/sessions",
                json={"target_id": self.target_id, "cols": 80, "rows": 24},
            )
            self.assertEqual(sess_res.status_code, 201, sess_res.text)
            self.session_id = sess_res.json()["id"]

    def tearDown(self):
        self.folder.cleanup()

    def test_asciinema_flight_log_export_endpoint(self):
        res = self.client.get(f"/api/v1/interactive/sessions/{self.session_id}/asciinema")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/x-asciicast", res.headers.get("content-type", ""))
        self.assertIn('"version": 2', res.text)
        self.assertIn("TARGET_ORIGIN", res.text)

    def test_multi_operator_collaboration_workflow(self):
        # 1. Check initial operator status
        ops_res = self.client.get(f"/api/v1/interactive/sessions/{self.session_id}/collaborate/operators")
        self.assertEqual(ops_res.status_code, 200)
        data = ops_res.json()
        self.assertEqual(data["primary_controller_id"], self.owner.id)

        # 2. Second operator logs in on their own client and joins as observer
        second_client = TestClient(self.app, base_url=self.settings.origin)
        second_client.headers["origin"] = self.settings.origin
        sec_login = second_client.post(
            "/api/v1/auth/login", json={"username": "second_op", "password": PASSWORD}
        )
        self.assertEqual(sec_login.status_code, 200)
        second_client.headers["x-csrf-token"] = sec_login.json()["csrf_token"]

        join_res = second_client.post(
            f"/api/v1/interactive/sessions/{self.session_id}/collaborate/join",
            json={"as_primary": False, "color_hex": "#10b981"},
        )
        self.assertEqual(join_res.status_code, 200)
        self.assertEqual(join_res.json()["status"], "joined")
        self.assertEqual(join_res.json()["role"], "OBSERVER")

        # Verify 2 operators in session
        ops_res = self.client.get(f"/api/v1/interactive/sessions/{self.session_id}/collaborate/operators")
        self.assertEqual(ops_res.status_code, 200)
        self.assertEqual(len(ops_res.json()["operators"]), 2)

        # 3. Primary controller (owner) transfers control to second operator
        trans_res = self.client.post(
            f"/api/v1/interactive/sessions/{self.session_id}/collaborate/transfer",
            json={"target_operator_id": self.second_user.id, "reason": "handing off investigation"},
        )
        self.assertEqual(trans_res.status_code, 200)
        self.assertEqual(trans_res.json()["primary_controller_id"], self.second_user.id)

        # 4. Lead preemption takeover by owner
        take_res = self.client.post(
            f"/api/v1/interactive/sessions/{self.session_id}/collaborate/takeover",
            json={"justification": "Urgent critical triage required"},
        )
        self.assertEqual(take_res.status_code, 200)
        self.assertEqual(take_res.json()["status"], "preempted")
        self.assertEqual(take_res.json()["primary_controller_id"], self.owner.id)

    def test_copilot_endpoint(self):
        # Autocomplete suggestions for curl
        res = self.client.post(
            f"/api/v1/interactive/sessions/{self.session_id}/copilot",
            json={"partial_cmd": "curl", "last_output": "ORA-00933: SQL command not properly ended"},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(len(body["completions"]) > 0)
        self.assertIsNotNone(body["suggestion"])
        self.assertEqual(body["suggestion"]["action"], "SQL Injection Confirmation")
