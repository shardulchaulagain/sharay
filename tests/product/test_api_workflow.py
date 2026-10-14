"""Real local assessment, persistence and access-control regressions."""

import json
import secrets
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from aegis.api import create_app
from aegis.audit import verify_audit
from aegis.auth import add_user, check_csrf, consume_recovery, issue_recovery, provision_owner
from aegis.config import Settings
from aegis.models import AuditEvent, Organization, RecoveryToken, SessionRecord
from aegis.worker import run_one
from fixtures.safe_targets.server import create_server

PASSWORD = "Synthetic-test-password-761!"


class WorkflowTests(unittest.TestCase):
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
        self.server = create_server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.client.close()
        self.app.state.engine.dispose()
        self.folder.cleanup()

    def login(self, client, username="localowner", password=PASSWORD):
        response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200, response.text)
        client.headers["x-csrf-token"] = response.json()["csrf_token"]
        return response

    def scope(self, url=None):
        now = datetime.now(timezone.utc)
        return {
            "hosts": ["127.0.0.1"],
            "allowed_origins": [(url or self.url).rstrip("/")],
            "allowed_paths": ["/"],
            "excluded_paths": ["/excluded"],
            "allowed_cidrs": ["127.0.0.1/32"],
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

    def target(self, approve=True, url=None):
        project = self.client.post(
            "/api/v1/projects",
            json={"name": "Synthetic local assessment", "description": "Controlled test fixture"},
        )
        self.assertEqual(project.status_code, 201, project.text)
        target = self.client.post(
            f"/api/v1/projects/{project.json()['id']}/targets",
            json={"url": url or self.url, "scope": self.scope()},
        )
        self.assertEqual(target.status_code, 201, target.text)
        if approve:
            response = self.client.post(
                f"/api/v1/targets/{target.json()['id']}/approve",
                json={
                    "acknowledgement": "I authorize this controlled laboratory target",
                    "expected_scope_version": target.json()["scope_version"],
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
        return target.json(), project.json()

    def launch(self, target, retest=None, key=None):
        response = self.client.post(
            "/api/v1/assessments",
            json={
                "target_id": target["id"],
                "idempotency_key": key or secrets.token_hex(16),
                "expected_scope_version": target["scope_version"],
                "retest_of": retest,
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_broad_inventory_authorization_is_versioned_and_cannot_queue_live_execution(self):
        from tests.product.test_broad_scope import broad_scope

        project = self.client.post("/api/v1/projects", json={"name": "Synthetic broad inventory"}).json()
        with (
            patch("socket.getaddrinfo", side_effect=AssertionError("No DNS in inventory")),
            patch("packages.scanner_adapters._connection") as connect,
        ):
            for host in ("example.com", "localhost", "192.168.1.50", "2001:db8::1"):
                scope = broad_scope(host)
                url = scope["allowed_origins"][0] + "/"
                registered = self.client.post(
                    f"/api/v1/projects/{project['id']}/targets", json={"url": url, "scope": scope}
                )
                self.assertEqual(registered.status_code, 201, registered.text)
                target = registered.json()
                self.assertIn("execution requires", target["execution_blocker"])
                approved = self.client.post(
                    f"/api/v1/targets/{target['id']}/approve",
                    json={
                        "expected_scope_version": 1,
                        "acknowledgement": "I authorize this target within the displayed scope",
                    },
                )
                self.assertEqual(approved.status_code, 200, approved.text)
                self.assertEqual(approved.json()["verification_status"], "operator_authorized")
                rejected = self.client.post(
                    "/api/v1/assessments",
                    json={
                        "target_id": target["id"],
                        "expected_scope_version": 1,
                        "idempotency_key": secrets.token_hex(16),
                    },
                )
                self.assertEqual(rejected.status_code, 422, rejected.text)
                self.assertIn("execution requires", rejected.json()["detail"])
                updated = self.client.patch(
                    f"/api/v1/targets/{target['id']}/scope",
                    json={
                        "url": url,
                        "scope": scope | {"excluded_paths": ["/private"]},
                        "expected_scope_version": 1,
                    },
                )
                self.assertEqual(updated.status_code, 200, updated.text)
                self.assertEqual(updated.json()["scope_version"], 2)
                self.assertIsNone(updated.json()["authorized_by"])
                self.assertEqual(updated.json()["verification_status"], "awaiting_authorization")
            connect.assert_not_called()
        self.assertEqual(self.client.get("/api/v1/assessments").json()["total"], 0)
        with self.sessions() as db:
            self.assertTrue(verify_audit(db))

    def test_real_worker_findings_reports_retest(self):
        target, project = self.target()
        assessment = self.launch(target)
        self.assertTrue(run_one(self.sessions))
        result = self.client.get(f"/api/v1/assessments/{assessment['id']}").json()
        self.assertEqual(result["status"], "completed")
        self.assertGreater(len(result["observations"]), 0)
        self.assertGreater(len(result["findings"]), 0)
        serialized = json.dumps(result)
        for secret in (
            "never-retain-this-body",
            "never-retain-this-header-value",
            "never-retain-this-cookie-value",
        ):
            self.assertNotIn(secret, serialized)
        self.assertTrue(all(f["evidence"][0]["data"]["observation_ids"] for f in result["findings"]))
        for format in ("html", "json", "markdown", "pdf"):
            report = self.client.get(f"/api/v1/reports/{assessment['id']}?format={format}")
            self.assertEqual(report.status_code, 200, report.text[:200] if format != "pdf" else "PDF error")
            self.assertGreater(len(report.content), 100)
        original_ids = {f["id"] for f in result["findings"]}
        self.server.secure_headers = True
        retest = self.launch(target, assessment["id"])
        run_one(self.sessions)
        result2 = self.client.get(f"/api/v1/assessments/{retest['id']}").json()
        self.assertEqual(result2["status"], "completed")
        findings = self.client.get("/api/v1/findings").json()["items"]
        self.assertEqual({f["id"] for f in findings}, original_ids)
        self.assertTrue(all(f["status"] == "fixed" for f in findings))
        historical = self.client.get(f"/api/v1/reports/{assessment['id']}?format=json").json()
        self.assertTrue(
            all(f["status"] == "confirmed" for f in historical["findings"]),
            "Retest must not rewrite historical confirmation evidence",
        )
        self.assertEqual(self.client.get("/api/v1/overview").json()["completed_assessments"], 2)
        self.assertEqual(self.client.get(f"/api/v1/projects/{project['id']}").status_code, 200)

    def test_cross_org_and_role_denial(self):
        target, project = self.target()
        assessment = self.launch(target)
        run_one(self.sessions)
        finding = self.client.get("/api/v1/findings").json()["items"][0]
        with self.sessions() as db:
            org = Organization(name="Other synthetic organization")
            db.add(org)
            db.flush()
            add_user(db, "otherowner", PASSWORD, org.id, "owner")
            add_user(db, "localviewer", PASSWORD, self.org_id, "viewer")
            db.commit()
        other = TestClient(self.app, base_url=self.settings.origin, headers={"origin": self.settings.origin})
        self.login(other, "otherowner")
        for path in (
            f"projects/{project['id']}",
            f"assessments/{assessment['id']}",
            f"reports/{assessment['id']}",
        ):
            self.assertEqual(other.get("/api/v1/" + path).status_code, 404)
        self.assertEqual(
            other.post(
                f"/api/v1/targets/{target['id']}/approve",
                json={
                    "acknowledgement": "I authorize this controlled laboratory target",
                    "expected_scope_version": target["scope_version"],
                },
            ).status_code,
            404,
        )
        self.assertEqual(other.post(f"/api/v1/assessments/{assessment['id']}/cancel").status_code, 404)
        self.assertEqual(
            other.patch(f"/api/v1/findings/{finding['id']}", json={"status": "accepted_risk"}).status_code,
            404,
        )
        self.assertEqual(other.get("/api/v1/findings").json()["items"], [])
        viewer = TestClient(self.app, base_url=self.settings.origin, headers={"origin": self.settings.origin})
        self.login(viewer, "localviewer")
        self.assertEqual(viewer.get(f"/api/v1/projects/{project['id']}").status_code, 200)
        self.assertEqual(viewer.post("/api/v1/projects", json={"name": "Denied"}).status_code, 403)
        self.assertEqual(
            viewer.post(
                "/api/v1/assessments",
                json={
                    "target_id": target["id"],
                    "idempotency_key": "viewer-denied",
                    "expected_scope_version": target["scope_version"],
                },
            ).status_code,
            403,
        )
        self.assertEqual(viewer.get("/api/v1/audit").status_code, 403)
        self.assertEqual(viewer.get("/api/v1/auth/members").status_code, 403)
        other.close()
        viewer.close()

    def test_session_csrf_expiry_logout_and_login_rate_limit(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as rejected:
            check_csrf(SessionRecord(csrf="ascii-valid"), "non-ascii-é")
        self.assertEqual(rejected.exception.status_code, 403)
        plain = TestClient(self.app, base_url=self.settings.origin, headers={"origin": self.settings.origin})
        self.assertEqual(plain.get("/api/v1/projects").status_code, 401)
        self.assertIn("HttpOnly", self.client.cookies and self.login(self.client).headers["set-cookie"])
        self.assertIn("SameSite=strict", self.login(self.client).headers["set-cookie"])
        csrf = self.client.headers.pop("x-csrf-token")
        self.assertEqual(self.client.post("/api/v1/projects", json={"name": "Denied"}).status_code, 403)
        self.client.headers["x-csrf-token"] = csrf
        self.client.headers["origin"] = "https://unapproved.example"
        self.assertEqual(self.client.post("/api/v1/projects", json={"name": "Denied"}).status_code, 403)
        self.client.headers["origin"] = self.settings.origin
        self.assertEqual(self.client.post("/api/v1/auth/logout").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/projects").status_code, 401)
        self.login(self.client)
        with self.sessions() as db:
            for session in db.scalars(select(SessionRecord)):
                session.expires_at = time.time() - 1
            db.commit()
        self.assertEqual(self.client.get("/api/v1/projects").status_code, 401)
        for _ in range(8):
            self.assertEqual(
                plain.post(
                    "/api/v1/auth/login", json={"username": "notfound", "password": "wrong"}
                ).status_code,
                401,
            )
        self.assertEqual(
            plain.post("/api/v1/auth/login", json={"username": "notfound", "password": "wrong"}).status_code,
            429,
        )
        plain.close()

    def test_scope_approval_and_idempotency(self):
        target, _ = self.target(approve=False)
        response = self.client.post(
            "/api/v1/assessments",
            json={
                "target_id": target["id"],
                "idempotency_key": "unapproved",
                "expected_scope_version": target["scope_version"],
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            self.client.post(
                f"/api/v1/targets/{target['id']}/approve",
                json={"acknowledgement": "I own a server", "expected_scope_version": target["scope_version"]},
            ).status_code,
            422,
        )
        self.client.post(
            f"/api/v1/targets/{target['id']}/approve",
            json={
                "acknowledgement": "I authorize this controlled laboratory target",
                "expected_scope_version": target["scope_version"],
            },
        )
        a = self.launch(target, key="stable-idempotency")
        b = self.launch(target, key="stable-idempotency")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(self.client.get("/api/v1/assessments").json()["total"], 1)
        self.assertEqual(
            self.client.post(
                "/api/v1/auth/login", json={"username": "u", "password": "private-value"}
            ).status_code,
            422,
        )
        self.assertNotIn(
            "private-value",
            self.client.post("/api/v1/auth/login", json={"username": "u", "password": "private-value"}).text,
        )
        self.assertEqual(self.client.post("/api/v1/projects", content=b"x" * 65537).status_code, 413)

    def test_tool_contracts_require_auth_and_expose_no_live_execution(self):
        plain = TestClient(self.app, base_url=self.settings.origin)
        self.assertEqual(plain.get("/api/v1/tool-contracts").status_code, 401)
        result = self.client.get("/api/v1/tool-contracts")
        self.assertEqual(result.status_code, 200)
        data = result.json()
        self.assertFalse(data["live_execution_enabled"])
        metasploit = next(row for row in data["adapters"] if row["adapter_id"] == "metasploit")
        self.assertEqual(metasploit["capability_state"], "planned")
        self.assertFalse(metasploit["execution_enabled"])
        self.assertNotIn("argv", data["proposal_schema"]["properties"])
        self.assertFalse(data["proposal_schema"]["additionalProperties"])
        plain.close()

    def test_valid_login_cannot_reset_failure_throttle(self):
        for _ in range(7):
            self.assertEqual(
                self.client.post(
                    "/api/v1/auth/login", json={"username": "notfound", "password": "wrong"}
                ).status_code,
                401,
            )
            self.login(self.client)
        self.assertEqual(
            self.client.post(
                "/api/v1/auth/login", json={"username": "notfound", "password": "wrong"}
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/auth/login", json={"username": "notfound", "password": "wrong"}
            ).status_code,
            429,
        )

    def test_cancel_queued_and_running(self):
        target, _ = self.target()
        assessment = self.launch(target)
        response = self.client.post(f"/api/v1/assessments/{assessment['id']}/cancel")
        self.assertEqual(response.json()["status"], "cancelled")
        self.assertFalse(run_one(self.sessions))
        slow, _ = self.target(url=self.url + "slow-header")
        live = self.launch(slow)
        thread = threading.Thread(target=run_one, args=(self.sessions,))
        thread.start()
        deadline = time.monotonic() + 3
        while self.client.get(f"/api/v1/assessments/{live['id']}").json()["status"] == "queued":
            if time.monotonic() > deadline:
                self.fail("Worker did not start")
            time.sleep(0.03)
        self.client.post(f"/api/v1/assessments/{live['id']}/cancel")
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.client.get(f"/api/v1/assessments/{live['id']}").json()["status"], "cancelled")

    def test_failed_retest_does_not_resolve_findings(self):
        target, _ = self.target()
        baseline = self.launch(target)
        run_one(self.sessions)
        self.server.shutdown()
        self.server.server_close()
        retest = self.launch(target, baseline["id"])
        run_one(self.sessions)
        self.assertEqual(self.client.get(f"/api/v1/assessments/{retest['id']}").json()["status"], "failed")
        self.assertTrue(
            all(f["status"] != "fixed" for f in self.client.get("/api/v1/findings").json()["items"])
        )

    def test_unexpected_worker_errors_keep_safe_classification_without_secret_text(self):
        target, _ = self.target()
        secret = "SyntheticSensitiveException7314"
        private_class = type(secret, (RuntimeError,), {})
        for exception, expected_class in (
            (RuntimeError(secret), "RuntimeError"),
            (TypeError(secret), "TypeError"),
            (private_class(secret), "Exception"),
        ):
            with self.subTest(expected_class=expected_class):
                assessment = self.launch(target)
                with patch("aegis.worker.scan", side_effect=exception):
                    self.assertTrue(run_one(self.sessions))
                result = self.client.get(f"/api/v1/assessments/{assessment['id']}").json()
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["observations"], [])
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["checks"][0]["error_class"], expected_class)
                report = self.client.get(f"/api/v1/reports/{assessment['id']}?format=json")
                self.assertEqual(report.status_code, 200)
                with self.sessions() as db:
                    event = db.scalar(
                        select(AuditEvent).where(
                            AuditEvent.resource_id == assessment["id"],
                            AuditEvent.action == "assessment.failed",
                        )
                    )
                    self.assertEqual(event.detail["checks"][0]["error_class"], expected_class)
                    self.assertTrue(verify_audit(db))
                    self.assertNotIn(secret, json.dumps([result, report.json(), event.detail]))

    def test_retest_redirect_drift_does_not_resolve_unvisited_endpoint(self):
        target, _ = self.target(url=self.url + "redirect-inside")
        baseline = self.launch(target)
        run_one(self.sessions)
        baseline_result = self.client.get(f"/api/v1/assessments/{baseline['id']}").json()
        original_ids = {f["id"] for f in baseline_result["findings"]}
        self.server.redirect_inside_path = "/other"
        self.server.secure_headers = True
        retest = self.launch(target, baseline["id"])
        run_one(self.sessions)
        retest_result = self.client.get(f"/api/v1/assessments/{retest['id']}").json()
        self.assertEqual(retest_result["status"], "completed")
        original = [f for f in self.client.get("/api/v1/findings").json()["items"] if f["id"] in original_ids]
        self.assertTrue(original)
        self.assertTrue(
            all(f["status"] == "confirmed" for f in original),
            "The repaired /other endpoint does not establish a fix for the unvisited /app",
        )

    def test_recovery_single_use_expiry(self):
        with self.sessions() as db:
            token = issue_recovery(db, "localowner")
            db.commit()
            consume_recovery(db, token, "Replacement-synthetic-password!")
            db.commit()
            with self.assertRaises(ValueError):
                consume_recovery(db, token, "Another-synthetic-password!")
            expired = issue_recovery(db, "localowner")
            record = db.scalar(select(RecoveryToken).where(RecoveryToken.used.is_(False)))
            record.expires_at = time.time() - 1
            db.commit()
            with self.assertRaises(ValueError):
                consume_recovery(db, expired, "Another-synthetic-password!")
        self.assertEqual(self.client.get("/api/v1/projects").status_code, 401)

    def test_audit_append_only_integrity(self):
        self.target()
        with self.sessions() as db:
            self.assertTrue(verify_audit(db))
            row = db.scalar(select(AuditEvent).limit(1))
            with self.assertRaises(IntegrityError):
                db.execute(text("UPDATE audit_events SET action='tampered' WHERE id=:id"), {"id": row.id})
            db.rollback()
            with self.assertRaises(IntegrityError):
                db.execute(text("DELETE FROM audit_events WHERE id=:id"), {"id": row.id})
            db.rollback()
            self.assertTrue(verify_audit(db))

    def test_real_dedicated_worker_process(self):
        from aegis.worker import WorkerSupervisor

        target, _ = self.target()
        assessment = self.launch(target)
        supervisor = WorkerSupervisor(self.settings)
        supervisor.start()
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                self.assertTrue(supervisor.alive(), "Dedicated worker exited unexpectedly")
                result = self.client.get(f"/api/v1/assessments/{assessment['id']}").json()
                if result["status"] == "completed":
                    break
                time.sleep(0.1)
            else:
                self.fail("Dedicated worker did not finish real assessment")
            self.assertGreater(len(result["observations"]), 0)
        finally:
            supervisor.stop()
        self.assertFalse(supervisor.alive())

    def test_duplicate_supervisor_cannot_interrupt_locked_worker(self):
        import fcntl

        from aegis.models import Assessment
        from aegis.worker import WorkerSupervisor

        target, _ = self.target()
        assessment = self.launch(target)
        with self.sessions() as db:
            row = db.get(Assessment, assessment["id"])
            row.status = "running"
            db.commit()
        with (self.settings.data_dir / "worker.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            WorkerSupervisor(self.settings).stop()
            with self.sessions() as db:
                self.assertEqual(db.get(Assessment, assessment["id"]).status, "running")

    def test_invalid_worker_parent_channel_leaves_jobs_unchanged(self):
        import subprocess
        import sys

        from aegis.config import ROOT
        from aegis.models import Assessment

        target, _ = self.target()
        assessment = self.launch(target)
        with self.sessions() as db:
            row = db.get(Assessment, assessment["id"])
            row.status, row.stage = "running", "Synthetic preexisting work"
            db.commit()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "aegis.worker",
                "--data-dir",
                str(self.settings.data_dir),
                "--parent-stdin",
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0, "Explicit parent lifetime channel must be a pipe")
        with self.sessions() as db:
            row = db.get(Assessment, assessment["id"])
            self.assertEqual(row.status, "running", "Rejected startup must not mutate stored work")
            self.assertEqual(row.stage, "Synthetic preexisting work")

    def test_parent_eof_cancels_inflight_and_leaves_next_job_queued(self):
        from aegis.worker import WorkerSupervisor
        from fixtures.safe_targets.server import FixtureHandler

        entered = threading.Event()
        original = FixtureHandler.do_GET

        def observed(handler):
            if handler.path == "/slow-header":
                entered.set()
            original(handler)

        slow, _ = self.target(url=self.url + "slow-header")
        live = self.launch(slow)
        following = self.launch(slow)
        supervisor = WorkerSupervisor(self.settings)
        with patch.object(FixtureHandler, "do_GET", observed):
            supervisor.start()
            try:
                self.assertTrue(entered.wait(5), "Worker did not begin the controlled HTTP request")
                assert supervisor.process is not None and supervisor.process.stdin is not None
                supervisor.process.stdin.close()
                self.assertEqual(supervisor.process.wait(timeout=8), 0)
                self.assertEqual(
                    self.client.get(f"/api/v1/assessments/{live['id']}").json()["status"], "cancelled"
                )
                self.assertEqual(
                    self.client.get(f"/api/v1/assessments/{following['id']}").json()["status"], "queued"
                )
            finally:
                supervisor.stop()

    def test_application_instance_lock_rejects_duplicate_data_directory(self):
        settings = Settings(self.settings.data_dir, start_worker=True)
        first = create_app(settings)
        second = create_app(settings)
        with TestClient(first, base_url=settings.origin):
            with self.assertRaisesRegex(RuntimeError, "Another SHARAY instance"):
                with TestClient(second, base_url=settings.origin):
                    self.fail("Two independent APIs cannot own the same local worker data")


if __name__ == "__main__":
    unittest.main()
