"""Report jobs belong to an application data directory and historical authorization."""

import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis.api import COOKIE, create_app
from aegis.auth import digest
from aegis.config import Settings
from aegis.models import Assessment, Organization, Project, SessionRecord, Target, User


class ReportAppLifecycleTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="report-app-")
        self.addCleanup(folder.cleanup)
        self.base = Path(folder.name)
        for name in ("socket.create_connection", "socket.getaddrinfo"):
            network = patch(name, side_effect=AssertionError("No network in report lifecycle fixtures"))
            network.start()
            self.addCleanup(network.stop)

    def client(self, name):
        settings = Settings(self.base / name, start_worker=False)
        app = create_app(settings)
        with app.state.sessions() as db:
            organization = Organization(name="Fixture")
            db.add(organization)
            db.flush()
            user = User(
                organization_id=organization.id,
                username="report-fixture",
                password_hash="unused-synthetic-hash",
                role="owner",
            )
            db.add(user)
            db.flush()
            db.add(
                SessionRecord(
                    token_hash=digest("fixture-token"),
                    user_id=user.id,
                    csrf="fixture-csrf",
                    expires_at=time.time() + 600,
                )
            )
            project = Project(organization_id=organization.id, owner_id=user.id, name="Fixture")
            db.add(project)
            db.flush()
            target = Target(
                organization_id=organization.id,
                project_id=project.id,
                url="http://127.0.0.1:8766/",
                scope={},
                verification_status="pending",
            )
            db.add(target)
            db.flush()
            db.add(
                Assessment(
                    id="same-assessment-id",
                    organization_id=organization.id,
                    project_id=project.id,
                    target_id=target.id,
                    created_by=user.id,
                    idempotency_key="same-fixture-key",
                    scope_version=1,
                    scope_snapshot={
                        "target_url": target.url,
                        "verification_status": "operator_authorized",
                        "verification_method": "explicit_operator_authorization",
                        "authorized_by": user.id,
                        "approved_at": time.time(),
                    },
                    status="completed",
                )
            )
            db.commit()
        client = self.enterContext(TestClient(app, base_url=settings.origin))
        client.cookies.set(COOKIE, "fixture-token")
        client.headers.update({"origin": settings.origin, "x-csrf-token": "fixture-csrf"})
        return client

    def submit(self, client):
        response = client.post("/api/v1/reports/same-assessment-id?format=json")
        self.assertEqual(response.status_code, 202, response.text)
        return response.json()

    def test_jobs_are_isolated_by_app_data_directory(self):
        first = self.client("first")
        second = self.client("second")
        job = self.submit(first)
        status_url = f"/api/v1/reports/jobs/{job['job_id']}"
        self.assertEqual(second.get(status_url).status_code, 404)
        self.assertEqual(second.get(status_url + "/download").status_code, 404)
        self.assertIsNot(first.app.state.report_manager, second.app.state.report_manager)
        self.assertEqual(
            first.app.state.report_manager.reports_dir, (self.base / "first" / "reports").resolve()
        )
        self.assertEqual(
            second.app.state.report_manager.reports_dir, (self.base / "second" / "reports").resolve()
        )

    def test_app_shutdown_rejects_new_render_work(self):
        client = self.client("closing")
        self.submit(client)
        manager = client.app.state.report_manager
        client.__exit__(None, None, None)
        with self.assertRaises(RuntimeError):
            manager.submit_render_job("after-shutdown", "json", {})

    def test_report_uses_recorded_authorization_when_target_has_changed(self):
        client = self.client("historical")
        response = client.get("/api/v1/reports/same-assessment-id?format=json")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["target"]["verification_status"], "operator_authorized")
        self.assertEqual(response.json()["report_metadata"]["scope_authorization"], "operator_authorized")
        with client.app.state.sessions() as db:
            row = db.get(Assessment, "same-assessment-id")
            row.scope_snapshot = {"target_url": "http://127.0.0.1:8766/"}
            db.commit()
        response = client.get("/api/v1/reports/same-assessment-id?format=json")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["target"]["verification_status"], "not_recorded")
        self.assertEqual(response.json()["report_metadata"]["scope_authorization"], "not recorded")

    def test_renderer_dispatch_failure_is_service_unavailable(self):
        client = self.client("dispatch-failure")
        client.get("/api/v1/reports/jobs/missing")
        with patch.object(
            client.app.state.report_manager, "submit_render_job", side_effect=RuntimeError("closed")
        ):
            response = client.post("/api/v1/reports/same-assessment-id?format=json")
        self.assertEqual(response.status_code, 503, response.text)
        self.assertNotIn("closed", response.text)

    def test_launch_records_operator_authorization(self):
        client = self.client("authorization")
        now = datetime.now(UTC)
        with client.app.state.sessions() as db:
            previous = db.get(Assessment, "same-assessment-id")
            target = db.get(Target, previous.target_id)
            target.verification_status = "operator_authorized"
            target.authorized_by = previous.created_by
            target.approved_at = time.time()
            target.scope = {
                "hosts": ["127.0.0.1"],
                "allowed_origins": ["http://127.0.0.1:8766"],
                "allowed_cidrs": ["127.0.0.1/32"],
                "categories": ["http_headers"],
                "starts_at": (now - timedelta(minutes=1)).isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(),
            }
            target_id = target.id
            db.commit()
        response = client.post(
            "/api/v1/assessments",
            json={
                "target_id": target_id,
                "idempotency_key": "new-operator-assessment",
                "expected_scope_version": 1,
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        snapshot = response.json()["scope_snapshot"]
        self.assertEqual(snapshot["verification_status"], "operator_authorized")
        self.assertEqual(snapshot["verification_method"], "explicit_operator_authorization")

    def test_missing_historical_scope_is_reported(self):
        client = self.client("missing-snapshot")
        with client.app.state.sessions() as db:
            row = db.get(Assessment, "same-assessment-id")
            row.scope_snapshot = {}
            db.commit()
        for method in (client.get, client.post):
            response = method("/api/v1/reports/same-assessment-id?format=json")
            self.assertEqual(response.status_code, 409, response.text)


if __name__ == "__main__":
    unittest.main()
