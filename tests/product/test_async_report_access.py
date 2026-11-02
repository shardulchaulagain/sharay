"""Async report artifacts retain assessment ownership and their recorded digest."""

import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis.api import COOKIE, create_app
from aegis.auth import digest
from aegis.config import Settings
from aegis.models import Assessment, Organization, Project, SessionRecord, Target, User
from packages.reporting.async_renderer import ReportJobManager


class AsyncReportAccessTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="report-access-")
        self.addCleanup(folder.cleanup)
        settings = Settings(Path(folder.name), start_worker=False)
        self.app = create_app(settings)
        self.addCleanup(self.app.state.engine.dispose)
        self.owner = TestClient(self.app, base_url=settings.origin)
        self.other = TestClient(self.app, base_url=settings.origin)
        self.addCleanup(self.owner.close)
        self.addCleanup(self.other.close)

        with self.app.state.sessions() as db:
            users = []
            for name, token in (
                ("report-owner", "fixture-owner-token"),
                ("other-owner", "fixture-other-token"),
            ):
                organization = Organization(name=name)
                db.add(organization)
                db.flush()
                user = User(
                    organization_id=organization.id,
                    username=name,
                    password_hash="unused-synthetic-hash",
                    role="owner",
                )
                db.add(user)
                db.flush()
                db.add(
                    SessionRecord(
                        token_hash=digest(token),
                        user_id=user.id,
                        csrf="unused-read-only-fixture",
                        expires_at=time.time() + 600,
                    )
                )
                users.append(user)
            project = Project(organization_id=users[0].organization_id, owner_id=users[0].id, name="Fixture")
            db.add(project)
            db.flush()
            target = Target(
                organization_id=users[0].organization_id,
                project_id=project.id,
                url="http://127.0.0.1:8766/",
                scope={},
            )
            db.add(target)
            db.flush()
            assessment = Assessment(
                organization_id=users[0].organization_id,
                project_id=project.id,
                target_id=target.id,
                created_by=users[0].id,
                idempotency_key="fixture-assessment",
                scope_version=1,
                scope_snapshot={"target_url": target.url},
                status="completed",
            )
            db.add(assessment)
            db.flush()
            self.assessment_id = assessment.id
            db.commit()

        self.owner.cookies.set(COOKIE, "fixture-owner-token")
        self.other.cookies.set(COOKIE, "fixture-other-token")
        self.manager = ReportJobManager(Path(folder.name) / "reports", max_workers=1)
        self.addCleanup(self.manager.shutdown)
        self.job = self.manager.submit_render_job(
            self.assessment_id,
            "json",
            {"assessment": {"id": self.assessment_id}, "generated_at": "2026-10-17T00:00:00Z"},
        )
        deadline = time.monotonic() + 5
        while self.job.status in {"queued", "rendering"} and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.job.status, "completed")
        self.body = Path(self.job.output_path).read_bytes()
        manager_patch = patch("aegis.api.get_report_manager", return_value=self.manager)
        manager_patch.start()
        self.addCleanup(manager_patch.stop)
        self.status_url = f"/api/v1/reports/jobs/{self.job.job_id}"
        self.download_url = self.status_url + "/download"
        for name in ("socket.create_connection", "socket.getaddrinfo"):
            network_patch = patch(name, side_effect=AssertionError("No network in report access fixtures"))
            network_patch.start()
            self.addCleanup(network_patch.stop)

    def test_other_organization_cannot_read_or_download_report(self):
        for url in (self.status_url, self.download_url):
            with self.subTest(url=url):
                response = self.other.get(url)
                self.assertEqual(response.status_code, 404)
                self.assertNotIn(self.body, response.content)

    def test_owner_can_read_and_download_intact_report(self):
        response = self.owner.get(self.status_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["assessment_id"], self.assessment_id)
        response = self.owner.get(self.download_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.body)
        self.assertEqual(response.headers["x-report-sha256"], hashlib.sha256(self.body).hexdigest())

    def test_unknown_report_job_is_not_found(self):
        for suffix in ("", "/download"):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.owner.get("/api/v1/reports/jobs/missing" + suffix).status_code, 404)

    def test_unfinished_report_cannot_be_downloaded(self):
        self.job.status = "rendering"
        self.assertEqual(self.owner.get(self.download_url).status_code, 409)

    def test_tampered_report_cannot_be_downloaded(self):
        Path(self.job.output_path).write_bytes(b"Tampered report evidence.")
        response = self.owner.get(self.download_url)
        self.assertEqual(response.status_code, 409)
        self.assertNotIn(b"Tampered report evidence", response.content)

    def test_report_without_recorded_digest_cannot_be_downloaded(self):
        self.job.sha256_hash = None
        self.assertEqual(self.owner.get(self.download_url).status_code, 409)

    def test_missing_or_unreadable_report_returns_conflict(self):
        with patch("aegis.api.Path.read_bytes", side_effect=PermissionError("fixture inaccessible")):
            response = self.owner.get(self.download_url)
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("fixture inaccessible", response.text)
        Path(self.job.output_path).unlink()
        self.assertEqual(self.owner.get(self.download_url).status_code, 409)


if __name__ == "__main__":
    unittest.main()
