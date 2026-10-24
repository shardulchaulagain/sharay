"""P1-2: source-analysis findings persist into the normal lifecycle when a target is given."""

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import select

from aegis.api import COOKIE, create_app
from aegis.auth import digest
from aegis.config import Settings
from aegis.models import Assessment, Finding, Organization, Project, SessionRecord, Target, User


class SourceAnalysisLifecycleTests(unittest.TestCase):
    def test_findings_persist_under_target_when_target_id_given(self):
        folder = tempfile.TemporaryDirectory(prefix="src-lifecycle-")
        self.addCleanup(folder.cleanup)
        base = Path(folder.name)
        for name in ("socket.create_connection", "socket.getaddrinfo"):
            net = patch(name, side_effect=AssertionError("No network"))
            net.start()
            self.addCleanup(net.stop)

        # A source tree with a secret-shaped value under the configured source root.
        src = base / "source" / "app"
        src.mkdir(parents=True)
        (src / "config.py").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEpAIBAAKCAQEA" * 20
            + "\n-----END RSA PRIVATE KEY-----\n"
        )

        settings = Settings(base, start_worker=False)
        app = create_app(settings)
        with app.state.sessions() as db:
            org = Organization(name="Org")
            db.add(org)
            db.flush()
            user = User(organization_id=org.id, username="operator", password_hash="x", role="owner")
            db.add(user)
            db.flush()
            db.add(
                SessionRecord(
                    token_hash=digest("tok"), user_id=user.id, csrf="csrf", expires_at=time.time() + 600
                )
            )
            project = Project(organization_id=org.id, owner_id=user.id, name="P")
            db.add(project)
            db.flush()
            target = Target(
                organization_id=org.id,
                project_id=project.id,
                url="http://127.0.0.1:8766/",
                scope={
                    "hosts": ["127.0.0.1"],
                    "allowed_origins": ["http://127.0.0.1:8766"],
                    "allowed_paths": ["/"],
                },
                verification_status="verified_lab",
            )
            db.add(target)
            db.flush()
            target_id = target.id
            db.commit()

        client = self.enterContext(TestClient(app, base_url=settings.origin))
        client.cookies.set(COOKIE, "tok")
        client.headers.update({"origin": settings.origin, "x-csrf-token": "csrf"})

        resp = client.post("/api/v1/source-analysis", json={"path": "app", "target_id": target_id})
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertGreaterEqual(len(body["findings"]), 1)  # the secret was found
        self.assertIsNotNone(body["assessment_id"])

        # The findings joined the lifecycle: a source-profile assessment + persisted Findings exist.
        with app.state.sessions() as db:
            asmt = db.get(Assessment, body["assessment_id"])
            self.assertEqual(asmt.profile, "source_analysis")
            findings = db.scalars(select(Finding).where(Finding.target_id == target_id)).all()
            self.assertTrue(any(f.category == "secret_exposure" for f in findings))

    def test_without_target_id_stays_ad_hoc(self):
        folder = tempfile.TemporaryDirectory(prefix="src-adhoc-")
        self.addCleanup(folder.cleanup)
        base = Path(folder.name)
        (base / "source" / "app").mkdir(parents=True)
        (base / "source" / "app" / "config.py").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEpAIBAAKCAQEA" * 20
            + "\n-----END RSA PRIVATE KEY-----\n"
        )
        settings = Settings(base, start_worker=False)
        app = create_app(settings)
        with app.state.sessions() as db:
            org = Organization(name="Org")
            db.add(org)
            db.flush()
            user = User(organization_id=org.id, username="operator", password_hash="x", role="owner")
            db.add(user)
            db.flush()
            db.add(
                SessionRecord(
                    token_hash=digest("tok"), user_id=user.id, csrf="csrf", expires_at=time.time() + 600
                )
            )
            db.commit()
        client = self.enterContext(TestClient(app, base_url=settings.origin))
        client.cookies.set(COOKIE, "tok")
        client.headers.update({"origin": settings.origin, "x-csrf-token": "csrf"})
        resp = client.post("/api/v1/source-analysis", json={"path": "app"})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertIsNone(resp.json()["assessment_id"])
        with app.state.sessions() as db:
            self.assertEqual(db.scalars(select(Assessment)).all(), [])


if __name__ == "__main__":
    unittest.main()
