"""P1-5: an AI investigation is persisted and survives a restart (not recomputed each view)."""

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


class AiInvestigationPersistenceTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="ai-persist-")
        self.addCleanup(folder.cleanup)
        self.base = Path(folder.name)
        for name in ("socket.create_connection", "socket.getaddrinfo"):
            net = patch(name, side_effect=AssertionError("No network in this fixture"))
            net.start()
            self.addCleanup(net.stop)
        # Seed a completed assessment once; both app instances share this DB directory.
        app = create_app(Settings(self.base, start_worker=False))
        with app.state.sessions() as db:
            org = Organization(name="Org")
            db.add(org)
            db.flush()
            user = User(organization_id=org.id, username="operator", password_hash="x", role="owner")
            db.add(user)
            db.flush()
            db.add(SessionRecord(token_hash=digest("tok"), user_id=user.id, csrf="csrf", expires_at=time.time() + 600))
            project = Project(organization_id=org.id, owner_id=user.id, name="P")
            db.add(project)
            db.flush()
            target = Target(
                organization_id=org.id,
                project_id=project.id,
                url="http://127.0.0.1:8766/",
                scope={},
                verification_status="verified_lab",
            )
            db.add(target)
            db.flush()
            db.add(
                Assessment(
                    id="asmt-1",
                    organization_id=org.id,
                    project_id=project.id,
                    target_id=target.id,
                    created_by=user.id,
                    idempotency_key="key-1",
                    scope_version=1,
                    scope_snapshot={"target_url": target.url},
                    status="completed",
                )
            )
            db.commit()

    def _client(self):
        settings = Settings(self.base, start_worker=False)
        app = create_app(settings)
        client = self.enterContext(TestClient(app, base_url=settings.origin))
        client.cookies.set(COOKIE, "tok")
        client.headers.update({"origin": settings.origin, "x-csrf-token": "csrf"})
        return app, client

    def test_investigation_persists_and_survives_restart(self):
        _, client = self._client()
        run = client.post("/api/v1/ai/investigate/asmt-1")
        self.assertEqual(run.status_code, 200, run.text)

        # Persisted on the row.
        app2, client2 = self._client()  # a fresh app == a restart (new engine, same DB)
        with app2.state.sessions() as db:
            self.assertIsNotNone(db.get(Assessment, "asmt-1").ai_investigation)

        got = client2.get("/api/v1/ai/investigations/asmt-1")
        self.assertEqual(got.status_code, 200, got.text)
        body = got.json()
        self.assertTrue(body.get("persisted"))
        self.assertEqual(body["assessment_id"], "asmt-1")


if __name__ == "__main__":
    unittest.main()
