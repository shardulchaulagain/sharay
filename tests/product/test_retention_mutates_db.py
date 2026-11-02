"""P1-7: the retention endpoint must actually delete expired rows, not just report them."""

import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from aegis.api import COOKIE, create_app
from aegis.auth import digest
from aegis.config import Settings
from aegis.models import (
    Assessment,
    Observation,
    Organization,
    Project,
    SessionRecord,
    Target,
    User,
)


class RetentionMutatesDbTests(unittest.TestCase):
    def test_expired_assessment_and_observations_are_deleted(self):
        folder = tempfile.TemporaryDirectory(prefix="retention-")
        self.addCleanup(folder.cleanup)
        settings = Settings(Path(folder.name), start_worker=False)
        app = create_app(settings)
        now = time.time()
        with app.state.sessions() as db:
            org = Organization(name="Fixture")
            db.add(org)
            db.flush()
            user = User(
                organization_id=org.id,
                username="control",
                password_hash="x",
                role="owner",
            )
            db.add(user)
            db.flush()
            db.add(
                SessionRecord(token_hash=digest("tok"), user_id=user.id, csrf="csrf", expires_at=now + 600)
            )
            project = Project(organization_id=org.id, owner_id=user.id, name="P")
            db.add(project)
            db.flush()
            target = Target(
                organization_id=org.id,
                project_id=project.id,
                url="http://127.0.0.1:8766/",
                scope={},
                verification_status="pending",
            )
            db.add(target)
            db.flush()
            # One assessment 120 days old (expired at 90d), one fresh.
            for aid, created in (("old-asmt", now - 120 * 86400), ("fresh-asmt", now)):
                db.add(
                    Assessment(
                        id=aid,
                        organization_id=org.id,
                        project_id=project.id,
                        target_id=target.id,
                        created_by=user.id,
                        idempotency_key=f"key-{aid}",
                        scope_version=1,
                        scope_snapshot={"target_url": target.url},
                        status="completed",
                        created_at=created,
                    )
                )
                db.add(
                    Observation(
                        organization_id=org.id,
                        assessment_id=aid,
                        data={"kind": "http_response"},
                        evidence_hash=f"hash-{aid}",
                    )
                )
            db.commit()

        client = self.enterContext(TestClient(app, base_url=settings.origin))
        client.cookies.set(COOKIE, "tok")
        client.headers.update({"origin": settings.origin, "x-csrf-token": "csrf"})

        resp = client.post("/api/v1/lifecycle/retention?assessment_days=90&evidence_days=14")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["purged_assessments_count"], 1)

        # The DB is actually mutated: the expired assessment and its observation are gone; fresh stays.
        with app.state.sessions() as db:
            asmt_ids = set(db.scalars(select(Assessment.id)).all())
            obs_asmt_ids = set(db.scalars(select(Observation.assessment_id)).all())
        self.assertEqual(asmt_ids, {"fresh-asmt"})
        self.assertEqual(obs_asmt_ids, {"fresh-asmt"})

    def test_old_observation_pii_is_redacted_in_db(self):
        folder = tempfile.TemporaryDirectory(prefix="retention-pii-")
        self.addCleanup(folder.cleanup)
        settings = Settings(Path(folder.name), start_worker=False)
        app = create_app(settings)
        now = time.time()
        with app.state.sessions() as db:
            org = Organization(name="Fixture")
            db.add(org)
            db.flush()
            user = User(organization_id=org.id, username="control", password_hash="x", role="owner")
            db.add(user)
            db.flush()
            db.add(
                SessionRecord(token_hash=digest("tok"), user_id=user.id, csrf="csrf", expires_at=now + 600)
            )
            project = Project(organization_id=org.id, owner_id=user.id, name="P")
            db.add(project)
            db.flush()
            target = Target(
                organization_id=org.id,
                project_id=project.id,
                url="http://127.0.0.1:8766/",
                scope={},
                verification_status="pending",
            )
            db.add(target)
            db.flush()
            # A fresh assessment (not purged) with an OLD observation (older than the 14d evidence
            # cutoff) that contains PII in its raw payload.
            db.add(
                Assessment(
                    id="keep-asmt",
                    organization_id=org.id,
                    project_id=project.id,
                    target_id=target.id,
                    created_by=user.id,
                    idempotency_key="key-keep",
                    scope_version=1,
                    scope_snapshot={"target_url": target.url},
                    status="completed",
                    created_at=now,
                )
            )
            db.add(
                Observation(
                    organization_id=org.id,
                    assessment_id="keep-asmt",
                    data={"note": "reporter alice@example.com filed this"},
                    evidence_hash="h-pii",
                    observed_at=now - 20 * 86400,
                )
            )
            db.commit()

        client = self.enterContext(TestClient(app, base_url=settings.origin))
        client.cookies.set(COOKIE, "tok")
        client.headers.update({"origin": settings.origin, "x-csrf-token": "csrf"})

        resp = client.post("/api/v1/lifecycle/retention?assessment_days=90&evidence_days=14")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertGreaterEqual(resp.json()["redacted_records_count"], 1)

        with app.state.sessions() as db:
            obs = db.scalar(select(Observation).where(Observation.assessment_id == "keep-asmt"))
            self.assertNotIn("alice@example.com", str(obs.data))  # PII scrubbed from the DB row
            self.assertIn("REDACTED", str(obs.data))


if __name__ == "__main__":
    unittest.main()
