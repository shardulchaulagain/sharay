"""P1-8 (RBAC): non-admin roles only reach projects they belong to."""

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
from aegis.models import Organization, Project, ProjectMember, SessionRecord, User


class ProjectRbacTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="rbac-")
        self.addCleanup(folder.cleanup)
        self.settings = Settings(Path(folder.name), start_worker=False)
        self.app = create_app(self.settings)
        for name in ("socket.create_connection", "socket.getaddrinfo"):
            net = patch(name, side_effect=AssertionError("No network"))
            net.start()
            self.addCleanup(net.stop)
        with self.app.state.sessions() as db:
            org = Organization(name="Org")
            db.add(org)
            db.flush()
            self.owner_id = self._user(db, org.id, "owner-u", "owner", "owner-tok")
            self.analyst_id = self._user(db, org.id, "analyst-u", "analyst", "analyst-tok")
            # A project the analyst is NOT a member of.
            project = Project(organization_id=org.id, owner_id=self.owner_id, name="Secret")
            db.add(project)
            db.flush()
            db.add(ProjectMember(project_id=project.id, user_id=self.owner_id))
            self.project_id = project.id
            db.commit()

    @staticmethod
    def _user(db, org_id, username, role, token):
        user = User(organization_id=org_id, username=username, password_hash="x", role=role)
        db.add(user)
        db.flush()
        db.add(
            SessionRecord(
                token_hash=digest(token), user_id=user.id, csrf="csrf", expires_at=time.time() + 600
            )
        )
        return user.id

    def _client(self, token):
        c = self.enterContext(TestClient(self.app, base_url=self.settings.origin))
        c.cookies.set(COOKIE, token)
        c.headers.update({"origin": self.settings.origin, "x-csrf-token": "csrf"})
        return c

    def test_non_member_analyst_denied_until_granted(self):
        owner = self._client("owner-tok")
        analyst = self._client("analyst-tok")

        # Owner (admin) sees and reads the project; analyst (non-member) does not.
        self.assertEqual(len(owner.get("/api/v1/projects").json()["items"]), 1)
        self.assertEqual(analyst.get("/api/v1/projects").json()["items"], [])
        self.assertEqual(analyst.get(f"/api/v1/projects/{self.project_id}").status_code, 404)

        # Grant membership -> analyst can list and read it.
        add = owner.post(f"/api/v1/projects/{self.project_id}/members", json={"user_id": self.analyst_id})
        self.assertEqual(add.status_code, 201, add.text)
        self.assertEqual(len(analyst.get("/api/v1/projects").json()["items"]), 1)
        self.assertEqual(analyst.get(f"/api/v1/projects/{self.project_id}").status_code, 200)

        # Revoke -> access is lost again.
        self.assertEqual(
            owner.delete(f"/api/v1/projects/{self.project_id}/members/{self.analyst_id}").status_code, 200
        )
        self.assertEqual(analyst.get(f"/api/v1/projects/{self.project_id}").status_code, 404)

    def test_creator_is_auto_added_as_member(self):
        analyst = self._client("analyst-tok")
        created = analyst.post("/api/v1/projects", json={"name": "Mine"})
        self.assertEqual(created.status_code, 201, created.text)
        pid = created.json()["id"]
        # The analyst created it, so they are a member and can read it.
        self.assertEqual(analyst.get(f"/api/v1/projects/{pid}").status_code, 200)
        with self.app.state.sessions() as db:
            self.assertTrue(
                db.scalar(
                    select(ProjectMember.id).where(
                        ProjectMember.project_id == pid, ProjectMember.user_id == self.analyst_id
                    )
                )
            )


if __name__ == "__main__":
    unittest.main()
