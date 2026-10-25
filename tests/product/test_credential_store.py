"""P1-4: encrypted credential store — ciphertext at rest, no plaintext in API or DB, auth resolution."""

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
from aegis.credentials import decrypt, encrypt, resolve_auth
from aegis.models import Credential, Organization, SessionRecord, User


class CredentialStoreTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="cred-")
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
            self.org_id = org.id
            owner = User(organization_id=org.id, username="owner-u", password_hash="x", role="owner")
            db.add(owner)
            db.flush()
            viewer = User(organization_id=org.id, username="viewer-u", password_hash="x", role="viewer")
            db.add(viewer)
            db.flush()
            self.owner_id = owner.id
            db.add(
                SessionRecord(
                    token_hash=digest("owner-tok"),
                    user_id=owner.id,
                    csrf="csrf",
                    expires_at=time.time() + 600,
                )
            )
            db.add(
                SessionRecord(
                    token_hash=digest("viewer-tok"),
                    user_id=viewer.id,
                    csrf="csrf",
                    expires_at=time.time() + 600,
                )
            )
            db.commit()

    def _client(self, token):
        c = self.enterContext(TestClient(self.app, base_url=self.settings.origin))
        c.cookies.set(COOKIE, token)
        c.headers.update({"origin": self.settings.origin, "x-csrf-token": "csrf"})
        return c

    def test_encrypt_round_trips_and_hides_plaintext(self):
        token = encrypt(self.settings, "s3cr3t-value")
        self.assertNotIn("s3cr3t-value", token)  # ciphertext must not leak plaintext
        self.assertEqual(decrypt(self.settings, token), "s3cr3t-value")
        with self.assertRaises(ValueError):
            decrypt(self.settings, "not-a-valid-token")

    def test_create_stores_ciphertext_and_list_hides_value(self):
        owner = self._client("owner-tok")
        created = owner.post(
            "/api/v1/credentials",
            json={"name": "session", "kind": "cookie", "value": "abc123", "header_name": "sid"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        body = created.json()
        self.assertNotIn("value", body)  # the secret never comes back
        self.assertNotIn("encrypted_value", body)

        listed = owner.get("/api/v1/credentials").json()["items"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["name"], "session")
        self.assertNotIn("value", listed[0])

        # At rest: the DB column holds ciphertext, never the plaintext.
        with self.app.state.sessions() as db:
            row = db.scalar(select(Credential).where(Credential.organization_id == self.org_id))
            self.assertNotIn("abc123", row.encrypted_value)
            self.assertEqual(decrypt(self.settings, row.encrypted_value), "abc123")

    def test_header_name_required_and_duplicate_rejected(self):
        owner = self._client("owner-tok")
        # header kind without header_name is a schema error.
        bad = owner.post(
            "/api/v1/credentials", json={"name": "h", "kind": "header", "value": "v"}
        )
        self.assertEqual(bad.status_code, 422, bad.text)
        # First bearer credential succeeds; same name again is a conflict.
        ok = owner.post("/api/v1/credentials", json={"name": "api", "kind": "bearer", "value": "tok"})
        self.assertEqual(ok.status_code, 201, ok.text)
        dup = owner.post("/api/v1/credentials", json={"name": "api", "kind": "bearer", "value": "tok2"})
        self.assertEqual(dup.status_code, 409, dup.text)

    def test_delete_removes_credential(self):
        owner = self._client("owner-tok")
        cid = owner.post(
            "/api/v1/credentials", json={"name": "api", "kind": "bearer", "value": "tok"}
        ).json()["id"]
        self.assertEqual(owner.delete(f"/api/v1/credentials/{cid}").status_code, 200)
        self.assertEqual(owner.get("/api/v1/credentials").json()["items"], [])

    def test_viewer_role_cannot_manage_credentials(self):
        viewer = self._client("viewer-tok")
        self.assertEqual(viewer.get("/api/v1/credentials").status_code, 403)
        self.assertEqual(
            viewer.post(
                "/api/v1/credentials", json={"name": "x", "kind": "bearer", "value": "v"}
            ).status_code,
            403,
        )

    def test_resolve_auth_groups_identities_for_matrix(self):
        # Two credentials under distinct identities -> two operator identities the IDOR matrix needs.
        rows = [
            Credential(
                kind="bearer", encrypted_value=encrypt(self.settings, "alice-tok"),
                identity="alice", subject_id="101", name="alice_tok",
            ),
            Credential(
                kind="cookie", header_name="sid", encrypted_value=encrypt(self.settings, "bob-sid"),
                identity="bob", subject_id="102", name="bob_sid",
            ),
            # An ungrouped credential still folds into the default context.
            Credential(kind="header", header_name="X-Api", encrypted_value=encrypt(self.settings, "k"), name="api"),
        ]
        resolved = resolve_auth(self.settings, rows)
        self.assertEqual(set(resolved["identities"]), {"alice", "bob"})
        self.assertEqual(resolved["identities"]["alice"]["headers"]["Authorization"], "Bearer alice-tok")
        self.assertEqual(resolved["identities"]["alice"]["user_id"], "101")
        self.assertEqual(resolved["identities"]["bob"]["cookies"], {"sid": "bob-sid"})
        self.assertEqual(resolved["identities"]["bob"]["user_id"], "102")
        self.assertEqual(resolved["headers"]["X-Api"], "k")  # ungrouped default context

    def test_resolve_auth_skips_undecryptable_credential(self):
        rows = [
            Credential(kind="bearer", encrypted_value=encrypt(self.settings, "ok"), name="good"),
            Credential(kind="bearer", encrypted_value="not-a-valid-token", name="broken"),
        ]
        resolved = resolve_auth(self.settings, rows)
        self.assertEqual(resolved["errors"], ["broken"])  # reported, not raised
        self.assertEqual(resolved["identity_names"], ["good"])
        self.assertEqual(resolved["headers"]["Authorization"], "Bearer ok")

    def test_resolve_auth_maps_each_kind(self):
        rows = [
            Credential(kind="cookie", header_name="sid", encrypted_value=encrypt(self.settings, "cv")),
            Credential(kind="header", header_name="X-Api", encrypted_value=encrypt(self.settings, "hv")),
            Credential(kind="bearer", encrypted_value=encrypt(self.settings, "bv")),
        ]
        for i, r in enumerate(rows):
            r.name = f"c{i}"
        resolved = resolve_auth(self.settings, rows)
        self.assertEqual(resolved["cookies"], {"sid": "cv"})
        self.assertEqual(resolved["headers"]["X-Api"], "hv")
        self.assertEqual(resolved["headers"]["Authorization"], "Bearer bv")
        self.assertEqual(resolved["identity_names"], ["c0", "c1", "c2"])


if __name__ == "__main__":
    unittest.main()
