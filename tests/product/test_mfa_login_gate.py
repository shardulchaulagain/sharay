"""P1-8 (MFA): an enrolled account must present a valid TOTP or backup code to sign in."""

import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

from aegis.auth import TOTPEngine, provision_owner, sign_in
from aegis.config import Settings
from aegis.database import create_database
from aegis.models import User

PW = "StrongLabPass!2026"


class MfaLoginGateTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="mfa-")
        self.addCleanup(folder.cleanup)
        self.settings = Settings(Path(folder.name), start_worker=False)
        self.engine, self.sessions = create_database(self.settings)  # applies migration 0004
        self.addCleanup(self.engine.dispose)
        with self.sessions() as db:
            self.user_id = provision_owner(db, "operator", PW, "Org").id
            db.commit()

    def _enroll(self, db):
        row = db.get(User, self.user_id)
        secret = TOTPEngine.generate_secret()
        plain, hashed = TOTPEngine.generate_backup_codes(2)
        row.totp_secret, row.totp_enabled, row.totp_backup_hashes = secret, True, hashed
        db.commit()
        return secret, plain

    def test_non_enrolled_user_logs_in_without_code(self):
        with self.sessions() as db:
            user, _, _ = sign_in(db, "operator", PW, "c", 600)
            self.assertEqual(user.username, "operator")

    def test_enrolled_requires_a_valid_code(self):
        with self.sessions() as db:
            secret, _ = self._enroll(db)
            with self.assertRaises(HTTPException) as missing:
                sign_in(db, "operator", PW, "c", 600)
            self.assertEqual(missing.exception.status_code, 401)
            with self.assertRaises(HTTPException):
                sign_in(db, "operator", PW, "c", 600, code="000000")
            user, _, _ = sign_in(db, "operator", PW, "c", 600, code=TOTPEngine.generate_otp(secret))
            self.assertEqual(user.username, "operator")

    def test_backup_code_works_and_is_consumed(self):
        with self.sessions() as db:
            _, plain = self._enroll(db)
            sign_in(db, "operator", PW, "c", 600, code=plain[0])
            remaining = db.get(User, self.user_id).totp_backup_hashes
            self.assertEqual(len(remaining), 1)  # the used code was consumed
            # The same backup code cannot be reused.
            with self.assertRaises(HTTPException):
                sign_in(db, "operator", PW, "c", 600, code=plain[0])


if __name__ == "__main__":
    unittest.main()
