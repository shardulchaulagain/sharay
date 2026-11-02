"""A transient SQLite write-lock must surface as a retryable 503, never a 500 (e.g. login overlapping the
worker's write transaction). Guards the OperationalError handler + get_db retry added for DB resilience."""

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from aegis.api import create_app, get_db
from aegis.config import Settings


class DbBusyHandlerTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.settings = Settings(Path(self.folder.name), start_worker=False)
        self.app = create_app(self.settings)

    def _client_raising(self, orig_message):
        def _raise():
            raise OperationalError("BEGIN IMMEDIATE", {}, Exception(orig_message))

        self.app.dependency_overrides[get_db] = _raise
        self.addCleanup(self.app.dependency_overrides.clear)
        c = TestClient(self.app, base_url=self.settings.origin, raise_server_exceptions=False)
        c.headers["origin"] = self.settings.origin
        return c

    def test_locked_db_returns_retryable_503_not_500(self):
        # /auth/bootstrap depends on the DB; a lock during that must become a retryable 503, not a 500.
        with self._client_raising("database is locked") as c:
            r = c.get("/api/v1/auth/bootstrap")
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.headers.get("Retry-After"), "1")

    def test_non_lock_operational_error_is_not_masked_as_503(self):
        with self._client_raising("disk I/O error") as c:
            r = c.get("/api/v1/auth/bootstrap")
        self.assertNotEqual(r.status_code, 503)  # a real DB fault must not be hidden behind "busy, retry"


if __name__ == "__main__":
    unittest.main()
