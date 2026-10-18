"""Requester acceptance for the unadopted terminal API; no terminal is executed."""

from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import Mock, patch


class TerminalRoleAcceptance(TestCase):
    def setUp(self):
        self.guard = ExitStack()
        self.addCleanup(self.guard.close)
        for operation in (
            "socket.socket.connect",
            "socket.getaddrinfo",
            "subprocess.run",
            "subprocess.Popen",
            "os.fork",
        ):
            self.guard.enter_context(patch(operation, side_effect=AssertionError("Unexpected external I/O")))
        from fastapi.testclient import TestClient

        from aegis.api import create_app
        from aegis.auth import add_user, provision_owner
        from aegis.config import Settings

        self.folder = TemporaryDirectory(prefix="sharay-terminal-role-")
        self.addCleanup(self.folder.cleanup)
        self.settings = Settings(Path(self.folder.name), start_worker=False)
        self.app = create_app(self.settings)
        self.addCleanup(self.app.state.engine.dispose)
        password = "Synthetic-acceptance-password-761!"
        with self.app.state.sessions() as db:
            owner = provision_owner(db, "acceptowner", password)
            add_user(db, "acceptviewer", password, owner.organization_id, "viewer")
            db.commit()
        self.owner = TestClient(self.app, base_url=self.settings.origin)
        self.viewer = TestClient(self.app, base_url=self.settings.origin)
        for client, username in ((self.owner, "acceptowner"), (self.viewer, "acceptviewer")):
            self.addCleanup(client.close)
            client.headers["origin"] = self.settings.origin
            response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
            self.assertEqual(response.status_code, 200)
            client.headers["x-csrf-token"] = response.json()["csrf_token"]
        self.write = Mock()
        self.resize = Mock()
        session = SimpleNamespace(is_alive=lambda: True, write=self.write, resize=self.resize)
        self.guard.enter_context(patch("aegis.api.terminal_manager.get_session", return_value=session))

    def test_owner_can_write_to_the_controlled_session(self):
        response = self.owner.post(
            "/api/v1/interactive/sessions/synthetic/input", json={"data": "synthetic input\n"}
        )
        self.assertEqual(response.status_code, 200)
        self.write.assert_called_once_with(b"synthetic input\n")

    def test_viewer_cannot_write_to_the_controlled_session(self):
        response = self.viewer.post(
            "/api/v1/interactive/sessions/synthetic/input", json={"data": "synthetic input\n"}
        )
        self.assertEqual(response.status_code, 403)
        self.write.assert_not_called()

    def test_owner_can_resize_the_controlled_session(self):
        response = self.owner.post(
            "/api/v1/interactive/sessions/synthetic/resize", json={"cols": 80, "rows": 24}
        )
        self.assertEqual(response.status_code, 200)
        self.resize.assert_called_once_with(80, 24)

    def test_viewer_cannot_resize_the_controlled_session(self):
        response = self.viewer.post(
            "/api/v1/interactive/sessions/synthetic/resize", json={"cols": 80, "rows": 24}
        )
        self.assertEqual(response.status_code, 403)
        self.resize.assert_not_called()


if __name__ == "__main__":
    main(verbosity=2)
