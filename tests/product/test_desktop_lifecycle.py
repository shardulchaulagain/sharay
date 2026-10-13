"""Native-quit lifecycle regression using a real API and worker, without a GUI."""

import fcntl
import http.client
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aegis.__main__ import desktop, ready
from aegis.config import ROOT, Settings

# The outer harness also owns a pipe: cancelling the test closes its stdin,
# returns from the headless window and runs the real desktop cleanup.
LAUNCHER = """
import json, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from aegis.__main__ import desktop
from aegis.config import Settings
from tests.product.test_desktop_lifecycle import ClosingEvent
import subprocess

original = subprocess.Popen
def spawn(*args, **kwargs):
    child = original(*args, **kwargs)
    print(json.dumps({'event': 'spawn', 'pid': child.pid}), flush=True)
    return child
window = SimpleNamespace(events=SimpleNamespace(closing=ClosingEvent()))
def start(**kwargs):
    print(json.dumps({'event': 'ready'}), flush=True)
    sys.stdin.buffer.read()
view = SimpleNamespace(create_window=lambda *a, **kw: window, start=start)
with patch.dict('sys.modules', {'webview': view}), \\
     patch('aegis.__main__.desktop_assets_available', return_value=True), \\
     patch('aegis.__main__.subprocess.Popen', side_effect=spawn):
    desktop(Settings(Path(sys.argv[1]), int(sys.argv[2])), browser=False, smoke_seconds=0)
"""


def lock_available(path):
    with path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False


def running(pid):
    result = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return bool(result.stdout.strip()) and not result.stdout.strip().startswith("Z")


class ClosingEvent:
    """Headless double for pywebview's synchronous closing-event contract."""

    def __init__(self):
        self.handlers = []

    def __iadd__(self, callback):
        self.handlers.append(callback)
        return self

    def set(self):
        return any(callback() is False for callback in self.handlers)


class DesktopLifecycleTests(unittest.TestCase):
    def wait_for(self, predicate, message, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        self.fail(message)

    def event(self, process, expected):
        assert process.stdout is not None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if select.select([process.stdout], [], [], 0.1)[0]:
                line = process.stdout.readline()
                self.assertTrue(line, "Launcher exited before readiness")
                value = json.loads(line)
                if value["event"] == expected:
                    return value
        self.fail("Launcher did not emit " + expected)

    @contextmanager
    def launcher(self, settings):
        process = subprocess.Popen(
            [sys.executable, "-c", LAUNCHER, str(settings.data_dir), str(settings.port)],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            bufsize=0,
            start_new_session=True,
        )
        pids = []
        try:
            pids.append(self.event(process, "spawn")["pid"])
            self.event(process, "ready")
            self.wait_for(
                lambda: not lock_available(settings.data_dir / "worker.lock"),
                "Worker never acquired its lock",
            )
            children = subprocess.run(
                ["pgrep", "-P", str(pids[0])], capture_output=True, text=True, check=True
            )
            pids.extend(int(value) for value in children.stdout.split())
            self.assertEqual(len(pids), 2, "Expected exactly the API and its controlled worker")
            yield process, pids
        finally:
            assert process.stdin is not None
            process.stdin.close()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            # Failure/baseline cleanup signals only these newly captured children.
            for pid in pids:
                if running(pid):
                    os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 15
            while any(running(pid) for pid in pids) and time.monotonic() < deadline:
                time.sleep(0.1)
            for pid in pids:
                if running(pid):
                    os.kill(pid, signal.SIGKILL)
            self.wait_for(lambda: all(not running(pid) for pid in pids), "Controlled test children leaked")
            assert process.stdout is not None
            process.stdout.close()

    def settings(self, folder):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return Settings(Path(folder), probe.getsockname()[1])

    def assert_children_stopped(self, settings, pids):
        self.wait_for(lambda: not ready(settings), "API remained ready after owner died")
        self.wait_for(
            lambda: all(not running(pid) for pid in pids), "Detached API or worker survived its owner"
        )
        self.assertTrue(lock_available(settings.data_dir / "app.lock"))
        self.assertTrue(lock_available(settings.data_dir / "worker.lock"))

    def test_sigkill_launcher_stops_detached_api_and_worker(self):
        with tempfile.TemporaryDirectory() as folder:
            settings = self.settings(folder)
            with self.launcher(settings) as (process, pids):
                process.kill()
                process.wait(timeout=5)
                self.assert_children_stopped(settings, pids)

    def test_sigkill_api_stops_worker_while_launcher_lives(self):
        with tempfile.TemporaryDirectory() as folder:
            settings = self.settings(folder)
            with self.launcher(settings) as (process, pids):
                os.kill(pids[0], signal.SIGKILL)
                self.assert_children_stopped(settings, pids)
                self.assertIsNone(process.poll(), "Headless window still owns the launcher")

    def test_early_parent_eof_shuts_down_after_startup(self):
        with tempfile.TemporaryDirectory() as folder:
            settings = self.settings(folder)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "aegis",
                    "--data-dir",
                    folder,
                    "--port",
                    str(settings.port),
                    "serve",
                    "--parent-stdin",
                ],
                cwd=ROOT,
                stdin=subprocess.PIPE,
            )
            try:
                assert process.stdin is not None
                process.stdin.close()
                self.assertEqual(process.wait(timeout=15), 0)
                self.assertFalse(ready(settings))
                self.assertTrue(lock_available(settings.data_dir / "app.lock"))
                self.assertTrue(lock_available(settings.data_dir / "worker.lock"))
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)

    def test_readiness_connection_reset_is_unavailable(self):
        for failure in (
            ConnectionResetError(),
            http.client.BadStatusLine("Synthetic interrupted response"),
            http.client.IncompleteRead(b""),
        ):
            with self.subTest(error=type(failure).__name__):
                with patch("aegis.__main__.urllib.request.urlopen", side_effect=failure):
                    self.assertFalse(ready(Settings(Path("unused"))))

    def test_standalone_serve_survives_closed_stdin_until_signalled(self):
        with tempfile.TemporaryDirectory() as folder:
            settings = self.settings(folder)
            process = subprocess.Popen(
                [sys.executable, "-m", "aegis", "--data-dir", folder, "--port", str(settings.port), "serve"],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
            )
            try:
                self.wait_for(lambda: ready(settings), "Standalone server failed startup")
                time.sleep(0.2)
                self.assertIsNone(process.poll(), "Unmarked stdin EOF must not stop standalone serve")
            finally:
                process.terminate()
                process.wait(timeout=15)
            self.wait_for(lambda: lock_available(settings.data_dir / "worker.lock"), "Worker did not stop")

    def test_smoke_exit_stops_owned_children(self):
        with tempfile.TemporaryDirectory() as folder:
            settings = self.settings(folder)
            with patch("aegis.__main__.desktop_assets_available", return_value=True):
                desktop(settings, browser=False, smoke_seconds=0.01)
            self.assertFalse(ready(settings))
            self.assertTrue(lock_available(settings.data_dir / "worker.lock"))

    def test_browser_interrupt_stops_owned_children(self):
        with tempfile.TemporaryDirectory() as folder:
            settings = self.settings(folder)

            def open_browser(url):
                self.assertEqual(url, settings.origin)
                self.assertTrue(ready(settings))
                raise KeyboardInterrupt

            with (
                patch("aegis.__main__.desktop_assets_available", return_value=True),
                patch("webbrowser.open", side_effect=open_browser),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    desktop(settings, browser=True, smoke_seconds=0)
            self.assertFalse(ready(settings))
            self.assertTrue(lock_available(settings.data_dir / "worker.lock"))

    def test_native_quit_stops_api_before_python_finally(self):
        # Simulate Cocoa's applicationShouldTerminate path: its synchronous
        # closing event must stop children before native exit can bypass finally.
        with tempfile.TemporaryDirectory() as folder, socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()
            settings = Settings(Path(folder), port)
            window = SimpleNamespace(events=SimpleNamespace())
            window.events.closing = ClosingEvent()
            invoked = []

            def start(**_kwargs):
                self.assertTrue(ready(settings))
                self.assertFalse(window.events.closing.set())
                self.assertFalse(ready(settings), "Native quit must stop API before webview.start returns")
                invoked.append(True)

            view = SimpleNamespace(create_window=lambda *_args, **_kwargs: window, start=start)
            with (
                patch.dict("sys.modules", {"webview": view}),
                patch("aegis.__main__.desktop_assets_available", return_value=True),
            ):
                desktop(settings, browser=False, smoke_seconds=0)
            self.assertEqual(invoked, [True])
            self.assertFalse(ready(settings))


if __name__ == "__main__":
    unittest.main()
