"""Native-quit lifecycle regression using a real API and worker, without a GUI."""

import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aegis.__main__ import desktop, ready
from aegis.config import Settings


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
