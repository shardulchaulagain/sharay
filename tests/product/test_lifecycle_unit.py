"""Owned pipe contracts and startup cleanup, without servers or scan dispatch."""

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.config import Settings
from aegis.lifecycle import watch_parent_stdin
from tests.product.test_desktop_lifecycle import lock_available


class LifetimePipeTests(unittest.TestCase):
    def test_eof_requests_stop_and_context_joins_watcher(self):
        reader, writer = os.pipe()
        stopped = threading.Event()
        duplicate = os.dup(reader)
        before = set(threading.enumerate())
        writer_closed = False
        try:
            with patch("aegis.lifecycle.os.dup", return_value=duplicate):
                with watch_parent_stdin(True, stopped.set):
                    self.assertFalse(stopped.wait(0.05))
                    os.close(writer)
                    writer_closed = True
                    self.assertTrue(stopped.wait(1), "Pipe EOF must reach the child stop flag")
            self.assertEqual(set(threading.enumerate()), before, "Watcher must not survive its context")
            os.fstat(reader)  # helper must not close the caller's original descriptor
            with self.assertRaises(OSError):
                os.fstat(duplicate)
        finally:
            os.close(reader)
            if not writer_closed:
                os.close(writer)

    def test_unexpected_channel_data_requests_stop(self):
        reader, writer = os.pipe()
        stopped = threading.Event()
        try:
            with patch("aegis.lifecycle.os.dup", return_value=os.dup(reader)):
                with watch_parent_stdin(True, stopped.set):
                    os.write(writer, b"invalid")
                    self.assertTrue(stopped.wait(1))
        finally:
            os.close(reader)
            os.close(writer)

    def test_normal_exit_joins_watcher_with_live_parent(self):
        reader, writer = os.pipe()
        stopped = threading.Event()
        before = set(threading.enumerate())
        try:
            with patch("aegis.lifecycle.os.dup", return_value=os.dup(reader)):
                with watch_parent_stdin(True, stopped.set):
                    pass
            self.assertFalse(stopped.is_set())
            self.assertEqual(set(threading.enumerate()), before)
        finally:
            os.close(reader)
            os.close(writer)

    def test_unmarked_process_does_not_inspect_stdin(self):
        with patch("aegis.lifecycle.os.dup", side_effect=AssertionError("Must not inspect stdin")):
            with watch_parent_stdin(False, lambda: self.fail("Unmarked process must not stop")):
                pass

    def test_marked_nonpipe_is_rejected(self):
        with tempfile.TemporaryFile() as source:
            with patch("aegis.lifecycle.os.dup", return_value=os.dup(source.fileno())):
                with self.assertRaisesRegex(ValueError, "must be a pipe"):
                    with watch_parent_stdin(True, lambda: None):
                        self.fail("Invalid lifetime channel cannot start")

    def test_channel_error_requests_stop(self):
        for failure in (OSError, ValueError):
            with self.subTest(error=failure.__name__):
                reader, writer = os.pipe()
                stopped = threading.Event()
                try:
                    with (
                        patch("aegis.lifecycle.os.dup", return_value=os.dup(reader)),
                        patch("aegis.lifecycle.select.select", side_effect=failure),
                    ):
                        with watch_parent_stdin(True, stopped.set):
                            self.assertTrue(stopped.wait(1))
                finally:
                    os.close(reader)
                    os.close(writer)

    def test_worker_spawn_failure_releases_application_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            settings = Settings(Path(folder))
            app = create_app(settings)
            with (
                patch(
                    "aegis.worker.WorkerSupervisor.start", side_effect=RuntimeError("Synthetic spawn failure")
                ),
                patch("aegis.worker.WorkerSupervisor.stop") as stop,
            ):
                with self.assertRaisesRegex(RuntimeError, "Synthetic spawn failure"):
                    with TestClient(app, base_url=settings.origin):
                        self.fail("Failed worker startup must fail API readiness")
                stop.assert_called_once()
            self.assertTrue(lock_available(settings.data_dir / "app.lock"))

    def test_worker_stop_failure_still_disposes_api_engine(self):
        with tempfile.TemporaryDirectory() as folder:
            settings = Settings(Path(folder))
            app = create_app(settings)
            try:
                with (
                    patch("aegis.worker.WorkerSupervisor.start"),
                    patch(
                        "aegis.worker.WorkerSupervisor.stop",
                        side_effect=RuntimeError("Synthetic stop failure"),
                    ),
                    patch.object(app.state.engine, "dispose") as dispose,
                ):
                    with self.assertRaisesRegex(RuntimeError, "Synthetic stop failure"):
                        with TestClient(app, base_url=settings.origin):
                            pass
                    dispose.assert_called_once()
                self.assertTrue(lock_available(settings.data_dir / "app.lock"))
            finally:
                app.state.engine.dispose()

    def test_supervisor_bookkeeping_failure_disposes_engine(self):
        from aegis.worker import WorkerSupervisor

        with tempfile.TemporaryDirectory() as folder:
            engine = Mock()
            with (
                patch("aegis.worker.create_database", return_value=(engine, object())),
                patch(
                    "aegis.worker.mark_interrupted", side_effect=RuntimeError("Synthetic database failure")
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "Synthetic database failure"):
                    WorkerSupervisor(Settings(Path(folder))).stop()
            engine.dispose.assert_called_once()


if __name__ == "__main__":
    unittest.main()
