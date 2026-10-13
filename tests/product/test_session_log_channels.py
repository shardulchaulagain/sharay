"""The operator-selected ideas channel preserves independent routing and defaults."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import log_view, session_log


class ChannelSelectionTests(unittest.TestCase):
    def test_cli_channels_isolate_requests_replies_and_reader_cursors(self):
        with tempfile.TemporaryDirectory() as folder:
            session = Path(folder, "session.md")
            ideas = Path(folder, "ideas.md")
            output = io.StringIO()
            with patch.dict(session_log.LOGS, {"session": session, "ideas": ideas}):
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(
                        session_log.main(
                            [
                                "--agent",
                                "claude",
                                "--log",
                                "ideas",
                                "--kind",
                                "question",
                                "--to",
                                "codex",
                                "--summary",
                                "A bounded experiment",
                            ]
                        ),
                        0,
                    )
                    request = session_log.inbox("codex", ideas)[0]["id"]
                    self.assertEqual(
                        session_log.main(["--agent", "claude", "--summary", "Legacy progress"]), 0
                    )
                    self.assertEqual(log_view.main(["--agent", "codex", "--log", "ideas"]), 0)
                    self.assertEqual(
                        session_log.main(
                            [
                                "--agent",
                                "codex",
                                "--log",
                                "ideas",
                                "--kind",
                                "answer",
                                "--to",
                                "claude",
                                "--reply-to",
                                request,
                                "--summary",
                                "Measured decision",
                            ]
                        ),
                        0,
                    )
                self.assertEqual(session_log.inbox("codex", ideas), [])
                self.assertEqual(session_log.inbox("codex", session), [])
                self.assertIn("A bounded experiment", output.getvalue())
                self.assertIn("Legacy progress", session.read_text())
                self.assertNotIn("A bounded experiment", session.read_text())
                self.assertNotIn("Legacy progress", ideas.read_text())
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as rejected:
                        log_view.main(["--agent", "codex", "--since", request])
                    self.assertEqual(rejected.exception.code, 2)

    def test_cli_refuses_arbitrary_channel_paths_and_linked_logs(self):
        with tempfile.TemporaryDirectory() as folder:
            session = Path(folder, "session.md")
            ideas = Path(folder, "ideas.md")
            outside = Path(folder, "outside.md")
            outside.write_text("preserve")
            ideas.symlink_to(outside)
            with patch.dict(session_log.LOGS, {"session": session, "ideas": ideas}):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        session_log.main(["--agent", "codex", "--log", str(outside), "--summary", "Refuse"])
                    with self.assertRaises(SystemExit) as rejected:
                        session_log.main(["--agent", "codex", "--log", "ideas", "--summary", "Refuse"])
                    self.assertEqual(rejected.exception.code, 2)
                    with self.assertRaises(SystemExit) as rejected:
                        log_view.main(["--agent", "codex", "--log", "ideas"])
                    self.assertEqual(rejected.exception.code, 2)
            self.assertEqual(outside.read_text(), "preserve")
            self.assertFalse(session.exists())


if __name__ == "__main__":
    unittest.main()
