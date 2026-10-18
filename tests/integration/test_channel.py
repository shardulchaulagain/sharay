"""The two-way log channel: requests stay open until their addressee replies."""

import tempfile
import unittest
from pathlib import Path

from scripts.session_log import append_entry, inbox


class ChannelTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.log = Path(folder.name) / "session.md"

    def waiting(self, agent):
        return [entry["id"] for entry in inbox(agent, self.log)]

    def test_request_stays_open_until_the_addressee_replies(self):
        critique = append_entry(
            "codex", "critique", "The runner leaks metadata", to="claude", log_path=self.log
        )
        self.assertEqual(self.waiting("claude"), [critique])
        self.assertEqual(self.waiting("codex"), [])
        # Someone else replying, or the addressee writing without a reference, closes nothing.
        append_entry("human", "answer", "Noted", reply_to=critique, log_path=self.log)
        append_entry("claude", "checkpoint", "Unrelated progress", log_path=self.log)
        self.assertEqual(self.waiting("claude"), [critique])
        append_entry("claude", "answer", "Accepted; documented", reply_to=critique, log_path=self.log)
        self.assertEqual(self.waiting("claude"), [])

    def test_unaddressed_requests_and_recommendation_fields_reach_the_other_writer(self):
        review = append_entry("codex", "review-request", "Review the boundary", log_path=self.log)
        handoff = append_entry(
            "codex", "handoff", "Done for now", recommendation="Claude: answer the review", log_path=self.log
        )
        self.assertEqual(self.waiting("claude"), [review, handoff])
        self.assertEqual(self.waiting("codex"), [])

    def test_praise_and_plain_checkpoints_need_no_reply(self):
        append_entry("claude", "praise", "Strict booleans are a good call", to="codex", log_path=self.log)
        append_entry("claude", "checkpoint", "Tests ran", log_path=self.log)
        self.assertEqual(self.waiting("codex"), [])

    def test_a_counter_critique_keeps_the_conversation_open_for_the_other_side(self):
        first = append_entry("claude", "critique", "One boolean is too coarse", to="codex", log_path=self.log)
        counter = append_entry(
            "codex",
            "critique",
            "Your capability list is unverified",
            to="claude",
            reply_to=first,
            log_path=self.log,
        )
        self.assertEqual(self.waiting("codex"), [])
        self.assertEqual(self.waiting("claude"), [counter])

    def test_the_architect_reviewer_is_asked_only_explicitly_and_its_advice_needs_an_answer(self):
        unaddressed = append_entry("codex", "review-request", "Review the boundary", log_path=self.log)
        asked = append_entry("claude", "question", "Which adapter next?", to="gemini", log_path=self.log)
        advice = append_entry(
            "gemini", "recommendation", "Build the parser first", to="claude", log_path=self.log
        )
        self.assertEqual(self.waiting("gemini"), [asked])
        self.assertEqual(self.waiting("claude"), [unaddressed, advice])
        append_entry("claude", "answer", "Accepted with evidence", reply_to=advice, log_path=self.log)
        self.assertEqual(self.waiting("claude"), [unaddressed])

    def test_the_ideas_channel_is_a_separate_file_with_the_same_rules(self):
        import contextlib
        import io
        from unittest.mock import patch

        from scripts import log_view, session_log

        ideas = self.log.with_name("ideas.md")
        with patch.dict(session_log.LOGS, {"session": self.log, "ideas": ideas}):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
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
                        "An idea",
                    ]
                )
                session_log.main(["--agent", "claude", "--summary", "Ordinary progress"])
                log_view.main(["--agent", "codex", "--log", "ideas"])
            self.assertIn("An idea", out.getvalue())  # the reader printed it from the ideas channel
            self.assertEqual(len(inbox("codex", ideas)), 1)
            self.assertEqual(inbox("codex", self.log), [])
            self.assertIn("An idea", ideas.read_text())
            self.assertNotIn("An idea", self.log.read_text())
            self.assertNotIn("Ordinary progress", ideas.read_text())
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                session_log.main(["--agent", "claude", "--log", "/tmp/elsewhere.md", "--summary", "x"])

    def test_unknown_addressee_is_rejected(self):
        with self.assertRaises(ValueError):
            append_entry("claude", "question", "Anyone?", to="nobody", log_path=self.log)


if __name__ == "__main__":
    unittest.main()
