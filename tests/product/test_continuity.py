"""Refresh correctness and non-interleaved, redacted multi-writer checkpoints."""

import tempfile
import threading
import unittest
from pathlib import Path

from scripts.session_log import append_entry
from sharay.__main__ import ROOT, refresh


class ContinuityTests(unittest.TestCase):
    def test_main_prompt_preserves_complete_original_and_current_assignment(self):
        original = (ROOT / "docs/PRODUCT_SPECIFICATION.txt").read_text()
        prompt = (ROOT / "MAIN_PROMPT.txt").read_text()
        self.assertIn(original.replace("AEGIS", "SHARAY"), prompt)
        for term in ("LIVE", "METASPLOIT", "Codex", "Claude", "SESSION_LOG.md"):
            self.assertIn(term, prompt)
        self.assertIn(prompt, refresh())

    def test_checkpoint_replies_redact_secrets_and_preserve_prior_entries(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "session.md"
            first = append_entry("codex", "review-request", "Review a typed boundary", log_path=path)
            append_entry(
                "claude",
                "review-response",
                "Accepted. token=synthetic-private-value",
                reply_to=first,
                checks=["unit test -> exit 0"],
                log_path=path,
            )
            text = path.read_text()
            self.assertIn(first, text)
            self.assertIn("— claude — review-response", text)
            self.assertIn("Reply to: " + first, text)
            self.assertNotIn("synthetic-private-value", text)

    def test_concurrent_log_writers_keep_each_entry_complete(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "session.md"

            def write(index):
                append_entry(
                    "codex" if index % 2 else "claude",
                    "checkpoint",
                    f"Complete checkpoint {index}",
                    log_path=path,
                )

            threads = [threading.Thread(target=write, args=(index,)) for index in range(12)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            text = path.read_text()
            self.assertEqual(text.count("\n## entry-"), 12)
            for index in range(12):
                self.assertEqual(text.count(f"Complete checkpoint {index}\n"), 1)


if __name__ == "__main__":
    unittest.main()
