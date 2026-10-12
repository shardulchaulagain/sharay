"""Reject accidental text collections before a coordination entry is written."""

import tempfile
import unittest
from pathlib import Path

from scripts.session_log import append_entry, read_log


class SessionLogInputTests(unittest.TestCase):
    def test_bare_text_paths_and_checks_cannot_append_character_lists(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "log.md"
            for field in ("paths", "checks"):
                for value in ("source.py", b"source.py", bytearray(b"source.py")):
                    with self.subTest(field=field, value_type=type(value).__name__):
                        with self.assertRaisesRegex(ValueError, "collections, not bare text"):
                            append_entry(
                                "codex", "checkpoint", "Synthetic entry", log_path=log, **{field: value}
                            )
                        self.assertFalse(log.exists())

    def test_lists_and_single_item_tuples_keep_whole_evidence_lines(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "log.md"
            for values in (["source.py"], ("source.py",)):
                append_entry(
                    "codex", "checkpoint", "Synthetic entry", paths=values, checks=values, log_path=log
                )
            text = read_log(log)
            self.assertEqual(text.count("- source.py\n"), 4)
            self.assertNotIn("- s\n", text)
