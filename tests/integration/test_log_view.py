"""The unread view and tree hash that let writers read and re-verify less."""

import tempfile
import unittest
from pathlib import Path

from scripts.log_view import tree_hash, unread
from scripts.session_log import append_entry


class LogViewTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.log = self.folder / "session.md"

    def test_unread_is_everything_by_others_since_my_last_entry(self):
        append_entry("codex", "checkpoint", "old news", log_path=self.log)
        append_entry("claude", "checkpoint", "my last entry", log_path=self.log)
        append_entry("codex", "critique", "new for claude " + "x" * 900, to="claude", log_path=self.log)
        append_entry("gemini", "answer", "also new", log_path=self.log)
        entries = unread("claude", self.log)
        self.assertEqual(
            [("codex — critique" in e, "gemini — answer" in e) for e in entries],
            [(True, False), (False, True)],
        )
        self.assertNotIn("old news", "".join(entries))
        short = unread("claude", self.log, brief=120)
        self.assertLess(len(short[0]), 200)
        self.assertIn("read the log for the rest", short[0])
        self.assertEqual(unread("gemini", self.log), [])
        # A writer with no entries yet sees the whole log.
        self.assertEqual(len(unread("human", self.log)), 4)
        with self.assertRaises(ValueError):
            unread("nobody", self.log)

    def test_entries_posted_while_i_was_writing_are_reachable_by_naming_what_i_last_read(self):
        marker = append_entry("codex", "checkpoint", "the last entry claude read", log_path=self.log)
        append_entry("codex", "checkpoint", "posted while claude was writing", log_path=self.log)
        append_entry("claude", "checkpoint", "written without having seen it", log_path=self.log)
        self.assertEqual(unread("claude", self.log), [])
        with self.assertRaisesRegex(ValueError, "Unknown entry id"):
            unread("claude", self.log, since="entry-0000000000000000")
        missed = unread("claude", self.log, since=marker)
        self.assertEqual(len(missed), 1)
        self.assertIn("posted while claude was writing", missed[0])

    def test_tree_hash_changes_with_source_content_and_ignores_caches(self):
        source = self.folder / "services"
        source.mkdir()
        (source / "a.py").write_text("x = 1\n")
        first = tree_hash(self.folder)
        (source / "__pycache__").mkdir()
        (source / "__pycache__" / "a.cpython-313.pyc").write_bytes(b"cache")
        (source / ".DS_Store").write_bytes(b"finder")
        self.assertEqual(tree_hash(self.folder), first)
        (source / "a.py").write_text("x = 2\n")
        self.assertNotEqual(tree_hash(self.folder), first)
        self.assertRegex(first, r"^[0-9a-f]{12}$")

    def test_tree_hash_covers_dependency_and_frontend_inputs_but_not_installed_packages(self):
        web = self.folder / "apps" / "web"
        (web / "app").mkdir(parents=True)
        (web / "node_modules" / "dep").mkdir(parents=True)
        (self.folder / "requirements-dev.txt").write_text("pytest==1\n")
        (web / "package.json").write_text("{}")
        (web / "app" / "page.tsx").write_text("export default 1\n")
        seen = {tree_hash(self.folder)}
        for path, content in (
            (self.folder / "requirements-dev.txt", "pytest==2\n"),
            (self.folder / "pyproject.toml", "[tool]\n"),
            (web / "package.json", '{"a": 1}'),
            (web / "package-lock.json", "{}"),
            (web / "app" / "page.tsx", "export default 2\n"),
        ):
            path.write_text(content)
            digest = tree_hash(self.folder)
            self.assertNotIn(digest, seen, path.name)
            seen.add(digest)
        (web / "node_modules" / "dep" / "index.js").write_text("installed, not an input")
        self.assertIn(tree_hash(self.folder), seen)
        # Lint rules in a dotfile and a rendered template are inputs too.
        (self.folder / "engineering").mkdir()
        for path in (web / ".oxlintrc.json", self.folder / "engineering" / "dashboard.html"):
            path.write_text("changed")
            digest = tree_hash(self.folder)
            self.assertNotIn(digest, seen, path.name)
            seen.add(digest)


if __name__ == "__main__":
    unittest.main()
