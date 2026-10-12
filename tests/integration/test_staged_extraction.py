"""Staged archive extraction: a sandboxed child writes one folder, then the parent trusts nothing."""

import errno
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from services.scanner_worker import (
    IsolationError,
    _run_sandboxed,
    attest,
    run_isolated,
    run_staged_extraction,
)
from services.source_analysis_worker.staging import StagedTreeError, purge, validate_staged_tree

PYTHON = os.path.realpath(sys.executable)


class Staging(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.output = self.root / "staging" / "output"
        self.output.mkdir(parents=True)
        self.outside = self.root / "outside"
        self.outside.mkdir()
        (self.outside / "keep.txt").write_text("mine")
        (self.outside / "keep.txt").chmod(0o400)

    def archive(self, entries: dict[str, bytes]) -> Path:
        path = self.root / "upload.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name, data in entries.items():
                bundle.writestr(name, data)
        return path

    def assert_outside_untouched(self):
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ["keep.txt"])
        self.assertEqual(stat.S_IMODE((self.outside / "keep.txt").stat().st_mode), 0o400)
        self.assertEqual((self.outside / "keep.txt").read_text(), "mine")


class SandboxedExtractionTests(Staging):
    @classmethod
    def setUpClass(cls):
        if not attest()["available"]:
            raise unittest.SkipTest("Seatbelt sandbox cannot be applied in this environment.")

    def test_child_extracts_into_the_output_and_the_parent_recounts(self):
        result = run_staged_extraction(
            self.archive({"src/app.py": b"print('hi')\n", "README.md": b"# demo\n"}), self.output
        )
        self.assertEqual((result.outcome, result.exit_code), ("completed", 0), result.stderr)
        claimed = json.loads(result.stdout)
        self.assertEqual((claimed["files"], claimed["folders"], claimed["bytes"]), (2, 1, 19))
        # Fork and network stay denied; the aggregate disk control is honestly absent for this run.
        self.assertIn("process_escape_containment", result.enforced)
        self.assertNotIn("aggregate_scratch_quota", result.enforced)
        self.assertNotIn("loopback_port_egress", result.enforced)
        # The parent's own count: the two files, plus the tree folder and src.
        checked = validate_staged_tree(self.output)
        self.assertEqual((checked["files"], checked["folders"], checked["bytes"]), (2, 2, 19))
        self.assertEqual((self.output / "tree" / "src" / "app.py").read_bytes(), b"print('hi')\n")

    def test_hostile_archives_are_rejected_inside_the_sandbox_and_leave_nothing(self):
        for label, entries, budgets, reason in (
            ("traversal", {"ok.txt": b"x", "../../outside/evil": b"evil"}, {}, "outside its own tree"),
            (
                "bomb",
                {"zeros.bin": b"\0" * (4 * 1024 * 1024)},
                {"max_file_bytes": 65536, "max_total_bytes": 65536},
                "size budget",
            ),
        ):
            with self.subTest(label):
                result = run_staged_extraction(self.archive(entries), self.output, **budgets)
                self.assertEqual((result.outcome, result.exit_code), ("failed", 3), result.stderr)
                self.assertIn(reason, json.loads(result.stdout)["rejected"])
                self.assertEqual(list(self.output.iterdir()), [])
                self.assert_outside_untouched()

    def test_the_write_grant_covers_the_output_folder_and_nothing_else(self):
        code = f"""
import json, os
results = []
for path in ({str(self.output / "inside.txt")!r}, "scratch.txt", {str(self.outside / "evil.txt")!r}):
    try:
        open(path, "w").close()
        results.append(0)
    except OSError as exc:
        results.append(exc.errno)
try:
    os.fork()
    results.append(0)
except OSError as exc:
    results.append(exc.errno)
print(json.dumps(results))
"""
        result = _run_sandboxed([PYTHON, "-I", "-c", code], exec_paths=[sys.base_prefix], output=self.output)
        self.assertEqual(json.loads(result.stdout), [0, errno.EPERM, errno.EPERM, errno.EPERM], result.stderr)
        self.assert_outside_untouched()

    def test_preconditions_and_the_absence_of_a_general_write_grant(self):
        archive = self.archive({"a.txt": b"x"})
        with self.assertRaisesRegex(IsolationError, "Unknown or unavailable runner option"):
            run_isolated([PYTHON, "-I", "-c", "pass"], exec_paths=[sys.base_prefix], output=self.output)
        (self.output / "left-over").write_text("x")
        link = self.root / "link"
        link.symlink_to(self.outside)
        pipe = self.root / "pipe.zip"
        os.mkfifo(pipe)
        empty = self.root / "empty"
        empty.mkdir()
        for label, call in (
            ("output not empty", lambda: run_staged_extraction(archive, self.output)),
            ("output is a link", lambda: run_staged_extraction(archive, link)),
            ("output missing", lambda: run_staged_extraction(archive, self.root / "absent")),
            ("archive is a pipe", lambda: run_staged_extraction(pipe, empty)),
            ("archive is a folder", lambda: run_staged_extraction(self.outside, empty)),
            ("budget is a string", lambda: run_staged_extraction(archive, empty, max_files="10")),
            ("budget is NaN", lambda: run_staged_extraction(archive, empty, max_total_bytes=float("nan"))),
            ("budget is zero", lambda: run_staged_extraction(archive, empty, max_file_bytes=0)),
        ):
            with self.subTest(label), self.assertRaises(IsolationError):
                call()
        self.assert_outside_untouched()


class ParentValidationTests(Staging):
    """A compromised child is simulated by planting entries after a normal extraction."""

    def setUp(self):
        super().setUp()
        tree = self.output / "tree"
        (tree / "src").mkdir(parents=True)
        (tree / "src" / "app.py").write_text("print('hi')\n")

    def assert_rejected(self, reason: str, **budgets):
        with self.assertRaisesRegex(StagedTreeError, reason) as caught:
            validate_staged_tree(self.output, **budgets)
        self.assertTrue(caught.exception.removed)
        self.assertFalse(self.output.exists())
        self.assert_outside_untouched()

    def test_a_clean_tree_is_counted_and_its_modes_are_clamped(self):
        (self.output / "tree" / "src" / "app.py").chmod(0o4777)
        checked = validate_staged_tree(self.output)
        self.assertEqual((checked["files"], checked["folders"], checked["bytes"]), (1, 2, 12))
        # The inventory is what the parent itself read: relative path, size and content hash.
        expected = hashlib.sha256(b"print('hi')\n").hexdigest()
        self.assertEqual(checked["inventory"], [{"path": "tree/src/app.py", "bytes": 12, "sha256": expected}])
        first = checked["tree_sha256"]
        self.assertEqual(validate_staged_tree(self.output)["tree_sha256"], first)
        (self.output / "tree" / "src" / "app.py").write_text("print('ho')\n")
        self.assertNotEqual(validate_staged_tree(self.output)["tree_sha256"], first)
        self.assertEqual(stat.S_IMODE((self.output / "tree" / "src" / "app.py").stat().st_mode), 0o600)

    def test_the_tree_digest_cannot_be_imitated_by_a_crafted_file_name(self):
        import shutil

        content = b"abc"
        digest = hashlib.sha256(content).hexdigest()
        # Under a newline-joined "sha bytes path" form these two trees serialized identically:
        # files a and b, versus one file b inside a folder named "a<newline><sha> 3 tree".
        digests = []
        for paths in (["a", "b"], [f"a\n{digest} 3 tree/b"]):
            shutil.rmtree(self.output / "tree")
            for relative in paths:
                target = self.output / "tree" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            digests.append(validate_staged_tree(self.output)["tree_sha256"])
        self.assertNotEqual(digests[0], digests[1])

    def test_links_hard_links_and_special_entries_are_rejected(self):
        plant = {
            "symlink to a file": lambda: (self.output / "tree" / "link").symlink_to(
                self.outside / "keep.txt"
            ),
            "symlink to a folder": lambda: (self.output / "tree" / "dir").symlink_to(self.outside),
            "hard link to an outside file": lambda: os.link(
                self.outside / "keep.txt", self.output / "tree" / "hard"
            ),
            "fifo": lambda: os.mkfifo(self.output / "tree" / "pipe"),
        }
        for label, action in plant.items():
            with self.subTest(label):
                self.setUp()
                action()
                self.assert_rejected("link|special")

    def test_a_tree_swapped_for_a_link_is_removed_without_touching_its_target(self):
        import shutil

        shutil.rmtree(self.output / "tree")
        (self.output / "tree").symlink_to(self.outside)
        self.assert_rejected("link or special")
        # And a staging folder that is itself a link is unlinked, never walked.
        link = self.root / "staging-link"
        link.symlink_to(self.outside)
        self.assertTrue(purge(link))
        self.assertFalse(link.is_symlink())
        self.assert_outside_untouched()

    def test_locked_and_immutable_entries_cannot_block_validation_or_cleanup(self):
        frozen = self.output / "tree" / "frozen.txt"
        frozen.write_text("x")

        def freeze():
            if (
                sys.platform == "darwin"
            ):  # immutable flags are macOS/BSD only; the mode-0 half runs everywhere
                os.chflags(frozen, stat.UF_IMMUTABLE)

        freeze()
        (self.output / "tree" / "src").chmod(0)
        (self.output / "tree").chmod(0)
        self.assertEqual(validate_staged_tree(self.output)["files"], 2)
        freeze()
        (self.output / "tree").chmod(0)
        self.assertTrue(purge(self.output))
        self.assertFalse(self.output.exists())

    def test_a_directory_that_cannot_be_listed_fails_validation_instead_of_counting_as_empty(self):
        import subprocess

        hidden = self.output / "tree" / "hidden"
        hidden.mkdir()
        (hidden / "big.bin").write_bytes(b"x" * 100)
        # An ACL denying "list" survives the validator's chmod; plain modes would not.
        acl = subprocess.run(["/bin/chmod", "+a", "everyone deny list", str(hidden)], capture_output=True)
        if acl.returncode != 0:
            self.skipTest("This filesystem does not support ACLs.")
        self.addCleanup(subprocess.run, ["/bin/chmod", "-N", str(hidden)], capture_output=True)
        with self.assertRaisesRegex(StagedTreeError, "cannot be listed") as caught:
            validate_staged_tree(self.output, max_total_bytes=10, max_file_bytes=10)
        # Truthful: what could not be deleted is reported as not removed, and is still there.
        self.assertEqual(caught.exception.removed, not self.output.exists())
        self.assert_outside_untouched()

    def test_overruns_the_child_did_not_report_are_caught_by_the_recount(self):
        (self.output / "tree" / "big.bin").write_bytes(b"x" * 5000)
        self.assert_rejected("size budget", max_file_bytes=1000)
        self.setUp()
        for index in range(5):
            (self.output / "tree" / f"extra{index}").write_text("x")
        self.assert_rejected("more files and folders", max_files=4)
        self.setUp()
        deep = self.output / "tree" / "a" / "b" / "c"
        deep.mkdir(parents=True)
        self.assert_rejected("deeper", max_depth=3)
        self.setUp()
        with self.assertRaisesRegex(StagedTreeError, "positive integers"):
            validate_staged_tree(self.output, max_files=True)


if __name__ == "__main__":
    unittest.main()
