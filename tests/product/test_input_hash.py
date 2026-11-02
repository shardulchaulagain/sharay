"""Input hashes never open pipes or follow links, including selection/open races."""

import contextlib
import errno
import hashlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.log_view import main, tree_hash

PROJECT = Path(__file__).resolve().parents[2]


class InputHashTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        (self.root / "services").mkdir()
        self.source = self.root / "services" / "a.py"
        self.source.write_bytes(b"source\n")

    def test_regular_digest_is_preserved_and_contents_are_streamed(self):
        content = b"data\n" * 50000
        self.source.write_bytes(content)
        files = {self.source: content, self.root / "pyproject.toml": b"[tool]\n"}
        (self.root / "pyproject.toml").write_bytes(b"[tool]\n")
        expected = hashlib.sha256()
        for path in sorted(files):
            name = "/".join(path.relative_to(self.root).parts).encode()
            expected.update(name + b"\0" + hashlib.sha256(files[path]).digest())
        real_read, real_open = os.read, os.open
        requests, flags_seen = [], []

        def read(descriptor, size):
            requests.append(size)
            return real_read(descriptor, size)

        def open_input(path, flags, **kwargs):
            flags_seen.append(flags)
            return real_open(path, flags, **kwargs)

        with (
            patch.object(Path, "read_bytes", side_effect=AssertionError("Whole-file reads are forbidden")),
            patch("scripts.log_view.os.read", side_effect=read),
            patch("scripts.log_view.os.open", side_effect=open_input),
        ):
            self.assertEqual(tree_hash(self.root), expected.hexdigest()[:12])
        self.assertGreater(len(requests), 2)
        self.assertLessEqual(max(requests), 64 * 1024)
        self.assertTrue(all(flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW for flags in flags_seen))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO fixtures require POSIX")
    def test_initial_fifo_input_is_rejected_instead_of_omitted(self):
        self.source.unlink()
        os.mkfifo(self.source)
        with self.assertRaisesRegex(ValueError, "Cannot hash project inputs safely"):
            tree_hash(self.root)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO fixtures require POSIX")
    def test_regular_to_fifo_after_selection_is_rejected_in_bounded_owned_child(self):
        program = """
import os, sys
from pathlib import Path
from unittest.mock import patch
from scripts.log_view import tree_hash
root = Path(sys.argv[1])
source = root / 'services' / 'a.py'
original = Path.is_file
def select(path):
    found = original(path)
    if path == source and found:
        source.unlink()
        os.mkfifo(source)
        print('FIFO reached', flush=True)
    return found
with patch.object(Path, 'is_file', select):
    try:
        tree_hash(root)
    except ValueError:
        print('FIFO rejected', flush=True)
    else:
        raise SystemExit('Unexpected hash success')
"""
        child = subprocess.Popen(
            [sys.executable, "-c", program, str(self.root)],
            cwd=PROJECT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            try:
                output, errors = child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                self.fail("Input hashing blocked on the FIFO; owned child killed and reaped")
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
        self.assertEqual(child.returncode, 0, errors)
        self.assertIn("FIFO reached", output)
        self.assertIn("FIFO rejected", output)
        self.assertIsNotNone(child.poll())

    def test_file_symlink_swapped_after_selection_never_reads_its_target(self):
        outside = self.root / "private-target"
        outside.write_bytes(b"synthetic private content")
        original = Path.is_file

        def select(path):
            found = original(path)
            if path == self.source and found:
                self.source.unlink()
                self.source.symlink_to(outside)
            return found

        with patch.object(Path, "is_file", select), patch("scripts.log_view.os.read") as read:
            with self.assertRaisesRegex(ValueError, "Cannot hash project inputs safely"):
                tree_hash(self.root)
            read.assert_not_called()
        self.assertEqual(outside.read_bytes(), b"synthetic private content")

    def test_parent_directory_swapped_to_symlink_never_reads_its_target(self):
        parent = self.root / "services" / "child"
        parent.mkdir()
        self.source.unlink()
        self.source = parent / "a.py"
        self.source.write_bytes(b"source")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "a.py").write_bytes(b"synthetic private content")
        original = Path.is_file

        def select(path):
            found = original(path)
            if path == self.source and found:
                parent.rename(self.root / "saved")
                parent.symlink_to(outside, target_is_directory=True)
            return found

        with patch.object(Path, "is_file", select), patch("scripts.log_view.os.read") as read:
            with self.assertRaisesRegex(ValueError, "Cannot hash project inputs safely"):
                tree_hash(self.root)
            read.assert_not_called()

    def test_regular_file_replaced_between_stat_and_open_is_rejected_without_reading(self):
        replacement = self.root / "replacement"
        replacement.write_bytes(b"changed source")
        real_open = os.open

        def open_input(path, flags, **kwargs):
            if path == "a.py":
                replacement.replace(self.source)
            return real_open(path, flags, **kwargs)

        with (
            patch("scripts.log_view.os.open", side_effect=open_input),
            patch("scripts.log_view.os.read") as read,
        ):
            with self.assertRaisesRegex(ValueError, "Cannot hash project inputs safely"):
                tree_hash(self.root)
            read.assert_not_called()

    def test_parent_swapped_after_descriptor_walk_is_rejected_and_outside_data_is_never_read(self):
        parent = self.root / "services" / "child"
        parent.mkdir()
        self.source.unlink()
        self.source = parent / "a.py"
        self.source.write_bytes(b"original source")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "a.py").write_bytes(b"synthetic private content")
        real_open, real_read = os.open, os.read
        observed = []

        def open_input(path, flags, **kwargs):
            if path == "a.py":
                parent.rename(self.root / "saved")
                parent.symlink_to(outside, target_is_directory=True)
            return real_open(path, flags, **kwargs)

        def read(descriptor, size):
            result = real_read(descriptor, size)
            observed.append(result)
            return result

        with (
            patch("scripts.log_view.os.open", side_effect=open_input),
            patch("scripts.log_view.os.read", side_effect=read),
        ):
            with self.assertRaisesRegex(ValueError, "Cannot hash project inputs safely"):
                tree_hash(self.root)
        self.assertEqual(observed, [b"original source"])

    def test_growth_during_read_is_rejected_after_only_the_initial_file_size(self):
        self.source.write_bytes(b"x" * (128 * 1024))
        real_read = os.read
        requested = []

        def read(descriptor, size):
            result = real_read(descriptor, size)
            requested.append(size)
            if len(requested) == 1:
                with self.source.open("ab") as stream:
                    stream.write(b"extra bytes")
            return result

        with patch("scripts.log_view.os.read", side_effect=read):
            with self.assertRaisesRegex(ValueError, "Cannot hash project inputs safely"):
                tree_hash(self.root)
        self.assertEqual(sum(requested), 128 * 1024)

    def test_read_failure_closes_every_owned_descriptor(self):
        real_open = os.open
        opened = []

        def open_input(path, flags, **kwargs):
            descriptor = real_open(path, flags, **kwargs)
            opened.append(descriptor)
            return descriptor

        with (
            patch("scripts.log_view.os.open", side_effect=open_input),
            patch("scripts.log_view.os.read", side_effect=OSError("synthetic private diagnostic")),
        ):
            with self.assertRaisesRegex(ValueError, "Cannot hash project inputs safely") as caught:
                tree_hash(self.root)
        self.assertNotIn("private diagnostic", str(caught.exception))
        self.assertGreater(len(opened), 1)
        for descriptor in opened:
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptor)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_tree_cli_errors_are_fixed_and_do_not_expose_underlying_details(self):
        output, errors = io.StringIO(), io.StringIO()
        with (
            patch("scripts.log_view.tree_hash", side_effect=ValueError("synthetic private diagnostic")),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            with self.assertRaises(SystemExit) as caught:
                main(["--tree"])
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Cannot hash project inputs safely", errors.getvalue())
        self.assertNotIn("private diagnostic", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
