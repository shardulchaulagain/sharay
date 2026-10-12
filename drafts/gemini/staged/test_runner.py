"""Tests for narrow runner entry point for staged extraction.

Author: Gemini (Principal Architect, Debugger & Helper)
"""

import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from drafts.gemini.staged.runner import (
    StagedExtractionError,
    run_staged_extraction,
)


class StagedRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def make_zip(self, files: dict[str, bytes]) -> Path:
        archive_path = self.tmp_path / "test.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            for name, data in files.items():
                zf.writestr(name, data)
        return archive_path

    def make_tar(self, files: dict[str, bytes]) -> Path:
        archive_path = self.tmp_path / "test.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            for name, data in files.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return archive_path

    def test_preflight_rejects_missing_archive(self):
        out = self.tmp_path / "out"
        out.mkdir()
        with self.assertRaises(StagedExtractionError):
            run_staged_extraction(self.tmp_path / "missing.zip", out)

    def test_preflight_rejects_directory_archive(self):
        fake_archive = self.tmp_path / "fake_archive_dir"
        fake_archive.mkdir()
        out = self.tmp_path / "out"
        out.mkdir()
        with self.assertRaises(StagedExtractionError):
            run_staged_extraction(fake_archive, out)

    def test_preflight_rejects_symlink_archive(self):
        real_zip = self.make_zip({"hello.txt": b"world"})
        sym_zip = self.tmp_path / "symlink.zip"
        sym_zip.symlink_to(real_zip)
        out = self.tmp_path / "out"
        out.mkdir()
        with self.assertRaises(StagedExtractionError):
            run_staged_extraction(sym_zip, out)

    def test_preflight_rejects_nonempty_output(self):
        real_zip = self.make_zip({"hello.txt": b"world"})
        out = self.tmp_path / "out"
        out.mkdir()
        (out / "stray.txt").write_text("not empty")
        with self.assertRaises(StagedExtractionError):
            run_staged_extraction(real_zip, out)

    def test_preflight_rejects_symlink_output(self):
        real_zip = self.make_zip({"hello.txt": b"world"})
        real_out = self.tmp_path / "real_out"
        real_out.mkdir()
        sym_out = self.tmp_path / "sym_out"
        sym_out.symlink_to(real_out)
        with self.assertRaises(StagedExtractionError):
            run_staged_extraction(real_zip, sym_out)

    def test_successful_zip_extraction_and_validation(self):
        real_zip = self.make_zip({"a/b/file1.txt": b"content1", "file2.txt": b"content2"})
        out = self.tmp_path / "out"
        out.mkdir()
        res = run_staged_extraction(real_zip, out, force_direct=True)
        self.assertEqual(res.outcome, "completed")
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(res.extracted_files, 2)
        self.assertEqual(res.extracted_folders, 2)
        self.assertEqual(res.extracted_bytes, len(b"content1") + len(b"content2"))
        self.assertTrue((out / "tree" / "file2.txt").is_file())
        self.assertTrue((out / "tree" / "a" / "b" / "file1.txt").is_file())

    def test_successful_tar_extraction_and_validation(self):
        real_tar = self.make_tar({"pkg/main.py": b"print('hi')", "pkg/__init__.py": b""})
        out = self.tmp_path / "out"
        out.mkdir()
        res = run_staged_extraction(real_tar, out, force_direct=True)
        self.assertEqual(res.outcome, "completed")
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(res.extracted_files, 2)
        self.assertEqual(res.extracted_folders, 1)
        self.assertEqual((out / "tree" / "pkg" / "main.py").read_bytes(), b"print('hi')")

    def test_corrupt_archive_rejection_and_purge(self):
        corrupt = self.tmp_path / "corrupt.zip"
        corrupt.write_bytes(b"PK\x03\x04not-a-valid-zip-content-here")
        out = self.tmp_path / "out"
        out.mkdir()
        res = run_staged_extraction(corrupt, out, force_direct=True)
        self.assertEqual(res.outcome, "rejected")
        self.assertTrue(
            "supported" in res.rejection_reason.lower() or "corrupt" in res.rejection_reason.lower()
        )
        # Confirms output folder was purged on failure
        self.assertFalse(out.exists())

    def test_oversized_file_budget_rejection_and_purge(self):
        large_zip = self.make_zip({"huge.bin": b"x" * 1000})
        out = self.tmp_path / "out"
        out.mkdir()
        # Cap file size at 100 bytes
        res = run_staged_extraction(large_zip, out, max_file_bytes=100, force_direct=True)
        self.assertEqual(res.outcome, "rejected")
        self.assertFalse(out.exists())

    def test_cancellation_purges_output(self):
        real_zip = self.make_zip({"a.txt": b"123"})
        out = self.tmp_path / "out"
        out.mkdir()
        res = run_staged_extraction(real_zip, out, cancelled=lambda: True, force_direct=True)
        self.assertEqual(res.outcome, "cancelled")
        self.assertFalse(out.exists())

    def test_seatbelt_nested_sandbox_behavior_reported_truthfully(self):
        real_zip = self.make_zip({"a.txt": b"123"})
        out = self.tmp_path / "out"
        out.mkdir()
        # In this test environment, nested sandbox-exec is blocked by kernel policy (Operation not permitted).
        # run_staged_extraction catches exit 71, purges output, and raises StagedExtractionError.
        with self.assertRaises(StagedExtractionError) as ctx:
            run_staged_extraction(real_zip, out, force_direct=False)
        self.assertIn("cannot be applied in this environment", str(ctx.exception))
        self.assertFalse(out.exists())

