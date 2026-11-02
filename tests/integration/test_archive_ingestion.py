"""Safe archive extraction against hostile archives the tests build themselves.

Every rejection asserts its reason, so a test cannot pass because some other guard fired.
"""

import io
import os
import shutil
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from services.source_analysis_worker import ArchiveError, extract_archive

OUTSIDE = "outside its own tree"
SIZE = "expands beyond its size budget"
CONFLICT = "corrupt, encrypted or has conflicting entries"
NODES = "more files and folders than the budget"
KIB64 = {"max_file_bytes": 65536, "max_total_bytes": 65536}


class ArchiveIngestionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.outside = self.root / "outside"
        self.outside.mkdir()
        self.destination = self.root / "work" / "extracted"
        self.destination.parent.mkdir()
        self.count = 0

    def path(self, suffix: str) -> Path:
        self.count += 1
        return self.root / f"sample{self.count}{suffix}"

    def make_zip(self, entries: dict[str, bytes]) -> Path:
        path = self.path(".zip")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name, data in entries.items():
                bundle.writestr(name, data)
        return path

    def make_tar(self, members, mode="w:gz", **options) -> Path:
        path = self.path(".tar")
        with tarfile.open(path, mode, **options) as bundle:
            for info, data in members:
                if data is not None:
                    info.size = len(data)
                bundle.addfile(info, io.BytesIO(data) if data is not None else None)
        return path

    def member(
        self, name: str, kind: bytes = tarfile.REGTYPE, link: str = "", mode: int = 0o644
    ) -> tarfile.TarInfo:
        info = tarfile.TarInfo(name)
        info.type, info.linkname, info.mode = kind, link, mode
        return info

    def assert_rejected(self, archive: Path, reason: str, **budgets):
        with self.assertRaisesRegex(ArchiveError, reason):
            extract_archive(archive, self.destination, **budgets)
        # Nothing kept, nothing written beside or above the destination.
        self.assertFalse(self.destination.exists())
        self.assertEqual(sorted(p.name for p in self.destination.parent.iterdir()), [])
        self.assertEqual(list(self.outside.iterdir()), [])

    def test_ordinary_archives_extract_as_plain_non_executable_files(self):
        for archive in (
            self.make_zip({"src/app.py": b"print('hi')\n", "README.md": b"# demo\n"}),
            self.make_tar(
                [
                    (self.member("./", tarfile.DIRTYPE), None),  # the usual root record is a no-op
                    (self.member("./src/app.py", mode=0o4755), b"print('hi')\n"),
                    (self.member("./README.md"), b"# demo\n"),
                ]
            ),
        ):
            with self.subTest(archive.suffix):
                destination = self.root / ("out" + archive.suffix)
                summary = extract_archive(archive, destination)
                self.assertEqual(summary, {"files": 2, "folders": 1, "bytes": 19, "skipped": []})
                script = destination / "src" / "app.py"
                self.assertEqual(script.read_bytes(), b"print('hi')\n")
                # No execute or setuid bit survives, whatever the archive claimed.
                self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o600)

    def test_traversal_entries_reject_the_whole_archive(self):
        for name in ("../outside/evil", "ok/../../outside/evil", "/abs/evil", "..\\outside\\evil", "C:evil"):
            with self.subTest(name=name):
                self.assert_rejected(self.make_zip({"good.txt": b"x", name: b"evil"}), OUTSIDE)
        self.assert_rejected(
            self.make_tar([(self.member("good.txt"), b"x"), (self.member("../outside/evil"), b"evil")]),
            OUTSIDE,
        )
        # A link that would be skipped anyway still rejects the archive if its own name escapes.
        self.assert_rejected(
            self.make_tar([(self.member("../outside", tarfile.SYMTYPE, "/etc"), None)]), OUTSIDE
        )
        self.assert_rejected(
            self.make_tar([(self.member("./"), b"file with no name")]), "without a usable name"
        )

    def test_links_and_special_files_are_never_created(self):
        archive = self.make_tar(
            [
                (self.member("link", tarfile.SYMTYPE, str(self.outside)), None),
                (self.member("link/evil.txt"), b"evil"),
                (self.member("hard", tarfile.LNKTYPE, "link/evil.txt"), None),
                (self.member("pipe", tarfile.FIFOTYPE), None),
                (self.member("device", tarfile.CHRTYPE), None),
            ]
        )
        summary = extract_archive(archive, self.destination)
        self.assertEqual((summary["files"], summary["folders"]), (1, 1))
        self.assertEqual([item["name"] for item in summary["skipped"]], ["link", "hard", "pipe", "device"])
        # The entry "through" the symlink landed in a plain directory inside the destination.
        self.assertTrue((self.destination / "link").is_dir() and not (self.destination / "link").is_symlink())
        self.assertEqual((self.destination / "link" / "evil.txt").read_bytes(), b"evil")
        self.assertEqual(list(self.outside.iterdir()), [])
        self.assertEqual({p.name for p in self.destination.iterdir()}, {"link"})

    def test_zip_symlink_entries_are_skipped(self):
        path = self.path(".zip")
        with zipfile.ZipFile(path, "w") as bundle:
            info = zipfile.ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            bundle.writestr(info, str(self.outside))
        summary = extract_archive(path, self.destination)
        self.assertEqual((summary["files"], summary["skipped"][0]["reason"]), (0, "link or special file"))
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_decompression_bombs_are_stopped_while_streaming_not_by_budget_validation(self):
        bomb = self.make_zip({"zeros.bin": b"\0" * (8 * 1024 * 1024)})
        self.assertLess(bomb.stat().st_size, 100 * 1024)  # tiny on disk, 8 MiB expanded
        original = zipfile.ZipExtFile.read
        with mock.patch.object(zipfile.ZipExtFile, "read", autospec=True, side_effect=original) as reads:
            self.assert_rejected(bomb, SIZE, **KIB64)
        # Decompression really started and was cut off: one chunk at the cap, one past it.
        self.assertEqual(reads.call_count, 2)
        self.assert_rejected(bomb, SIZE, max_file_bytes=65536, max_total_bytes=1024 * 1024)
        tar_bomb = self.make_tar([(self.member("zeros.bin"), b"\0" * (2 * 1024 * 1024))], mode="w:xz")
        self.assertLess(tar_bomb.stat().st_size, 10 * 1024)
        self.assert_rejected(tar_bomb, SIZE, **KIB64)
        many = self.make_zip({f"f{n}": b"x" for n in range(20)})
        self.assert_rejected(many, "more entries than the file budget", max_files=10)
        self.assert_rejected(bomb, "larger than the input budget", max_archive_bytes=1000)

    def test_tar_metadata_and_skipped_payloads_count_against_the_stream_budget(self):
        one = {"max_files": 2, "max_file_bytes": 1, "max_total_bytes": 1}
        info = self.member("a.txt")
        info.pax_headers = {"comment": "x" * 1048576}
        metadata = self.make_tar([(info, b"x")], mode="w:gz", format=tarfile.PAX_FORMAT)
        self.assertLess(metadata.stat().st_size, 10 * 1024)
        self.assert_rejected(metadata, SIZE, **one)
        # An entry of an unknown type is skipped, but its 2 MiB payload is still read and counted.
        skipped = self.make_tar(
            [(self.member("blob", b"Z"), b"\0" * (2 * 1024 * 1024)), (self.member("a"), b"x")]
        )
        self.assertLess(skipped.stat().st_size, 10 * 1024)
        self.assert_rejected(skipped, SIZE, **one)
        # The same archives are fine when the budget really covers them.
        self.assertEqual(extract_archive(skipped, self.root / "roomy")["files"], 1)

    def test_pathological_metadata_becomes_a_plain_rejection(self):
        record = b"30 comment=aaaaaaaaaaaaaaaaaa\n"
        chain = self.path(".tar")
        with open(chain, "wb") as out:
            for _ in range(400):
                header = tarfile.TarInfo("PaxHeaders/x")
                header.type, header.size = tarfile.XHDTYPE, len(record)
                out.write(header.tobuf(tarfile.USTAR_FORMAT) + record.ljust(512, b"\0"))
            last = tarfile.TarInfo("a.txt")
            last.size = 1
            out.write(last.tobuf(tarfile.USTAR_FORMAT) + b"x".ljust(512, b"\0") + b"\0" * 1024)
        # 400 chained extended headers overflow the stdlib parser's recursion on this Python.
        self.assert_rejected(chain, CONFLICT)
        named = self.make_zip({"é.txt": b"x"})
        named.write_bytes(named.read_bytes().replace("é".encode(), b"\xff\xfe"))
        self.assert_rejected(named, CONFLICT)  # name flagged UTF-8 but not decodable
        sparse = self.make_tar([(self.member("sparse", tarfile.GNUTYPE_SPARSE), b"x" * 600)], mode="w")
        summary = extract_archive(sparse, self.destination)
        # Not silently written as an empty file: reported as unsupported instead.
        self.assertEqual(
            (summary["files"], summary["skipped"][0]["reason"]), (0, "sparse file is not supported")
        )

    def test_implied_folders_depth_and_name_length_are_budgeted(self):
        self.assert_rejected(
            self.make_zip({"/".join(["d"] * 60) + "/f": b"x"}), "too deep or too long", max_files=1
        )
        self.assert_rejected(self.make_zip({"/".join(["d"] * 20) + "/f": b"x"}), NODES, max_files=5)
        self.assert_rejected(self.make_zip({"n" * 2000: b"x"}), "too deep or too long")
        # 3 folders + 1 file = 4 nodes: exactly at the budget passes, one below does not.
        nested = self.make_zip({"a/b/c/f": b"x"})
        self.assert_rejected(nested, NODES, max_files=3)
        self.assertEqual(extract_archive(nested, self.destination, max_files=4)["folders"], 3)

    def test_duplicates_corruption_and_non_archives_are_rejected(self):
        duplicate = self.path(".zip")
        with zipfile.ZipFile(duplicate, "w") as bundle:
            bundle.writestr("same.txt", b"first")
            with self.assertWarns(UserWarning):
                bundle.writestr("same.txt", b"second")
        self.assert_rejected(duplicate, CONFLICT)
        self.assert_rejected(self.make_zip({"a": b"file", "a/b": b"under a file"}), CONFLICT)
        truncated = self.path(".tar")
        truncated.write_bytes(
            self.make_tar([(self.member("a.bin"), os.urandom(200000))]).read_bytes()[:50000]
        )
        self.assert_rejected(truncated, CONFLICT)
        plain = self.path(".txt")
        plain.write_text("not an archive")
        self.assert_rejected(plain, "Only zip and tar archives are supported")
        self.assert_rejected(self.root / "missing.zip", "missing or larger")
        # The input must be a regular file: a FIFO is refused without being opened.
        pipe = self.path(".zip")
        os.mkfifo(pipe)
        self.assert_rejected(pipe, "missing or larger")

    def test_budgets_must_be_strict_positive_integers_before_anything_is_created(self):
        archive = self.make_zip({"a.txt": b"x" * 5000})
        for budget in ("max_files", "max_file_bytes", "max_total_bytes", "max_archive_bytes"):
            for value in ("10", float("nan"), float("inf"), True, 0, -1, 1.5, 10**12, None):
                with self.subTest(budget=budget, value=value):
                    self.assert_rejected(archive, "Budgets must be positive integers", **{budget: value})
        # A per-file budget above the total budget is a contradiction, not a wider limit.
        self.assert_rejected(
            archive, "Budgets must be positive integers", max_file_bytes=2000, max_total_bytes=1000
        )

    def test_an_unexpected_error_still_removes_everything_written(self):
        archive = self.make_zip({"a.txt": b"x", "b.txt": b"y"})
        calls = []

        def explode(destination, name):
            calls.append(name)
            if len(calls) == 2:
                raise TypeError("synthetic unexpected failure")
            return destination / name

        with mock.patch("services.source_analysis_worker._target", side_effect=explode):
            with self.assertRaises(TypeError):
                extract_archive(archive, self.destination)
        self.assertFalse(self.destination.exists())

    def test_output_that_cannot_be_removed_is_reported_not_called_clean(self):
        archive = self.make_zip({"good.txt": b"x", "../outside/evil": b"evil"})
        with mock.patch("services.source_analysis_worker.shutil.rmtree"):
            with self.assertRaisesRegex(ArchiveError, "partial output could not be removed"):
                extract_archive(archive, self.destination)
        self.assertTrue(self.destination.exists())
        shutil.rmtree(self.destination)

    def test_an_existing_destination_is_refused_and_left_alone(self):
        self.destination.mkdir()
        (self.destination / "keep.txt").write_text("mine")
        with self.assertRaisesRegex(ArchiveError, "must be a new directory"):
            extract_archive(self.make_zip({"a.txt": b"x"}), self.destination)
        self.assertEqual((self.destination / "keep.txt").read_text(), "mine")


if __name__ == "__main__":
    unittest.main()
