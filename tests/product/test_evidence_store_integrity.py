"""Filesystem evidence integrity regressions use isolated local artifacts only."""

import hashlib
import json
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aegis.storage import LocalEvidenceStore


class LocalEvidenceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.base = Path(self.folder.name)
        self.store = LocalEvidenceStore(self.base / "data")
        self.content = b"synthetic evidence artifact"
        self.key = hashlib.sha256(self.content).hexdigest()
        self.path = self.store.root_dir / self.key[:2] / self.key

    def test_keys_are_canonical_hashes_before_any_filesystem_access(self):
        outside = self.base / "outside"
        outside.write_bytes(b"outside fixture")
        for key in [str(outside), "../outside", "a/" + "b" * 62, "A" * 64, "g" * 64, "0" * 63, "0" * 65, ""]:
            for method in (self.store.get, self.store.exists, self.store.get_metadata):
                with self.subTest(key=key, operation=method.__name__):
                    with self.assertRaises(ValueError):
                        method(key)
        self.assertEqual(outside.read_bytes(), b"outside fixture")

    def test_corrupt_artifact_is_rejected_by_reads_existence_and_deduplication(self):
        self.store.put(self.content)
        self.path.write_bytes(b"corrupt fixture")
        for action in (
            lambda: self.store.get(self.key),
            lambda: self.store.exists(self.key),
            lambda: self.store.put(self.content),
        ):
            with self.subTest(action=action):
                with self.assertRaises(ValueError):
                    action()
        self.assertEqual(self.path.read_bytes(), b"corrupt fixture")

    def test_metadata_errors_are_distinguished_from_absence_and_empty_object(self):
        self.store.put(self.content)
        self.assertIsNone(self.store.get_metadata(self.key))
        self.store.put(self.content, metadata={})
        self.assertEqual(self.store.get_metadata(self.key), {})
        meta_path = self.path.with_suffix(".meta.json")
        for raw in ("{", "[]", '"string"', "null", '{"value": NaN}', '{"value": Infinity}'):
            with self.subTest(raw=raw):
                meta_path.write_text(raw)
                with self.assertRaises(ValueError):
                    self.store.get_metadata(self.key)
        meta_path.write_bytes(b"\xff")
        with self.assertRaises(ValueError):
            self.store.get_metadata(self.key)

    def test_invalid_metadata_is_rejected_before_publishing_content(self):
        for metadata in ([], {"value": float("nan")}, {"value": float("inf")}):
            with self.subTest(metadata=metadata):
                with self.assertRaises(ValueError):
                    self.store.put(self.content, metadata)
                self.assertFalse(self.store.exists(self.key))

    def test_store_and_hash_directory_symlinks_are_rejected(self):
        outside = self.base / "outside-dir"
        outside.mkdir()
        linked_root = self.base / "linked-data"
        linked_root.mkdir()
        (linked_root / "evidence").symlink_to(outside, target_is_directory=True)
        try:
            linked_store = LocalEvidenceStore(linked_root)
        except (ValueError, OSError):
            pass
        else:
            with self.assertRaises((ValueError, OSError)):
                linked_store.put(self.content)
        (self.store.root_dir / self.key[:2]).symlink_to(outside, target_is_directory=True)
        for action in (
            lambda: self.store.put(self.content),
            lambda: self.store.get(self.key),
            lambda: self.store.get_metadata(self.key),
        ):
            with self.subTest(action=action):
                with self.assertRaises((ValueError, OSError)):
                    action()
        self.assertEqual(list(outside.iterdir()), [])

    def test_artifact_and_metadata_symlinks_and_hardlinks_are_refused(self):
        self.path.parent.mkdir()
        outside = self.base / "outside-artifact"
        outside.write_bytes(self.content)
        for link in (lambda source, destination: destination.symlink_to(source), os.link):
            with self.subTest(link=link):
                link(outside, self.path)
                for action in (
                    lambda: self.store.get(self.key),
                    lambda: self.store.exists(self.key),
                    lambda: self.store.put(self.content),
                ):
                    with self.assertRaises((ValueError, OSError)):
                        action()
                self.path.unlink()
                self.store.put(self.content)
                meta_path = self.path.with_suffix(".meta.json")
                outside_meta = self.base / "outside-metadata"
                outside_meta.write_text('{"outside": true}')
                link(outside_meta, meta_path)
                for action in (
                    lambda: self.store.get_metadata(self.key),
                    lambda: self.store.put(self.content, {"changed": True}),
                ):
                    with self.assertRaises((ValueError, OSError)):
                        action()
                self.assertEqual(outside_meta.read_text(), '{"outside": true}')
                self.assertEqual(outside.read_bytes(), self.content)
                meta_path.unlink()
                self.path.unlink()

    def test_concurrent_duplicate_writes_are_intact_private_and_leave_no_temporary_files(self):
        metadata = {"assessment_id": "synthetic-fixture", "kind": "trace"}
        with ThreadPoolExecutor(max_workers=16) as pool:
            keys = list(pool.map(lambda _index: self.store.put(self.content, metadata), range(64)))
        self.assertEqual(set(keys), {self.key})
        self.assertEqual(self.store.get(self.key), self.content)
        self.assertEqual(self.store.get_metadata(self.key), metadata)
        self.assertEqual(
            {path.name for path in self.path.parent.iterdir()}, {self.key, self.key + ".meta.json"}
        )
        for artifact in (self.path, self.path.with_suffix(".meta.json")):
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
        self.assertEqual(json.loads(self.path.with_suffix(".meta.json").read_text()), metadata)


if __name__ == "__main__":
    unittest.main()
