"""Tests for Phase 5 Evidence & Artifact Object Storage Engine."""

import tempfile
import unittest
from pathlib import Path

from aegis.storage import LocalEvidenceStore, S3EvidenceStore, get_evidence_store


class StorageTests(unittest.TestCase):
    def test_local_evidence_store_content_addressing_and_metadata(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = LocalEvidenceStore(Path(tmp_dir))
            sample_data = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"ok"}'
            metadata = {"assessment_id": "test_assessment_1", "category": "http_trace"}

            # Store content
            sha256 = store.put(sample_data, metadata=metadata)
            self.assertEqual(len(sha256), 64)
            self.assertTrue(store.exists(sha256))

            # Retrieve content
            retrieved = store.get(sha256)
            self.assertEqual(retrieved, sample_data)

            # Retrieve metadata
            meta = store.get_metadata(sha256)
            self.assertIsNotNone(meta)
            assert meta is not None
            self.assertEqual(meta.get("assessment_id"), "test_assessment_1")

            # Non-existent key raises FileNotFoundError
            with self.assertRaises(FileNotFoundError):
                store.get("0" * 64)

    def test_s3_store_reports_unimplemented_operations(self):
        s3_store = S3EvidenceStore(bucket_name="sharay-enterprise-evidence")
        sample_pcap = b"DUMMY_PCAP_DATA_FOR_ENTERPRISE_EVIDENCE"
        for operation, argument in (
            (s3_store.put, sample_pcap),
            (s3_store.get, "0" * 64),
            (s3_store.exists, "0" * 64),
        ):
            with self.subTest(operation=operation.__name__), self.assertRaises(NotImplementedError):
                operation(argument)

    def test_get_evidence_store_default_fallback(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = get_evidence_store(Path(tmp_dir))
            self.assertIsInstance(store, LocalEvidenceStore)


if __name__ == "__main__":
    unittest.main()
