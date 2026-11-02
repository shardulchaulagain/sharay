"""Completed report caches must remain usable and honor manager shutdown."""

import hashlib
import tempfile
import time
import unittest
from pathlib import Path

from packages.reporting.async_renderer import ReportJobManager


class ReportCacheRecoveryTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="report-cache-")
        self.addCleanup(folder.cleanup)
        self.manager = ReportJobManager(folder.name, max_workers=1)
        self.addCleanup(self.manager.shutdown)
        self.data = {"assessment": {"id": "cache-fixture"}, "findings": []}

    def render(self):
        job = self.manager.submit_render_job("cache-fixture", "json", self.data)
        deadline = time.monotonic() + 5
        while job.status in {"queued", "rendering"} and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(job.status, "completed", job.error)
        return job

    def test_missing_cached_artifact_can_be_rendered_again(self):
        first = self.render()
        Path(first.output_path).unlink()
        replacement = self.render()
        self.assertNotEqual(first.job_id, replacement.job_id)
        self.assertTrue(Path(replacement.output_path).is_file())
        self.assertEqual(
            hashlib.sha256(Path(replacement.output_path).read_bytes()).hexdigest(), replacement.sha256_hash
        )

    def test_tampered_cached_artifact_can_be_rendered_again(self):
        first = self.render()
        Path(first.output_path).write_bytes(b"synthetic corrupt report")
        replacement = self.render()
        self.assertNotEqual(first.job_id, replacement.job_id)
        self.assertEqual(
            hashlib.sha256(Path(replacement.output_path).read_bytes()).hexdigest(), replacement.sha256_hash
        )
        self.assertNotEqual(Path(replacement.output_path).read_bytes(), b"synthetic corrupt report")

    def test_shutdown_rejects_an_identical_completed_cache_hit(self):
        completed = self.render()
        self.manager.shutdown()
        with self.assertRaises(RuntimeError):
            self.manager.submit_render_job("cache-fixture", "json", self.data)
        self.assertIs(self.manager.get_job(completed.job_id), completed)


if __name__ == "__main__":
    unittest.main()
