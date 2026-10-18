"""Unit tests for Asynchronous Report Rendering Pipeline (Requirements J1 & J2)."""

from __future__ import annotations

import concurrent.futures
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.reporting import async_renderer
from packages.reporting.async_renderer import ReportJobManager


class TestAsyncReports(unittest.TestCase):
    """Test suite for async report job submission, idempotency locking, and canary check."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.mgr = ReportJobManager(reports_dir=self.temp_dir.name, max_workers=2)
        self.addCleanup(self.mgr.shutdown)

    def test_01_canary_health_check(self):
        # Startup canary must verify ReportLab PDF engine is functional
        ok = ReportJobManager.verify_renderer_canary()
        self.assertTrue(ok)

    def test_02_submit_async_pdf_job(self):
        report_data = {
            "assessment": {"id": "test-async-001", "created_at": time.time(), "duration_seconds": 10.0},
            "project": {"name": "Async Test Project"},
            "target": {"url": "https://example.com/"},
            "scope": {"target_url": "https://example.com/"},
            "observations": [],
            "findings": [
                {
                    "severity": "high",
                    "confidence": "high",
                    "title": "Async Test Finding",
                    "description": "Verification of async rendering pipeline",
                    "affected_url": "https://example.com/test",
                    "remediation": "Apply patch",
                    "poc": {
                        "curl_command": "curl -s -k https://example.com/test",
                        "parameter": "id",
                        "payload": "1' OR '1'='1",
                    },
                }
            ],
            "checks": [{"category": "async_test", "status": "completed", "detail": "Test ok"}],
            "events": [],
            "generated_at": "2026-10-15T00:00:00Z",
        }

        job = self.mgr.submit_render_job("test-async-001", "pdf", report_data)
        self.assertEqual(job.assessment_id, "test-async-001")
        self.assertEqual(job.format, "pdf")
        self.assertIn(job.status, ("queued", "rendering", "completed"))

        # Wait for completion (bounded to 10 seconds)
        start = time.time()
        while job.status in ("queued", "rendering") and (time.time() - start) < 10.0:
            time.sleep(0.05)
            job = self.mgr.get_job(job.job_id)

        self.assertEqual(job.status, "completed")
        self.assertIsNotNone(job.output_path)
        self.assertTrue(Path(job.output_path).exists())
        self.assertIsNotNone(job.sha256_hash)
        self.assertEqual(len(job.sha256_hash), 64)
        self.assertEqual(job.content_type, "application/pdf")

    def test_03_idempotency_locking(self):
        # Submitting the same assessment_id + format while rendering returns the existing job
        report_data = {
            "assessment": {"id": "test-idempotent-001", "created_at": time.time(), "duration_seconds": 5.0},
            "project": {"name": "Idempotent Project"},
            "target": {"url": "https://example.com/"},
            "scope": {"target_url": "https://example.com/"},
            "observations": [],
            "findings": [],
            "checks": [],
            "events": [],
            "generated_at": "2026-10-15T00:00:00Z",
        }

        job1 = self.mgr.submit_render_job("test-idempotent-001", "markdown", report_data)
        job2 = self.mgr.submit_render_job("test-idempotent-001", "markdown", report_data)

        self.assertEqual(job1.job_id, job2.job_id)

    def test_json_jobs_render_json_and_reject_unknown_formats(self):
        data = {
            "assessment": {"id": "test-json-001", "status": "completed"},
            "project": {"name": "JSON fixture"},
            "target": {"url": "http://127.0.0.1:8766/"},
            "scope": {},
            "observations": [],
            "findings": [],
            "checks": [],
            "events": [],
        }
        job = self.mgr.submit_render_job("test-json-001", "json", data)
        deadline = time.monotonic() + 5
        while job.status in {"queued", "rendering"} and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.format, "json")
        self.assertEqual(job.content_type, "application/json")
        self.assertEqual(json.loads(Path(job.output_path).read_bytes())["assessment"]["id"], "test-json-001")
        with self.assertRaises(ValueError):
            self.mgr.submit_render_job("test-invalid-format", "unsupported", data)

    def wait_for_job(self, job):
        deadline = time.monotonic() + 5
        while job.status in {"queued", "rendering"} and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertNotIn(job.status, {"queued", "rendering"})
        return job

    def test_cache_identity_tracks_evidence_but_ignores_generation_timestamp(self):
        data = {"generated_at": "first", "findings": [{"lifecycle_state": "CANDIDATE"}]}
        original = self.wait_for_job(self.mgr.submit_render_job("snapshot", "json", data))
        same = self.mgr.submit_render_job("snapshot", "json", data | {"generated_at": "second"})
        self.assertEqual(same.job_id, original.job_id)
        data["findings"][0]["lifecycle_state"] = "REPRODUCED"
        changed = self.wait_for_job(self.mgr.submit_render_job("snapshot", "json", data))
        self.assertNotEqual(changed.job_id, original.job_id)
        self.assertEqual(
            json.loads(Path(changed.output_path).read_bytes())["findings"][0]["lifecycle_state"],
            "REPRODUCED",
        )

    def test_submission_freezes_nested_data_and_deduplicates_queued_work(self):
        data = {"target": {"url": "https://before.test/"}}
        with patch.object(self.mgr._executor, "submit") as dispatch:
            first = self.mgr.submit_render_job("frozen", "json", data)
            same = self.mgr.submit_render_job("frozen", "json", json.loads(json.dumps(data)))
            self.assertEqual(first.job_id, same.job_id)
            self.assertEqual(dispatch.call_count, 1)
        data["target"]["url"] = "https://after.test/"
        execute, *arguments = dispatch.call_args.args
        execute(*arguments)
        self.assertEqual(first.status, "completed")
        rendered = json.loads(Path(first.output_path).read_bytes())
        self.assertEqual(rendered["target"]["url"], "https://before.test/")

    def test_concurrent_equivalent_submissions_dispatch_once(self):
        ready = threading.Barrier(4)

        def submit(_):
            ready.wait(timeout=2)
            return self.mgr.submit_render_job(
                "concurrent", "json", {"target": {"url": "https://fixture.test/"}}
            )

        with patch.object(self.mgr._executor, "submit") as dispatch:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as callers:
                jobs = list(callers.map(submit, range(4)))
        self.assertEqual(len({job.job_id for job in jobs}), 1)
        self.assertEqual(dispatch.call_count, 1)

    def test_rejected_dispatch_fails_job_and_releases_idempotency_lock(self):
        with patch.object(self.mgr._executor, "submit", side_effect=RuntimeError("Executor closed")):
            with self.assertRaisesRegex(RuntimeError, "Executor closed"):
                self.mgr.submit_render_job("rejected", "json", {})
        failed = list(self.mgr._jobs.values())
        self.assertEqual([job.status for job in failed], ["failed"])
        self.assertIsNotNone(failed[0].finished_at)
        self.assertEqual(failed[0].error, "Executor closed")
        self.assertFalse(self.mgr._active_locks)
        retried = self.wait_for_job(self.mgr.submit_render_job("rejected", "json", {}))
        self.assertEqual(retried.status, "completed")

    def test_artifacts_are_private_and_assessment_id_cannot_change_path(self):
        job = self.wait_for_job(self.mgr.submit_render_job("nested/../../outside", "json", {}))
        self.assertEqual(job.status, "completed", job.error)
        artifact = Path(job.output_path)
        self.assertEqual(artifact.parent.resolve(), Path(self.temp_dir.name).resolve())
        self.assertEqual(artifact.name, f"sharay-{job.job_id}.json")
        self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(artifact.parent.stat().st_mode), 0o700)

    def test_render_timeout_kills_and_reaps_renderer_process(self):
        pid_path = Path(self.temp_dir.name) / "renderer.pid"
        child = (
            "import os,time; from pathlib import Path; "
            f"Path({str(pid_path)!r}).write_text(str(os.getpid())); time.sleep(30)"
        )
        with (
            patch.object(async_renderer, "MAX_RENDER_TIMEOUT_SECONDS", 0.2),
            patch.object(async_renderer, "_RENDER_SOURCE", child, create=True),
        ):
            started = time.monotonic()
            job = self.wait_for_job(self.mgr.submit_render_job("timeout", "json", {}))
        self.assertEqual(job.status, "failed")
        self.assertIn("timeout", job.error.lower())
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(pid_path.exists(), "Expected an actual renderer process")
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_path.read_text()), 0)
        self.assertFalse(self.mgr._active_locks)

    def test_shutdown_cancels_queued_jobs_and_allows_no_further_dispatch(self):
        with patch.object(self.mgr._executor, "submit"):
            queued = self.mgr.submit_render_job("shutdown", "json", {})
        self.mgr.shutdown()
        self.assertEqual(queued.status, "failed")
        self.assertIn("shut down", queued.error)
        self.assertFalse(self.mgr._active_locks)
        with self.assertRaises(RuntimeError):
            self.mgr.submit_render_job("shutdown", "json", {})

    def test_renderer_process_failure_records_error_and_allows_retry(self):
        child = "import sys; sys.stderr.write('Synthetic renderer failure'); sys.exit(7)"
        with (
            patch.object(async_renderer, "_RENDER_SOURCE", child),
            self.assertLogs("sharay.reporting.async", level="ERROR"),
        ):
            failed = self.wait_for_job(self.mgr.submit_render_job("renderer-error", "json", {}))
        self.assertEqual(failed.status, "failed")
        self.assertIn("code 7: Synthetic renderer failure", failed.error)
        self.assertIsNone(failed.output_path)
        self.assertFalse(self.mgr._active_locks)
        retry = self.wait_for_job(self.mgr.submit_render_job("renderer-error", "json", {}))
        self.assertNotEqual(retry.job_id, failed.job_id)
        self.assertEqual(retry.status, "completed")

    def test_invalid_json_input_does_not_create_a_queued_job(self):
        for invalid in ({"value": float("nan")}, {"value": float("inf")}, []):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.mgr.submit_render_job("invalid-json", "json", invalid)
        self.assertFalse(self.mgr._jobs)
        self.assertFalse(self.mgr._active_locks)


if __name__ == "__main__":
    unittest.main()
