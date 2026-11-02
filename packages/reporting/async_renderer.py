"""Asynchronous report rendering with a subprocess wall-clock deadline.

Decouples heavy PDF, HTML, and Markdown document rendering from the FastAPI request thread:
- Job queue pattern: Returns `202 Accepted {job_id}` immediately.
- Content-aware idempotency prevents redundant concurrent renders.
- A renderer subprocess is killed and reaped after its wall-clock deadline.
- SHA-256 identifies the final artifact; it does not authenticate its provenance.
- An optional canary checks renderer dependencies against a fixed local fixture.

The renderer has no operating-system memory or CPU quota and is not a sandbox.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packages.reporting.reports import redact, render_report

logger = logging.getLogger("sharay.reporting.async")

REPORTS_DIR = Path(".aegis/reports")
MAX_RENDER_TIMEOUT_SECONDS = 120.0
_RENDER_SOURCE = """import json, sys
from packages.reporting.reports import render_report
body, _ = render_report(json.load(sys.stdin), sys.argv[1])
sys.stdout.buffer.write(body)
"""
_CONTENT_TYPES = {
    "html": "text/html; charset=utf-8",
    "json": "application/json",
    "markdown": "text/markdown; charset=utf-8",
    "pdf": "application/pdf",
    "sarif": "application/sarif+json",
    "csv": "text/csv; charset=utf-8",
    "bundle": "application/zip",
    "zip": "application/zip",
}


@dataclass
class ReportJob:
    job_id: str
    assessment_id: str
    format: str
    status: str  # "queued" | "rendering" | "completed" | "failed"
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    output_path: str | None = None
    content_type: str | None = None
    sha256_hash: str | None = None
    error: str | None = None
    request_sha256: str = field(default="", repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "assessment_id": self.assessment_id,
            "format": self.format,
            "status": self.status,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "download_url": f"/api/v1/reports/jobs/{self.job_id}/download"
            if self.status == "completed"
            else None,
            "sha256_hash": self.sha256_hash,
            "error": self.error,
        }


class ReportJobManager:
    """Thread-safe report job queue and lifecycle coordinator with idempotency locking."""

    def __init__(self, reports_dir: Path | str = REPORTS_DIR, max_workers: int = 4) -> None:
        self.reports_dir = Path(reports_dir).resolve()
        self.reports_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.reports_dir.chmod(0o700)
        self._jobs: dict[str, ReportJob] = {}
        self._active_locks: dict[tuple[str, str, str], str] = {}
        self._lock = threading.Lock()
        self._closed = False
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="sharay-report-render"
        )

    def get_job(self, job_id: str) -> ReportJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def submit_render_job(
        self,
        assessment_id: str,
        format: str,
        report_data: dict[str, Any],
    ) -> ReportJob:
        """Submit an asynchronous report render job with idempotency locking."""
        norm_format = format.strip().lower()
        if norm_format == "md":
            norm_format = "markdown"
        if norm_format not in _CONTENT_TYPES:
            raise ValueError("Unsupported report format")
        if not isinstance(report_data, dict):
            raise ValueError("Report data must be a dictionary")
        # Freeze nested data before dispatch; only generation time is excluded from cache identity.
        payload = json.dumps(report_data, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
        identity = json.loads(payload)
        identity.pop("generated_at", None)
        request_hash = hashlib.sha256(
            json.dumps(identity, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
        ).hexdigest()
        lock_key = (assessment_id, norm_format, request_hash)

        with self._lock:
            if self._closed:
                raise RuntimeError("Report renderer has been shut down")
            existing_job_id = self._active_locks.get(lock_key)
            if existing_job_id and existing_job_id in self._jobs:
                existing_job = self._jobs[existing_job_id]
                if existing_job.status in ("queued", "rendering"):
                    return existing_job
                if existing_job.status == "completed":
                    error = "Cached report artifact metadata is missing"
                    if existing_job.output_path and existing_job.sha256_hash:
                        try:
                            with Path(existing_job.output_path).open("rb") as artifact:
                                digest = hashlib.file_digest(artifact, "sha256").hexdigest()
                            if digest == existing_job.sha256_hash:
                                return existing_job
                            error = "Cached report artifact failed its SHA-256 integrity check"
                        except OSError as exc:
                            error = f"Cached report artifact is unavailable: {exc}"
                    existing_job.status = "failed"
                    existing_job.finished_at = time.time()
                    existing_job.error = redact(error)
                    self._active_locks.pop(lock_key, None)

            job_id = str(uuid.uuid4())
            job = ReportJob(
                job_id=job_id,
                assessment_id=assessment_id,
                format=norm_format,
                status="queued",
                request_sha256=request_hash,
            )
            self._jobs[job_id] = job
            self._active_locks[lock_key] = job_id

        # Dispatch execution to background worker pool
        try:
            self._executor.submit(self._execute_render, job_id, payload)
        except Exception as exc:
            self._fail_job(job, str(exc))
            raise
        return job

    def _fail_job(self, job: ReportJob, error: str) -> None:
        with self._lock:
            job.status = "failed"
            job.finished_at = time.time()
            job.error = redact(error)
            lock_key = (job.assessment_id, job.format, job.request_sha256)
            if self._active_locks.get(lock_key) == job.job_id:
                self._active_locks.pop(lock_key)

    def _execute_render(self, job_id: str, payload: bytes) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.status != "queued":
                return
            job.status = "rendering"

        ext = "md" if job.format == "markdown" else ("zip" if job.format == "bundle" else job.format)
        output_file = self.reports_dir / f"sharay-{job.job_id}.{ext}"
        output_created = False

        try:
            start = time.monotonic()
            result = subprocess.run(
                [sys.executable, "-c", _RENDER_SOURCE, job.format],
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=MAX_RENDER_TIMEOUT_SECONDS,
                cwd=Path(__file__).resolve().parents[2],
                check=False,
            )
            if result.returncode:
                detail = result.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(f"Renderer exited with code {result.returncode}: {detail}")
            body = result.stdout
            elapsed = time.monotonic() - start
            logger.info("Rendered %s report in %.2fs", job.format, elapsed)

            descriptor = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            output_created = True
            with os.fdopen(descriptor, "wb") as output:
                output.write(body)

            # Compute the artifact digest.
            file_hash = hashlib.sha256(body).hexdigest()

            with self._lock:
                job.status = "completed"
                job.finished_at = time.time()
                job.output_path = str(output_file)
                job.content_type = _CONTENT_TYPES[job.format]
                job.sha256_hash = file_hash

        except subprocess.TimeoutExpired:
            self._fail_job(
                job, f"Report renderer exceeded {MAX_RENDER_TIMEOUT_SECONDS:g}s wall-clock timeout"
            )
        except Exception as exc:
            logger.exception("Async report rendering failed for job %s", job_id)
            self._fail_job(job, str(exc))
        finally:
            if output_created and job.status != "completed":
                output_file.unlink(missing_ok=True)

    def shutdown(self, wait: bool = True) -> None:
        """Cancel queued jobs; active render subprocesses retain their wall-clock deadline."""
        with self._lock:
            self._closed = True
        self._executor.shutdown(wait=wait, cancel_futures=True)
        with self._lock:
            queued = [job for job in self._jobs.values() if job.status == "queued"]
        for job in queued:
            self._fail_job(job, "Report renderer shut down before job execution")

    @staticmethod
    def verify_renderer_canary() -> bool:
        """Check that ReportLab and templates render a fixed local PDF fixture."""
        canary_data = {
            "assessment": {"id": "canary-test", "created_at": time.time(), "duration_seconds": 1.0},
            "project": {"name": "Canary Project"},
            "target": {"url": "https://localhost:443/"},
            "scope": {"target_url": "https://localhost:443/"},
            "observations": [],
            "findings": [],
            "checks": [{"category": "canary", "status": "completed", "detail": "Render canary ok"}],
            "events": [],
            "generated_at": "2026-10-15T00:00:00Z",
        }
        try:
            pdf_bytes, c_type = render_report(canary_data, "pdf")
            return len(pdf_bytes) > 1000 and c_type == "application/pdf"
        except Exception as exc:
            logger.error("Report renderer canary check failed: %s", exc)
            return False


_DEFAULT_REPORT_MANAGER: ReportJobManager | None = None
_DEFAULT_MANAGER_LOCK = threading.Lock()


def get_report_manager(reports_dir: Path | str | None = None) -> ReportJobManager:
    if reports_dir is not None:
        return ReportJobManager(reports_dir)
    global _DEFAULT_REPORT_MANAGER
    with _DEFAULT_MANAGER_LOCK:
        if _DEFAULT_REPORT_MANAGER is None:
            _DEFAULT_REPORT_MANAGER = ReportJobManager()
        return _DEFAULT_REPORT_MANAGER


__all__ = ["ReportJob", "ReportJobManager", "get_report_manager"]
