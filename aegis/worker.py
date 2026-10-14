"""One durable local queue and dedicated, bounded safe-scanner process."""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

from sqlalchemy import select, text

from aegis.audit import audit
from aegis.config import ROOT, Settings
from aegis.database import create_database
from aegis.lifecycle import watch_parent_stdin
from aegis.models import Assessment, Finding, FindingEvidence, FindingHistory, Observation
from packages.reporting import redact
from packages.scanner_adapters import scan
from packages.security_policies import ScopePolicy

# ponytail: one local worker; durable shared pacing is required before multiworker/live release.
_request_starts: dict[str, tuple[float, float]] = {}


def evidence_hash(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def mark_interrupted(sessions):
    with sessions() as db:
        db.execute(text("BEGIN IMMEDIATE"))
        for row in db.scalars(select(Assessment).where(Assessment.status.in_(["running", "cancelling"]))):
            row.status = "cancelled" if row.cancel_requested else "failed"
            row.stage = "Worker stopped before completion"
            row.error = "Worker interruption; stored evidence does not establish complete coverage"
            row.finished_at = time.time()
            audit(db, row.organization_id, "worker", "assessment.interrupted", row.id)
        db.commit()


def run_one(sessions, stopping=lambda: False) -> bool:
    with sessions() as db:
        db.execute(text("BEGIN IMMEDIATE"))
        row = db.scalar(
            select(Assessment).where(Assessment.status == "queued").order_by(Assessment.created_at).limit(1)
        )
        if row is None:
            db.rollback()
            return False
        row.status, row.stage, row.started_at = "running", "Validating approved scope", time.time()
        assessment_id, organization_id, target_id = row.id, row.organization_id, row.target_id
        scope = {key: value for key, value in row.scope_snapshot.items() if key in ScopePolicy.model_fields}
        target_url = row.scope_snapshot["target_url"]
        audit(db, organization_id, "worker", "assessment.started", row.id)
        db.commit()

    def cancelled():
        if stopping():
            return True
        with sessions() as db:
            current = db.get(Assessment, assessment_id)
            return not current or current.cancel_requested

    def emit(event):
        with sessions() as db:
            db.execute(text("BEGIN IMMEDIATE"))
            current = db.get(Assessment, assessment_id)
            if current:
                current.stage = (
                    "Collecting HTTP evidence"
                    if event.get("type") == "observation"
                    else "Checking scope and coverage"
                )
                audit(
                    db,
                    organization_id,
                    "worker",
                    "scanner." + event.get("type", "event"),
                    assessment_id,
                    redact(event),
                )
                db.commit()

    try:
        result = scan(scope, target_url, cancelled, emit, request_starts=_request_starts)
    except Exception as exc:
        # Only fixed builtin names are retained: messages and custom class names can contain secrets.
        error_class = {
            RuntimeError: "RuntimeError",
            TypeError: "TypeError",
            ValueError: "ValueError",
            KeyError: "KeyError",
            IndexError: "IndexError",
            OSError: "OSError",
            TimeoutError: "TimeoutError",
            AssertionError: "AssertionError",
        }.get(type(exc), "Exception")
        result = {
            "outcome": "failed",
            "observations": [],
            "findings": [],
            "checks": [
                {
                    "category": "safe_http",
                    "status": "failed",
                    "detail": "Unexpected adapter error",
                    "error_class": error_class,
                }
            ],
        }
    with sessions() as db:
        db.execute(text("BEGIN IMMEDIATE"))
        current = db.get(Assessment, assessment_id)
        if current is None:
            return True
        outcome = result["outcome"]
        if current.cancel_requested or stopping():
            outcome = "cancelled"
        current.status, current.finished_at = outcome, time.time()
        current.stage = {
            "completed": "Assessment complete",
            "completed_with_errors": "Finished with coverage errors",
            "failed": "Assessment failed",
            "cancelled": "Assessment cancelled",
        }[outcome]
        current.checks = redact(result.get("checks", []))
        if outcome in {"failed", "completed_with_errors"}:
            current.error = "One or more checks did not complete; review coverage details"
        saved_observations = []
        for observation in result.get("observations", []):
            clean = redact(observation)
            item = Observation(
                organization_id=organization_id,
                assessment_id=assessment_id,
                data=clean,
                evidence_hash=evidence_hash(clean),
            )
            db.add(item)
            db.flush()
            saved_observations.append(item)
        seen = set()
        for raw in result.get("findings", []):
            clean = redact(raw)
            fingerprint = clean["fingerprint"]
            seen.add(fingerprint)
            finding = db.scalar(
                select(Finding).where(Finding.target_id == target_id, Finding.fingerprint == fingerprint)
            )
            state = "confirmed"
            if finding:
                state = "reopened" if finding.status == "fixed" else finding.status
                finding.last_seen = time.time()
                finding.status = state
            else:
                finding = Finding(
                    organization_id=organization_id,
                    project_id=current.project_id,
                    target_id=target_id,
                    fingerprint=fingerprint,
                    title=clean["title"],
                    category=clean["category"],
                    severity=clean["severity"],
                    confidence=str(clean["confidence"]),
                    status=state,
                    description=clean["description"],
                    remediation=clean["remediation"],
                    affected_url=clean["affected_url"],
                )
                db.add(finding)
                db.flush()
            snapshot = {
                **clean,
                "status": state,
                "observation_ids": [
                    o.id for o in saved_observations if o.data.get("url") == clean["affected_url"]
                ],
            }
            db.add(
                FindingEvidence(
                    finding_id=finding.id,
                    assessment_id=assessment_id,
                    data=snapshot,
                    evidence_hash=evidence_hash(snapshot),
                )
            )
            db.add(
                FindingHistory(
                    finding_id=finding.id,
                    status=state,
                    actor="safe_http",
                    reason="Configuration fact observed in assessment " + assessment_id,
                )
            )
        # A failed/partial/cancelled retest must not establish remediation.
        complete_headers = outcome == "completed" and any(
            c.get("category") == "http_headers" and c.get("status") == "completed" for c in current.checks
        )
        covered_urls = {
            c.get("url")
            for c in current.checks
            if c.get("category") == "http_headers" and c.get("status") == "completed"
        }
        if current.retest_of and complete_headers:
            baseline_ids = select(FindingEvidence.finding_id).where(
                FindingEvidence.assessment_id == current.retest_of
            )
            for finding in db.scalars(
                select(Finding).where(Finding.target_id == target_id, Finding.id.in_(baseline_ids))
            ):
                if finding.fingerprint not in seen and finding.affected_url in covered_urls:
                    finding.status = "fixed"
                    db.add(
                        FindingHistory(
                            finding_id=finding.id,
                            status="fixed",
                            actor="safe_http",
                            reason="Absent in completed retest " + assessment_id,
                        )
                    )
                    snapshot = {
                        "status": "fixed",
                        "title": finding.title,
                        "category": finding.category,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "description": finding.description,
                        "remediation": finding.remediation,
                        "affected_url": finding.affected_url,
                        "verification": "Absent in complete safe HTTP retest",
                        "observation_ids": [o.id for o in saved_observations],
                    }
                    db.add(
                        FindingEvidence(
                            finding_id=finding.id,
                            assessment_id=assessment_id,
                            data=snapshot,
                            evidence_hash=evidence_hash(snapshot),
                        )
                    )
        audit(
            db,
            organization_id,
            "worker",
            "assessment." + outcome,
            assessment_id,
            {
                "checks": current.checks,
                "adapter": result.get("adapter", "safe_http"),
                "version": result.get("version"),
                "duration_ms": result.get("duration_ms"),
                "requests_performed": result.get("requests_performed"),
            },
        )
        db.commit()
    return True


class WorkerSupervisor:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.process: subprocess.Popen[bytes] | None = None

    def start(self):
        environment = {
            key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "TMPDIR", "LANG") if key in os.environ
        }
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "aegis.worker",
                "--data-dir",
                str(self.settings.data_dir),
                "--parent-stdin",
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self):
        if self.process is not None and self.process.stdin:
            self.process.stdin.close()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
        import fcntl

        # A duplicate supervisor must never alter a different live worker's jobs.
        with (self.settings.data_dir / "worker.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            engine, sessions = create_database(self.settings, migrate=False)
            try:
                mark_interrupted(sessions)
            finally:
                engine.dispose()


def main():
    import fcntl
    import resource
    from pathlib import Path

    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--parent-stdin", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    settings = Settings(Path(args.data_dir), start_worker=False)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    # Limits total CPU per worker lifetime; no target code executes here.
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    with (settings.data_dir / "worker.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 2
        engine, sessions = create_database(settings, migrate=False)
        stop = [False]

        def request_stop(_signum, _frame):
            stop[0] = True

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        try:
            with watch_parent_stdin(args.parent_stdin, lambda: request_stop(None, None)):
                try:
                    mark_interrupted(sessions)
                    while not stop[0]:
                        if not run_one(sessions, lambda: stop[0]):
                            time.sleep(0.25)
                finally:
                    mark_interrupted(sessions)
        finally:
            engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
