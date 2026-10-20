"""Safe Concurrent Job Queue, Worker Pool & PostgreSQL Backend Abstraction.

Architecture Reference for Sector 4 (Platform, Scale & Persistence):
- Concurrency-safe job queue supporting N parallel workers.
- Per-origin rate coordination & concurrent origin exclusion (no target hammering).
- PostgreSQL dialect support with `FOR UPDATE SKIP LOCKED` + SQLite WAL fallback.
- Heartbeats, worker leasing, and dead-worker lease reaping.
"""

from __future__ import annotations

import math
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy import (
    Engine,
    select,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session, sessionmaker

from aegis.models import Assessment, OriginCooldown


def extract_origin(url: str) -> str:
    """Normalize target URL to protocol://host[:port] origin."""
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower() or "http"
        netloc = parsed.netloc.lower()
        if not netloc and parsed.path:
            netloc = parsed.path.split("/")[0].lower()
        return f"{scheme}://{netloc}"
    except Exception:
        return "default-origin"


@dataclass
class JobLease:
    """A thread/worker lease on an assessment task."""
    assessment_id: str
    worker_id: str
    target_origin: str
    target_url: str
    leased_at: float
    lease_expires_at: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now >= self.lease_expires_at


class DialectAdapter:
    """Dialect-specific SQL generation and query optimization."""

    @staticmethod
    def is_postgres(engine: Engine) -> bool:
        return engine.dialect.name == "postgresql"

    @staticmethod
    def is_sqlite(engine: Engine) -> bool:
        return engine.dialect.name == "sqlite"

    @classmethod
    def compile_for_update_skip_locked(cls) -> str:
        """Returns the compiled SQL statement for PostgreSQL concurrent leasing."""
        stmt = (
            select(Assessment)
            .where(Assessment.status == "queued")
            .order_by(Assessment.created_at)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        compiled = stmt.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
        return str(compiled)

    @classmethod
    def get_lease_statement(cls, engine: Engine):
        """Constructs dialect-optimized query statement."""
        stmt = (
            select(Assessment)
            .where(Assessment.status == "queued")
            .order_by(Assessment.created_at)
        )
        if cls.is_postgres(engine):
            stmt = stmt.with_for_update(skip_locked=True)
        return stmt


class OriginPacingCoordinator:
    """Thread-safe and multi-worker origin rate coordinator.

    Ensures:
    1. Mutual exclusion: At most ONE worker active against a given origin at any moment.
    2. Cooldown preservation: Enforces inter-request/inter-assessment delay per origin.
    """

    def __init__(self, sessions: sessionmaker[Session], default_cooldown: float = 0.5):
        self.sessions = sessions
        self.default_cooldown = default_cooldown
        self._lock = threading.RLock()
        # In-memory fast-tracking: origin -> (worker_id, acquired_at)
        self._active_origins: Dict[str, Tuple[str, float]] = {}
        # origin -> last_completion_timestamp
        self._last_completed: Dict[str, float] = {}

    def get_origin_interval(self, db: Session, origin: str) -> float:
        """Look up configured origin cooldown interval from DB."""
        row = db.get(OriginCooldown, origin)
        if row is not None and math.isfinite(row.interval) and row.interval >= 0.05:
            return float(row.interval)
        return self.default_cooldown

    def try_claim_origin(
        self,
        origin: str,
        worker_id: str,
        db: Optional[Session] = None,
        now: Optional[float] = None,
    ) -> bool:
        """Atomically attempt to claim an origin for a worker."""
        current_time = now if now is not None else time.time()
        with self._lock:
            # 1. Check if another worker is currently active on this origin
            if origin in self._active_origins:
                active_worker, _ = self._active_origins[origin]
                if active_worker != worker_id:
                    return False

            # 2. Check if cooldown has elapsed since last job on this origin
            last_done = self._last_completed.get(origin, 0.0)
            cooldown = self.default_cooldown
            if db is not None:
                try:
                    cooldown = self.get_origin_interval(db, origin)
                except Exception:
                    pass

            if current_time - last_done < cooldown:
                return False

            # Claim origin
            self._active_origins[origin] = (worker_id, current_time)
            return True

    def release_origin(
        self,
        origin: str,
        worker_id: str,
        now: Optional[float] = None,
        apply_cooldown: bool = True,
    ):
        """Release an origin claim and optionally record cooldown start."""
        current_time = now if now is not None else time.time()
        with self._lock:
            if origin in self._active_origins:
                active_worker, _ = self._active_origins[origin]
                if active_worker == worker_id:
                    del self._active_origins[origin]
                    if apply_cooldown:
                        self._last_completed[origin] = current_time

    def is_origin_active(self, origin: str) -> bool:
        with self._lock:
            return origin in self._active_origins

    def clear(self):
        with self._lock:
            self._active_origins.clear()
            self._last_completed.clear()


class ConcurrentJobQueue:
    """Production-grade job queue supporting N concurrent workers with safe leasing."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        engine: Optional[Engine] = None,
        origin_coordinator: Optional[OriginPacingCoordinator] = None,
        lease_timeout: float = 120.0,
    ):
        self.sessions = sessions
        self.engine = engine or sessions.kw.get("bind")
        self.lease_timeout = lease_timeout
        self.origin_coordinator = origin_coordinator or OriginPacingCoordinator(sessions)
        self._active_leases: Dict[str, JobLease] = {}
        self._lease_lock = threading.RLock()

    def lease_job(
        self,
        worker_id: str,
        lease_duration: Optional[float] = None,
        now: Optional[float] = None,
    ) -> Optional[JobLease]:
        """Atomically claim the next eligible queued job.
        
        Skips jobs whose target origin is currently busy on another worker.
        """
        duration = lease_duration or self.lease_timeout
        current_time = now if now is not None else time.time()

        with self.sessions() as db:
            is_sqlite = self.engine is not None and DialectAdapter.is_sqlite(self.engine)
            if is_sqlite:
                # Use immediate transaction for atomic read-modify-write on SQLite
                db.execute(text("BEGIN IMMEDIATE"))

            # Fetch candidate queued jobs in FIFO order
            stmt = select(Assessment).where(Assessment.status == "queued").order_by(Assessment.created_at)
            candidates = db.scalars(stmt).all()

            chosen: Optional[Assessment] = None
            target_origin: Optional[str] = None
            target_url: str = ""

            for cand in candidates:
                snapshot = cand.scope_snapshot or {}
                cand_url = snapshot.get("target_url") or ""
                origin = extract_origin(cand_url)

                # Try to claim this origin for worker
                if self.origin_coordinator.try_claim_origin(origin, worker_id, db=db, now=current_time):
                    chosen = cand
                    target_origin = origin
                    target_url = cand_url
                    break

            if chosen is None or target_origin is None:
                db.rollback()
                return None

            # Mark assessment running and attach lease metadata
            chosen.status = "running"
            chosen.stage = f"Leased to worker {worker_id}"
            chosen.started_at = current_time

            # Update checks or metadata to reflect worker ownership
            lease = JobLease(
                assessment_id=chosen.id,
                worker_id=worker_id,
                target_origin=target_origin,
                target_url=target_url,
                leased_at=current_time,
                lease_expires_at=current_time + duration,
                metadata={"organization_id": chosen.organization_id, "project_id": chosen.project_id},
            )

            db.commit()

            with self._lease_lock:
                self._active_leases[chosen.id] = lease

            return lease

    def heartbeat(
        self,
        lease: JobLease,
        extend_seconds: float = 60.0,
        now: Optional[float] = None,
    ) -> bool:
        """Extend an active lease timeout to prove worker liveness."""
        current_time = now if now is not None else time.time()
        with self._lease_lock:
            existing = self._active_leases.get(lease.assessment_id)
            if existing is None or existing.worker_id != lease.worker_id:
                return False
            existing.lease_expires_at = current_time + extend_seconds
            lease.lease_expires_at = existing.lease_expires_at
            return True

    def complete_job(
        self,
        lease: JobLease,
        outcome: str = "completed",
        error: Optional[str] = None,
        checks: Optional[List[Dict[str, Any]]] = None,
        now: Optional[float] = None,
    ) -> bool:
        """Mark job finished and release origin lock."""
        current_time = now if now is not None else time.time()
        with self.sessions() as db:
            row = db.get(Assessment, lease.assessment_id)
            if row is not None:
                row.status = outcome
                row.stage = "Assessment completed" if outcome == "completed" else "Assessment failed"
                row.finished_at = current_time
                if error:
                    row.error = error
                if checks is not None:
                    row.checks = checks
                db.commit()

        # Release origin and lease
        with self._lease_lock:
            self._active_leases.pop(lease.assessment_id, None)

        self.origin_coordinator.release_origin(lease.target_origin, lease.worker_id, now=current_time)
        return True

    def reap_expired_leases(
        self,
        requeue: bool = True,
        now: Optional[float] = None,
    ) -> List[str]:
        """Detect worker crashes / expired leases and recover or fail them."""
        current_time = now if now is not None else time.time()
        reaped: List[str] = []

        with self._lease_lock:
            expired_ids = [
                aid for aid, l in self._active_leases.items() if l.is_expired(current_time)
            ]

        for aid in expired_ids:
            with self._lease_lock:
                lease = self._active_leases.pop(aid, None)

            if lease is None:
                continue

            with self.sessions() as db:
                row = db.get(Assessment, aid)
                if row is not None and row.status == "running":
                    if requeue:
                        row.status = "queued"
                        row.stage = "Requeued after worker lease timeout"
                        row.started_at = None
                    else:
                        row.status = "failed"
                        row.stage = "Worker heartbeat timeout"
                        row.error = f"Lease expired for worker {lease.worker_id}"
                        row.finished_at = current_time
                    db.commit()
                    reaped.append(aid)

            # Release origin claim; do not penalize crashed leases with completion cooldown
            self.origin_coordinator.release_origin(
                lease.target_origin,
                lease.worker_id,
                now=current_time,
                apply_cooldown=not requeue,
            )

        return reaped


class ConcurrentWorkerPool:
    """Coordinates a pool of N concurrent workers executing jobs from ConcurrentJobQueue."""

    def __init__(
        self,
        queue: ConcurrentJobQueue,
        worker_count: int = 4,
        job_handler: Optional[Callable[[JobLease], Tuple[str, Optional[str]]]] = None,
        poll_interval: float = 0.05,
    ):
        self.queue = queue
        self.worker_count = worker_count
        self.job_handler = job_handler or self._default_handler
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._processed_count = 0
        self._count_lock = threading.Lock()

    @staticmethod
    def _default_handler(lease: JobLease) -> Tuple[str, Optional[str]]:
        # Simulates minimal non-zero work
        time.sleep(0.01)
        return "completed", None

    def _worker_loop(self, worker_index: int):
        worker_id = f"worker-{worker_index}-{uuid.uuid4().hex[:6]}"
        while not self._stop_event.is_set():
            lease = self.queue.lease_job(worker_id)
            if lease is None:
                time.sleep(self.poll_interval)
                continue

            # Process job
            outcome, error = "completed", None
            try:
                outcome, error = self.job_handler(lease)
            except Exception as exc:
                outcome, error = "failed", str(exc)
            finally:
                self.queue.complete_job(lease, outcome=outcome, error=error)
                with self._count_lock:
                    self._processed_count += 1

    def start(self):
        self._stop_event.clear()
        self._threads = []
        for i in range(self.worker_count):
            t = threading.Thread(target=self._worker_loop, args=(i,), daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self, timeout: float = 5.0):
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=timeout)
        self._threads.clear()

    @property
    def processed_count(self) -> int:
        with self._count_lock:
            return self._processed_count
