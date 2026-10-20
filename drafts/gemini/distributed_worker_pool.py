"""Distributed Worker Pool, Leased Job Engine & Multi-Tenant Quota System.

Part of SHARAY Sector 4 (Platform, Scale & Persistence - Milestone P2.1 & P2.3).
Provides:
1. Headless worker registration, capabilities, and monotonic heartbeat monitoring.
2. Safe distributed lease claims with automatic stale-worker reaping and job re-dispatch.
3. Multi-tenant fair-share scheduling and per-org concurrency quotas.
4. Resumable assessment checkpointing across worker reboots and failovers.
"""

from __future__ import annotations

import collections
import dataclasses
import enum
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

_DEFAULT_HEARTBEAT_TIMEOUT = 30.0  # seconds
_DEFAULT_LEASE_DURATION = 45.0     # seconds
_DEFAULT_MAX_ATTEMPTS = 3


class WorkerStatus(str, enum.Enum):
    ONLINE = "ONLINE"
    DRAINING = "DRAINING"
    OFFLINE = "OFFLINE"


class JobState(str, enum.Enum):
    QUEUED = "QUEUED"
    CLAIMED = "CLAIMED"
    RUNNING = "RUNNING"
    CHECKPOINTED = "CHECKPOINTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclasses.dataclass
class WorkerNode:
    node_id: str
    hostname: str
    capacity: int
    last_heartbeat: float
    status: WorkerStatus = WorkerStatus.ONLINE
    active_leases: Set[str] = dataclasses.field(default_factory=set)
    tags: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class AssessmentCheckpoint:
    assessment_id: str
    stage_index: int
    stage_name: str
    stage_percent: float
    completed_stages: List[str]
    interim_findings: List[Dict[str, Any]]
    remaining_urls: List[str]
    checkpoint_epoch: float


@dataclasses.dataclass
class DistributedJob:
    assessment_id: str
    target_origin: str
    org_id: str
    state: JobState = JobState.QUEUED
    assigned_worker_id: Optional[str] = None
    leased_at: Optional[float] = None
    lease_expires_at: Optional[float] = None
    attempt_count: int = 0
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS
    checkpoint: Optional[AssessmentCheckpoint] = None
    created_at: float = dataclasses.field(default_factory=time.time)


class MultiTenantQuotaManager:
    """Enforces per-organization concurrency limits and fair queue depth."""

    def __init__(self, default_org_quota: int = 3, org_quotas: Optional[Dict[str, int]] = None) -> None:
        self.default_org_quota = default_org_quota
        self.org_quotas = org_quotas or {}
        self._active_org_counts: Dict[str, int] = collections.defaultdict(int)

    def get_quota(self, org_id: str) -> int:
        return self.org_quotas.get(org_id, self.default_org_quota)

    def can_lease(self, org_id: str) -> bool:
        return self._active_org_counts[org_id] < self.get_quota(org_id)

    def record_job_started(self, org_id: str) -> None:
        self._active_org_counts[org_id] += 1

    def record_job_finished(self, org_id: str) -> None:
        if self._active_org_counts[org_id] > 0:
            self._active_org_counts[org_id] -= 1

    def active_count(self, org_id: str) -> int:
        return self._active_org_counts[org_id]


class DistributedWorkerCoordinator:
    """Coordinates distributed scanning farms with leases, heartbeat reap, quotas, and checkpointing."""

    def __init__(
        self,
        heartbeat_timeout: float = _DEFAULT_HEARTBEAT_TIMEOUT,
        lease_duration: float = _DEFAULT_LEASE_DURATION,
        quota_manager: Optional[MultiTenantQuotaManager] = None,
    ) -> None:
        self.heartbeat_timeout = heartbeat_timeout
        self.lease_duration = lease_duration
        self.quota_mgr = quota_manager or MultiTenantQuotaManager()

        self._lock = threading.RLock()
        self._workers: Dict[str, WorkerNode] = {}
        self._jobs: Dict[str, DistributedJob] = {}
        self._active_origins: Set[str] = set()

    def register_worker(
        self,
        node_id: str,
        hostname: str,
        capacity: int = 4,
        tags: Optional[List[str]] = None,
        now: Optional[float] = None,
    ) -> WorkerNode:
        ts = now if now is not None else time.time()
        with self._lock:
            node = WorkerNode(
                node_id=node_id,
                hostname=hostname,
                capacity=max(1, capacity),
                last_heartbeat=ts,
                status=WorkerStatus.ONLINE,
                tags=tags or [],
            )
            self._workers[node_id] = node
            return node

    def record_heartbeat(self, node_id: str, now: Optional[float] = None) -> bool:
        ts = now if now is not None else time.time()
        with self._lock:
            worker = self._workers.get(node_id)
            if not worker:
                return False
            worker.last_heartbeat = ts
            if worker.status == WorkerStatus.OFFLINE:
                worker.status = WorkerStatus.ONLINE
            return True

    def submit_job(
        self,
        assessment_id: str,
        target_origin: str,
        org_id: str,
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    ) -> DistributedJob:
        with self._lock:
            if assessment_id in self._jobs:
                raise ValueError(f"Job {assessment_id} already exists")
            job = DistributedJob(
                assessment_id=assessment_id,
                target_origin=target_origin,
                org_id=org_id,
                state=JobState.QUEUED,
                max_attempts=max_attempts,
            )
            self._jobs[assessment_id] = job
            return job

    def lease_next_job(
        self,
        worker_id: str,
        now: Optional[float] = None,
    ) -> Optional[DistributedJob]:
        """Atomically leases the highest-priority eligible job to a requesting worker."""
        ts = now if now is not None else time.time()
        with self._lock:
            worker = self._workers.get(worker_id)
            if not worker or worker.status != WorkerStatus.ONLINE:
                return None

            # Check worker slot capacity
            if len(worker.active_leases) >= worker.capacity:
                return None

            # Find next eligible queued job
            for job in self._jobs.values():
                if job.state != JobState.QUEUED:
                    continue

                # Rule 1: Per-origin mutual exclusion across entire cluster
                if job.target_origin in self._active_origins:
                    continue

                # Rule 2: Multi-tenant per-organization concurrency quota
                if not self.quota_mgr.can_lease(job.org_id):
                    continue

                # Claim job
                job.state = JobState.CLAIMED
                job.assigned_worker_id = worker_id
                job.leased_at = ts
                job.lease_expires_at = ts + self.lease_duration
                job.attempt_count += 1

                self._active_origins.add(job.target_origin)
                self.quota_mgr.record_job_started(job.org_id)
                worker.active_leases.add(job.assessment_id)
                return job

            return None

    def renew_lease(self, assessment_id: str, worker_id: str, now: Optional[float] = None) -> bool:
        ts = now if now is not None else time.time()
        with self._lock:
            job = self._jobs.get(assessment_id)
            if not job or job.assigned_worker_id != worker_id:
                return False
            job.lease_expires_at = ts + self.lease_duration
            return True

    def save_checkpoint(
        self,
        assessment_id: str,
        worker_id: str,
        stage_index: int,
        stage_name: str,
        stage_percent: float,
        completed_stages: List[str],
        interim_findings: List[Dict[str, Any]],
        remaining_urls: List[str],
        now: Optional[float] = None,
    ) -> bool:
        """Persists progressive scan state so interrupted assessments resume without restarting."""
        ts = now if now is not None else time.time()
        with self._lock:
            job = self._jobs.get(assessment_id)
            if not job or job.assigned_worker_id != worker_id:
                return False

            checkpoint = AssessmentCheckpoint(
                assessment_id=assessment_id,
                stage_index=stage_index,
                stage_name=stage_name,
                stage_percent=stage_percent,
                completed_stages=list(completed_stages),
                interim_findings=list(interim_findings),
                remaining_urls=list(remaining_urls),
                checkpoint_epoch=ts,
            )
            job.checkpoint = checkpoint
            job.state = JobState.CHECKPOINTED
            return True

    def complete_job(self, assessment_id: str, worker_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(assessment_id)
            if not job or job.assigned_worker_id != worker_id:
                return False

            job.state = JobState.COMPLETED
            job.assigned_worker_id = None
            self._active_origins.discard(job.target_origin)
            self.quota_mgr.record_job_finished(job.org_id)

            worker = self._workers.get(worker_id)
            if worker:
                worker.active_leases.discard(assessment_id)
            return True

    def reap_stale_workers(self, now: Optional[float] = None) -> List[str]:
        """Detects crashed or timed-out workers, revokes leases, and re-enqueues orphaned jobs."""
        ts = now if now is not None else time.time()
        reaped_jobs: List[str] = []

        with self._lock:
            for worker_id, worker in list(self._workers.items()):
                if worker.status == WorkerStatus.OFFLINE:
                    continue

                if ts - worker.last_heartbeat > self.heartbeat_timeout:
                    worker.status = WorkerStatus.OFFLINE
                    # Revoke all active leases for this dead worker
                    for ass_id in list(worker.active_leases):
                        job = self._jobs.get(ass_id)
                        if not job:
                            continue

                        self._active_origins.discard(job.target_origin)
                        self.quota_mgr.record_job_finished(job.org_id)

                        if job.attempt_count < job.max_attempts:
                            # Re-enqueue for another available worker to resume from checkpoint!
                            job.state = JobState.QUEUED
                            job.assigned_worker_id = None
                            job.lease_expires_at = None
                            reaped_jobs.append(ass_id)
                        else:
                            # Exceeded max retry attempts
                            job.state = JobState.FAILED
                            job.assigned_worker_id = None

                    worker.active_leases.clear()

        return reaped_jobs
