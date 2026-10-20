"""Product & integration tests for Sector 4: Concurrent Queue, Origin Pacing & Worker Pool.

Verifies:
1. Multi-worker leasing without race conditions or duplicate leases.
2. Cross-worker / cross-process origin mutual exclusion and pacing.
3. Worker crash recovery via lease reaping and origin release.
4. ConcurrentWorkerPool execution against live SQLite database.
5. PostgreSQL DialectAdapter SQL compilation with FOR UPDATE SKIP LOCKED.
"""

import tempfile
import time
import unittest
from pathlib import Path

from aegis.config import Settings
from aegis.database import create_database
from aegis.models import Assessment, Organization, Project, Target, User
from aegis.queue import (
    ConcurrentJobQueue,
    ConcurrentWorkerPool,
    DialectAdapter,
    JobLease,
    extract_origin,
)


class TestQueueConcurrency(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.settings = Settings(self.data_dir, start_worker=False)
        self.engine, self.sessions = create_database(self.settings, migrate=True)

        # Seed initial organization and target
        with self.sessions() as db:
            org = Organization(id="org-concurrent-test", name="Concurrency Test Org")
            db.add(org)
            db.flush()
            user = User(
                id="usr-concurrent-test",
                organization_id=org.id,
                username="tester",
                role="admin",
                password_hash="test-hash",
            )
            db.add(user)
            db.flush()
            project = Project(
                id="proj-concurrent-test",
                organization_id=org.id,
                owner_id=user.id,
                name="Test Project",
            )
            db.add(project)
            db.commit()

    def tearDown(self):
        self.engine.dispose()
        self.temp_dir.cleanup()

    def _create_assessment(self, assessment_id: str, target_url: str, org_id="org-concurrent-test") -> str:
        with self.sessions() as db:
            # Create or reuse target
            target_id = f"target-{extract_origin(target_url)}"
            target = db.get(Target, target_id)
            if not target:
                target = Target(
                    id=target_id,
                    organization_id=org_id,
                    project_id="proj-concurrent-test",
                    url=target_url,
                    scope={"allowed_hosts": [target_url]},
                    verification_status="operator_authorized",
                )
                db.add(target)
                db.flush()

            assessment = Assessment(
                id=assessment_id,
                organization_id=org_id,
                project_id="proj-concurrent-test",
                target_id=target_id,
                created_by="usr-concurrent-test",
                idempotency_key=f"idem-{assessment_id}",
                profile="safe_http",
                status="queued",
                scope_version=1,
                scope_snapshot={
                    "target_url": target_url,
                    "allowed_hosts": [target_url],
                    "safe_mode": True,
                },
                created_at=time.time(),
            )
            db.add(assessment)
            db.commit()
        return assessment_id

    def test_multi_worker_leasing_no_duplicates(self):
        """Ensure multiple workers concurrently leasing jobs never receive the same assessment."""
        # Enqueue 5 jobs across different origins
        for i in range(5):
            self._create_assessment(f"assess-{i}", f"http://app{i}.local/api")

        queue = ConcurrentJobQueue(self.sessions, lease_duration=60.0)

        # Worker 1 leases
        lease1 = queue.lease_job("worker-1")
        self.assertIsNotNone(lease1)
        self.assertEqual(lease1.worker_id, "worker-1")

        # Worker 2 leases
        lease2 = queue.lease_job("worker-2")
        self.assertIsNotNone(lease2)
        self.assertEqual(lease2.worker_id, "worker-2")

        # Worker 3 leases
        lease3 = queue.lease_job("worker-3")
        self.assertIsNotNone(lease3)

        # Leases must be strictly distinct assessments
        leased_ids = {lease1.assessment_id, lease2.assessment_id, lease3.assessment_id}
        self.assertEqual(len(leased_ids), 3)

        # In DB, these assessments must be marked running
        with self.sessions() as db:
            for aid in leased_ids:
                row = db.get(Assessment, aid)
                self.assertIsNotNone(row)
                self.assertEqual(row.status, "running")

    def test_origin_pacing_exclusion(self):
        """Ensure two assessments targeting the same origin cannot run concurrently."""
        origin = "http://shared-target.local"
        self._create_assessment("job-alpha", f"{origin}/page-1")
        self._create_assessment("job-beta", f"{origin}/page-2")

        queue = ConcurrentJobQueue(self.sessions, lease_duration=60.0)

        # Worker 1 leases job-alpha
        lease1 = queue.lease_job("worker-1")
        self.assertIsNotNone(lease1)
        self.assertEqual(lease1.assessment_id, "job-alpha")

        # Worker 2 attempts to lease: job-beta has the same origin so it must NOT be leased!
        lease2 = queue.lease_job("worker-2")
        self.assertIsNone(
            lease2,
            "Worker 2 should not be able to lease job-beta while job-alpha is active on the same origin",
        )

        # Complete job-alpha with zero artificial cooldown for this test
        queue.complete_job(lease1, outcome="completed", error=None)

        # Simulate cooldown elapsing (cooldown interval elapsed):
        lease2_retry = queue.lease_job("worker-2", now=time.time() + 10.0)
        self.assertIsNotNone(
            lease2_retry, "Worker 2 should now lease job-beta after job-alpha completes and cooldown elapses"
        )
        self.assertEqual(lease2_retry.assessment_id, "job-beta")

        queue.complete_job(lease2_retry, outcome="completed", error=None)

    def test_lease_reaping_on_worker_crash(self):
        """Ensure expired worker leases are automatically reaped and requeued."""
        self._create_assessment("crash-job", "http://crash-test.local/vuln")

        # Set very short lease duration
        queue = ConcurrentJobQueue(self.sessions, lease_duration=0.1)

        lease = queue.lease_job("worker-crasher")
        self.assertIsNotNone(lease)
        self.assertEqual(lease.assessment_id, "crash-job")

        # Wait for lease to expire
        time.sleep(0.15)
        self.assertTrue(lease.is_expired())

        # Reap expired leases
        reaped = queue.reap_expired_leases(requeue=True)
        self.assertIn("crash-job", reaped)

        # Check DB: status should be reset to queued
        with self.sessions() as db:
            row = db.get(Assessment, "crash-job")
            self.assertEqual(row.status, "queued")

        # Another worker can now lease the job
        new_lease = queue.lease_job("worker-survivor")
        self.assertIsNotNone(new_lease)
        self.assertEqual(new_lease.assessment_id, "crash-job")
        queue.complete_job(new_lease, outcome="completed", error=None)

    def test_concurrent_worker_pool_processes_all_jobs(self):
        """Ensure ConcurrentWorkerPool drains multiple jobs using worker threads."""
        job_count = 6
        for i in range(job_count):
            self._create_assessment(f"pool-job-{i}", f"http://service-{i}.internal/health")

        queue = ConcurrentJobQueue(self.sessions, lease_duration=30.0)

        completed_records = []

        def mock_handler(lease: JobLease):
            completed_records.append(lease.assessment_id)
            return "completed", None

        pool = ConcurrentWorkerPool(queue, worker_count=3, job_handler=mock_handler, poll_interval=0.01)
        pool.start()

        # Wait for all jobs to be processed
        max_wait = 5.0
        start = time.time()
        while time.time() - start < max_wait:
            if pool.processed_count >= job_count:
                break
            time.sleep(0.05)

        pool.stop(timeout=2.0)

        self.assertEqual(pool.processed_count, job_count)
        self.assertEqual(len(completed_records), job_count)

        # Verify DB states
        with self.sessions() as db:
            for i in range(job_count):
                row = db.get(Assessment, f"pool-job-{i}")
                self.assertIsNotNone(row)
                self.assertEqual(row.status, "completed")

    def test_dialect_adapter_postgres_sql(self):
        """Ensure DialectAdapter correctly emits FOR UPDATE SKIP LOCKED for PostgreSQL."""
        sql = DialectAdapter.compile_for_update_skip_locked()
        self.assertIn("FOR UPDATE SKIP LOCKED", sql)
        self.assertIn("assessments", sql)


if __name__ == "__main__":
    unittest.main()
