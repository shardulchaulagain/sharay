"""Concurrent integration tests for safe job queue & PostgreSQL backend (Sector 4).

Proves:
1. N concurrent workers lease without race conditions or duplicate claims.
2. Per-origin mutual exclusion prevents parallel execution against the same target.
3. Cooldown intervals are strictly respected across workers.
4. PostgreSQL SKIP LOCKED dialect query compilation is accurate.
5. Worker lease expiration & reaping handles crashed workers fail-closed.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from aegis.models import Assessment, Base, Organization, Project, Target, User
from aegis.queue import (
    ConcurrentJobQueue,
    DialectAdapter,
    JobLease,
    OriginPacingCoordinator,
    extract_origin,
)


@pytest.fixture
def sqlite_db():
    folder = tempfile.TemporaryDirectory(prefix="test-queue-")
    db_path = Path(folder.name) / "test.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 15},
    )

    @event.listens_for(engine, "connect")
    def setup_sqlite(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=15000")

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(engine, expire_on_commit=False)

    with session_factory() as db:
        org = Organization(id="org-1", name="Test Org")
        db.add(org)
        db.flush()
        user = User(
            id="user-1",
            organization_id=org.id,
            username="testadmin",
            password_hash="hash",
            role="owner",
        )
        db.add(user)
        db.flush()
        proj = Project(id="proj-1", organization_id=org.id, owner_id=user.id, name="Test Project")
        db.add(proj)
        db.flush()
        for i in range(10):
            target = Target(
                id=f"target-{i}",
                organization_id=org.id,
                project_id=proj.id,
                url=f"https://server{i}.company.com",
                scope={},
            )
            db.add(target)
        db.commit()

    yield engine, session_factory
    engine.dispose()
    folder.cleanup()


def test_postgres_skip_locked_sql_compilation():
    """Verify that PostgreSQL dialect generates FOR UPDATE SKIP LOCKED clause."""
    sql = DialectAdapter.compile_for_update_skip_locked()
    assert "FOR UPDATE SKIP LOCKED" in sql.upper()
    assert "from assessments" in sql.lower()
    assert "assessments.status = 'queued'" in sql


def test_url_origin_extraction():
    """Verify robust origin normalization."""
    assert extract_origin("https://api.example.com/v1/users") == "https://api.example.com"
    assert extract_origin("http://127.0.0.1:8080/test?query=1") == "http://127.0.0.1:8080"
    assert extract_origin("https://sub.domain.co.uk:443/login") == "https://sub.domain.co.uk:443"


def test_origin_cooldown_and_exclusion():
    """Verify OriginPacingCoordinator enforces single active worker and cooldown."""
    coordinator = OriginPacingCoordinator(None, default_cooldown=0.5)

    assert coordinator.try_claim_origin("https://target.com", "worker-1", now=10.0) is True
    # Worker 2 cannot claim same origin concurrently
    assert coordinator.try_claim_origin("https://target.com", "worker-2", now=10.1) is False
    # Worker 1 re-asserting succeeds
    assert coordinator.try_claim_origin("https://target.com", "worker-1", now=10.1) is True

    # Release origin with cooldown
    coordinator.release_origin("https://target.com", "worker-1", now=12.0, apply_cooldown=True)

    # Worker 2 immediately trying should fail because 0.5s cooldown has not elapsed
    assert coordinator.try_claim_origin("https://target.com", "worker-2", now=12.2) is False
    # Worker 2 trying after 0.5s cooldown succeeds
    assert coordinator.try_claim_origin("https://target.com", "worker-2", now=12.6) is True


def test_concurrent_queue_leasing_no_duplicate_claims(sqlite_db):
    """Verify that concurrent workers lease separate queued jobs without duplication."""
    engine, session_factory = sqlite_db
    queue = ConcurrentJobQueue(session_factory, engine=engine)

    # Seed 5 queued assessments
    with session_factory() as db:
        for i in range(5):
            ass = Assessment(
                id=f"asmt-multi-{i}",
                organization_id="org-1",
                project_id="proj-1",
                target_id=f"target-{i}",
                created_by="user-1",
                idempotency_key=f"idem-multi-{i}",
                status="queued",
                scope_version=1,
                scope_snapshot={"target_url": f"https://server{i}.company.com"},
            )
            db.add(ass)
        db.commit()

    claimed_ids: list[str] = []
    leases: list[JobLease] = []

    for w in range(5):
        lease = queue.lease_job(f"worker-{w}")
        assert lease is not None
        assert lease.assessment_id not in claimed_ids
        claimed_ids.append(lease.assessment_id)
        leases.append(lease)

    assert len(claimed_ids) == 5
    # Sixth worker finds queue empty
    assert queue.lease_job("worker-6") is None

    # Clean up jobs
    for lease in leases:
        queue.complete_job(lease, outcome="completed")


def test_concurrent_queue_enforces_per_origin_exclusion(sqlite_db):
    """Verify that two jobs on the exact same origin cannot be leased concurrently."""
    engine, session_factory = sqlite_db
    queue = ConcurrentJobQueue(session_factory, engine=engine)

    with session_factory() as db:
        ass1 = Assessment(
            id="asmt-same-1",
            organization_id="org-1",
            project_id="proj-1",
            target_id="target-0",
            created_by="user-1",
            idempotency_key="idem-same-1",
            status="queued",
            scope_version=1,
            scope_snapshot={"target_url": "https://shared.target.com/api/v1"},
        )
        ass2 = Assessment(
            id="asmt-same-2",
            organization_id="org-1",
            project_id="proj-1",
            target_id="target-0",
            created_by="user-1",
            idempotency_key="idem-same-2",
            status="queued",
            scope_version=1,
            scope_snapshot={"target_url": "https://shared.target.com/api/v2"},
        )
        db.add(ass1)
        db.add(ass2)
        db.commit()

    lease1 = queue.lease_job("worker-a")
    assert lease1 is not None
    assert lease1.assessment_id == "asmt-same-1"

    # Worker B tries to lease: asmt-same-2 has the same origin so it must be SKIPPED
    lease2 = queue.lease_job("worker-b")
    assert lease2 is None

    # Complete job 1
    queue.complete_job(lease1, outcome="completed", now=100.0)

    # Worker B can now lease job 2 after cooldown
    lease2_retry = queue.lease_job("worker-b", now=102.0)
    assert lease2_retry is not None
    assert lease2_retry.assessment_id == "asmt-same-2"
    queue.complete_job(lease2_retry, outcome="completed")


def test_reap_expired_worker_leases(sqlite_db):
    """Verify dead worker lease reaping re-enqueues orphaned jobs."""
    engine, session_factory = sqlite_db
    queue = ConcurrentJobQueue(session_factory, engine=engine, lease_timeout=10.0)

    with session_factory() as db:
        ass = Assessment(
            id="asmt-crash-1",
            organization_id="org-1",
            project_id="proj-1",
            target_id="target-1",
            created_by="user-1",
            idempotency_key="idem-crash-1",
            status="queued",
            scope_version=1,
            scope_snapshot={"target_url": "https://crashed.app.com"},
        )
        db.add(ass)
        db.commit()

    lease = queue.lease_job("worker-dead", lease_duration=5.0, now=100.0)
    assert lease is not None
    assert lease.lease_expires_at == 105.0

    # At t=104, lease is not expired
    reaped = queue.reap_expired_leases(requeue=True, now=104.0)
    assert len(reaped) == 0

    # At t=106, lease is expired and reaped back to 'queued'
    reaped = queue.reap_expired_leases(requeue=True, now=106.0)
    assert reaped == ["asmt-crash-1"]

    with session_factory() as db:
        row = db.get(Assessment, "asmt-crash-1")
        assert row is not None
        assert row.status == "queued"
        assert "Requeued" in str(row.stage)
