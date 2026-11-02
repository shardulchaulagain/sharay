"""Integration tests for Distributed Worker Pool, Quotas & Checkpoint Resumption (Sector 4).

Verifies:
1. Worker registration, capabilities, and monotonic heartbeat tracking.
2. Safe distributed leasing with per-origin mutual exclusion across nodes.
3. Multi-tenant quota enforcement and starvation prevention.
4. Intermediate assessment checkpointing with partial findings and remaining URLs.
5. Crashed worker detection, lease revocation, and seamless failover to new workers.
"""

from __future__ import annotations

from aegis.lifecycle import load_assessment_checkpoint, save_assessment_checkpoint
from aegis.models import Assessment, Base, Organization, Project, Target, User
from services.scanner_worker.pool import (
    DistributedWorkerCoordinator,
    JobState,
    MultiTenantQuotaManager,
    WorkerStatus,
)


def test_worker_registration_and_heartbeat():
    coord = DistributedWorkerCoordinator()
    w1 = coord.register_worker("worker-1", "scanner-host-1", capacity=3, tags=["cloud", "fast"])
    assert w1.node_id == "worker-1"
    assert w1.capacity == 3
    assert w1.status == WorkerStatus.ONLINE

    # Update heartbeat
    assert coord.record_heartbeat("worker-1", now=150.0) is True
    assert coord._workers["worker-1"].last_heartbeat == 150.0

    # Heartbeat for non-existent worker returns False
    assert coord.record_heartbeat("worker-nonexistent") is False


def test_origin_mutual_exclusion_across_workers():
    coord = DistributedWorkerCoordinator()
    coord.register_worker("node-a", "host-a", capacity=2)
    coord.register_worker("node-b", "host-b", capacity=2)

    # Submit two jobs with the same target origin
    coord.submit_job("job-1", target_origin="https://target.corp", org_id="org-1")
    coord.submit_job("job-2", target_origin="https://target.corp", org_id="org-1")

    # Node A leases job-1
    leased_1 = coord.lease_next_job("node-a")
    assert leased_1 is not None
    assert leased_1.assessment_id == "job-1"

    # Node B attempts to lease: job-2 must NOT be leased because origin https://target.corp is actively running!
    leased_2 = coord.lease_next_job("node-b")
    assert leased_2 is None

    # When Node A completes job-1, origin is unlocked and Node B can now lease job-2
    assert coord.complete_job("job-1", "node-a") is True
    leased_2_retry = coord.lease_next_job("node-b")
    assert leased_2_retry is not None
    assert leased_2_retry.assessment_id == "job-2"


def test_multi_tenant_quota_starvation_prevention():
    # Configure Org 1 quota = 1, Org 2 quota = 2
    qm = MultiTenantQuotaManager(default_org_quota=2, org_quotas={"org-1": 1, "org-2": 2})
    coord = DistributedWorkerCoordinator(quota_manager=qm)
    coord.register_worker("big-node", "worker-farm", capacity=5)

    # Enqueue 2 jobs for Org 1 and 1 job for Org 2
    coord.submit_job("org1-job-a", target_origin="https://a.org1.com", org_id="org-1")
    coord.submit_job("org1-job-b", target_origin="https://b.org1.com", org_id="org-1")
    coord.submit_job("org2-job-a", target_origin="https://a.org2.com", org_id="org-2")

    # Lease 1: Org 1 job-a is claimed (hits org-1 quota of 1)
    j1 = coord.lease_next_job("big-node")
    assert j1 is not None
    assert j1.assessment_id == "org1-job-a"

    # Lease 2: Org 1 job-b is skipped because Org 1 is at quota; Org 2 job-a is leased!
    j2 = coord.lease_next_job("big-node")
    assert j2 is not None
    assert j2.assessment_id == "org2-job-a"

    # Org 1 finishes job-a, unblocking job-b
    coord.complete_job("org1-job-a", "big-node")
    j3 = coord.lease_next_job("big-node")
    assert j3 is not None
    assert j3.assessment_id == "org1-job-b"


def test_checkpoint_persistence_and_failover_resumption():
    coord = DistributedWorkerCoordinator(heartbeat_timeout=30.0)
    coord.register_worker("worker-alpha", "node-1", capacity=1, now=100.0)
    coord.register_worker("worker-beta", "node-2", capacity=1, now=100.0)

    coord.submit_job("assessment-999", target_origin="https://critical.app", org_id="tenant-x")

    # Worker Alpha leases job
    job = coord.lease_next_job("worker-alpha", now=100.0)
    assert job is not None
    assert job.assessment_id == "assessment-999"
    assert job.attempt_count == 1

    # Worker Alpha progresses through crawl, reaches 45% and saves progressive checkpoint
    interim = [{"id": "vuln-1", "type": "xss", "url": "https://critical.app/search"}]
    urls_left = ["https://critical.app/admin", "https://critical.app/settings"]
    saved = coord.save_checkpoint(
        assessment_id="assessment-999",
        worker_id="worker-alpha",
        stage_index=2,
        stage_name="active_scanning",
        stage_percent=45.0,
        completed_stages=["passive_recon", "crawl"],
        interim_findings=interim,
        remaining_urls=urls_left,
        now=110.0,
    )
    assert saved is True
    assert job.state == JobState.CHECKPOINTED
    assert job.checkpoint is not None
    assert job.checkpoint.stage_percent == 45.0

    # Worker Alpha crashes (stops sending heartbeats). Time advances past 30s timeout to t=145.0
    reaped = coord.reap_stale_workers(now=145.0)
    assert "assessment-999" in reaped
    assert coord._workers["worker-alpha"].status == WorkerStatus.OFFLINE

    # Worker Beta is alive and ready to claim next job
    coord.record_heartbeat("worker-beta", now=145.0)
    resumed_job = coord.lease_next_job("worker-beta", now=146.0)
    assert resumed_job is not None

    assert resumed_job.assessment_id == "assessment-999"
    assert resumed_job.attempt_count == 2
    # The checkpoint was preserved: Worker Beta resumes without re-crawling!
    assert resumed_job.checkpoint is not None
    assert resumed_job.checkpoint.stage_name == "active_scanning"
    assert resumed_job.checkpoint.stage_percent == 45.0
    assert resumed_job.checkpoint.interim_findings == interim
    assert resumed_job.checkpoint.remaining_urls == urls_left


def test_database_checkpoint_lifecycle_save_and_load():
    """Verify save_assessment_checkpoint and load_assessment_checkpoint in SQLite DB."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)

    org = Organization(id="org-chk", name="Checkpoint Org")
    session.add(org)
    session.flush()
    user = User(id="user-chk", organization_id=org.id, username="admin_chk", password_hash="h", role="owner")
    session.add(user)
    session.flush()
    proj = Project(id="proj-chk", organization_id=org.id, owner_id=user.id, name="Project Chk")
    session.add(proj)
    session.flush()
    target = Target(id="tgt-chk", organization_id=org.id, project_id=proj.id, url="https://chk.com", scope={})
    session.add(target)
    session.flush()

    ass = Assessment(
        id="asmt-chk-1",
        organization_id=org.id,
        project_id=proj.id,
        target_id=target.id,
        created_by=user.id,
        idempotency_key="idem-chk-1",
        status="running",
        stage="active_scan",
        scope_version=1,
        scope_snapshot={"target_url": "https://chk.com"},
        checks=[],
    )
    session.add(ass)
    session.commit()

    # Initially no checkpoint
    assert load_assessment_checkpoint(session, "asmt-chk-1") is None

    # Save checkpoint
    saved = save_assessment_checkpoint(
        session,
        "asmt-chk-1",
        stage_name="vuln_scanner",
        stage_percent=60.0,
        interim_findings=[{"id": "vuln-sqli"}],
        remaining_urls=["https://chk.com/api/v2"],
    )
    assert saved["stage_name"] == "vuln_scanner"
    assert saved["stage_percent"] == 60.0

    # Load checkpoint
    loaded = load_assessment_checkpoint(session, "asmt-chk-1")
    assert loaded is not None
    assert loaded["stage_name"] == "vuln_scanner"
    assert loaded["stage_percent"] == 60.0
    assert loaded["interim_findings"] == [{"id": "vuln-sqli"}]
    assert loaded["remaining_urls"] == ["https://chk.com/api/v2"]
