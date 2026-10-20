"""Product API tests for 3D Topology, Virtualized Tables, Bulk Triage, and Saved Views (Sector 9)."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.auth import provision_owner
from aegis.config import Settings
from aegis.models import Assessment, Finding

PASSWORD = "Synthetic-test-password-761!"


class TestVisualizationApi(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.settings = Settings(Path(self.folder.name), start_worker=False)
        self.app = create_app(self.settings)
        self.sessions = self.app.state.sessions

        with self.sessions() as db:
            self.owner = provision_owner(db, "testowner", PASSWORD)
            self.org_id = self.owner.organization_id
            db.commit()

        self.client = TestClient(self.app, base_url=self.settings.origin)
        self.client.headers["origin"] = self.settings.origin

        # Sign in as owner
        res = self.client.post("/api/v1/auth/login", json={"username": "testowner", "password": PASSWORD})
        self.assertEqual(res.status_code, 200)
        self.client.headers["x-csrf-token"] = res.json()["csrf_token"]

        # Create project
        proj = self.client.post(
            "/api/v1/projects", json={"name": "Vis Project", "description": "Visualization"}
        )
        self.assertEqual(proj.status_code, 201)
        self.project_id = proj.json()["id"]

        now = datetime.now(timezone.utc)
        scope = {
            "hosts": ["example.com"],
            "allowed_origins": ["https://example.com"],
            "allowed_paths": ["/"],
            "excluded_paths": ["/excluded"],
            "allowed_cidrs": ["93.184.216.34/32"],
            "categories": ["http_headers", "tls", "dns"],
            "request_rate": 5.0,
            "max_concurrency": 1,
            "authenticated": False,
            "credential_refs": [],
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "intrusive": False,
            "approval_required": True,
            "emergency_stop_conditions": ["operator_cancel", "scope_expired", "policy_violation"],
        }

        # Create target
        t_res = self.client.post(
            f"/api/v1/projects/{self.project_id}/targets",
            json={"url": "https://example.com/", "scope": scope},
        )
        self.assertEqual(t_res.status_code, 201)
        target_data = t_res.json()
        self.target_id = target_data["id"]

        # Approve target
        appr = self.client.post(
            f"/api/v1/targets/{self.target_id}/approve",
            json={
                "acknowledgement": "I authorize this target within the displayed scope",
                "expected_scope_version": target_data["scope_version"],
            },
        )
        self.assertEqual(appr.status_code, 200)

        # Populate sample assessment and findings in DB
        with self.sessions() as db:
            self.assessment = Assessment(
                organization_id=self.org_id,
                project_id=self.project_id,
                target_id=self.target_id,
                created_by=self.owner.id,
                idempotency_key="vis-key-001",
                scope_snapshot=scope,
                scope_version=1,
                status="completed",
            )
            db.add(self.assessment)
            db.flush()

            self.f1 = Finding(
                organization_id=self.org_id,
                project_id=self.project_id,
                target_id=self.target_id,
                fingerprint="fp-sqli-vis-01",
                title="SQL Injection in /api/items",
                category="sqli",
                severity="CRITICAL",
                confidence="confirmed",
                status="needs_triage",
                description="SQL injection vulnerability in query parameter",
                remediation="Use parameterized queries",
                affected_url="https://example.com/api/items",
            )
            self.f2 = Finding(
                organization_id=self.org_id,
                project_id=self.project_id,
                target_id=self.target_id,
                fingerprint="fp-hsts-vis-02",
                title="Missing Strict-Transport-Security",
                category="headers",
                severity="LOW",
                confidence="confirmed",
                status="needs_triage",
                description="HSTS header missing",
                remediation="Add Strict-Transport-Security header",
                affected_url="https://example.com/",
            )
            db.add_all([self.f1, self.f2])
            db.commit()
            self.assessment_id = self.assessment.id
            self.f1_id = self.f1.id
            self.f2_id = self.f2.id

    def tearDown(self):
        self.folder.cleanup()

    def test_3d_topology_endpoint(self):
        res = self.client.get(f"/api/v1/assessments/{self.assessment_id}/topology-3d")
        self.assertEqual(res.status_code, 200)
        payload = res.json()
        self.assertIn("nodeCount", payload)
        self.assertIn("edgeCount", payload)
        self.assertGreaterEqual(payload["nodeCount"], 3)  # target + gateway + findings
        self.assertTrue(any(n["type"] == "vulnerability" for n in payload["nodes"]))
        self.assertTrue(any(e["isMinCut"] for e in payload["edges"]))

    def test_virtualized_findings_table_endpoint(self):
        res = self.client.get("/api/v1/findings/virtualized?scroll_top=0&container_height=400&row_height=40")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["start_index"], 0)
        self.assertGreaterEqual(data["total_items"], 2)
        self.assertEqual(len(data["visible_items"]), data["total_items"])

        # Filter by severity
        crit_res = self.client.get("/api/v1/findings/virtualized?severity=CRITICAL")
        self.assertEqual(crit_res.status_code, 200)
        crit_data = crit_res.json()
        self.assertEqual(crit_data["total_items"], 1)
        self.assertEqual(crit_data["visible_items"][0]["title"], "SQL Injection in /api/items")

        # Fuzzy search
        search_res = self.client.get("/api/v1/findings/virtualized?search=strict-transport")
        self.assertEqual(search_res.status_code, 200)
        self.assertEqual(search_res.json()["total_items"], 1)

    def test_bulk_triage_and_saved_views(self):
        # 1. Bulk triage finding to CONFIRMED
        bulk_res = self.client.post(
            "/api/v1/findings/bulk-triage",
            json={
                "finding_ids": [self.f1_id],
                "status": "CONFIRMED",
                "justification": "Verified by senior auditor",
            },
        )
        self.assertEqual(bulk_res.status_code, 200)
        self.assertEqual(bulk_res.json()["updated_count"], 1)

        # 2. Save custom view
        save_res = self.client.post(
            "/api/v1/views/saved",
            json={
                "name": "Critical Triaged",
                "filters": {"severity": "CRITICAL", "status": "CONFIRMED"},
            },
        )
        self.assertEqual(save_res.status_code, 200)

        # 3. Retrieve saved view
        get_res = self.client.get("/api/v1/views/saved/Critical Triaged")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["filters"]["severity"], "CRITICAL")
