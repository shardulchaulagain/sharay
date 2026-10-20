"""Integration tests for Sector 6 reporting API endpoints.

Proves:
1. SARIF and CSV export via GET /api/v1/reports/{id}?format=...
2. Hash-sealed evidence bundle download via GET /api/v1/assessments/{id}/bundle
3. Executive dashboard metrics via GET /api/v1/assessments/{id}/executive-dashboard
4. Multi-assessment differential analytics via GET /api/v1/assessments/{id}/trends
5. Ticketing push with deduplication via POST /api/v1/findings/{id}/ticket
"""

import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from aegis.api import COOKIE, create_app
from aegis.auth import digest
from aegis.config import Settings
from aegis.models import (
    Assessment,
    Finding,
    FindingEvidence,
    Organization,
    Project,
    SessionRecord,
    Target,
    User,
)
from packages.reporting.bundle import EvidenceBundleBuilder


class ReportingApiEndpointsTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="report-api-")
        self.addCleanup(folder.cleanup)
        settings = Settings(Path(folder.name), start_worker=False)
        self.app = create_app(settings)
        self.addCleanup(self.app.state.engine.dispose)
        self.client = TestClient(self.app, base_url=settings.origin)
        self.addCleanup(self.client.close)

        token = "fixture-owner-token"
        with self.app.state.sessions() as db:
            org = Organization(name="Sector6Org")
            db.add(org)
            db.flush()
            user = User(
                organization_id=org.id,
                username="sec-lead",
                password_hash="unused",
                role="owner",
            )
            db.add(user)
            db.flush()
            db.add(
                SessionRecord(
                    token_hash=digest(token),
                    user_id=user.id,
                    csrf="read-only-csrf",
                    expires_at=time.time() + 600,
                )
            )
            project = Project(organization_id=org.id, owner_id=user.id, name="Project Alpha")
            db.add(project)
            db.flush()
            target = Target(
                organization_id=org.id,
                project_id=project.id,
                url="http://127.0.0.1:8766/",
                scope={"target_url": "http://127.0.0.1:8766/"},
            )
            db.add(target)
            db.flush()

            # Completed assessment with a confirmed finding
            assessment1 = Assessment(
                organization_id=org.id,
                project_id=project.id,
                target_id=target.id,
                created_by=user.id,
                idempotency_key="assess-1",
                scope_version=1,
                scope_snapshot={"target_url": target.url, "verification_status": "approved_lab"},
                status="completed",
                checks=[],
            )
            db.add(assessment1)
            db.flush()

            finding1 = Finding(
                organization_id=org.id,
                project_id=project.id,
                target_id=target.id,
                fingerprint="fp-sqli-01",
                category="sqli",
                severity="high",
                confidence="high",
                status="confirmed",
                title="SQL Injection in /api/items",
                description="Unsanitized query in items endpoint",
                remediation="Use parameterized queries",
                affected_url="http://127.0.0.1:8766/api/items?id=1",
            )
            db.add(finding1)
            db.flush()

            evidence1 = FindingEvidence(
                finding_id=finding1.id,
                assessment_id=assessment1.id,
                data={"detail": "reflected payload in sql response"},
                evidence_hash="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            )
            db.add(evidence1)
            db.flush()

            self.assessment_id = assessment1.id
            self.finding_id = finding1.id
            self.token = token
            self.origin = settings.origin
            db.commit()

        self.client.cookies.set(COOKIE, token)

    def _headers(self):
        return {
            "X-CSRF-Token": "read-only-csrf",
            "Origin": self.origin,
        }

    def test_sarif_export_endpoint(self):
        res = self.client.get(
            f"/api/v1/reports/{self.assessment_id}?format=sarif",
            headers=self._headers(),
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/sarif+json", res.headers.get("content-type", ""))
        sarif = res.json()
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "SHARAY")
        self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 1)

    def test_csv_export_endpoint(self):
        res = self.client.get(
            f"/api/v1/reports/{self.assessment_id}?format=csv",
            headers=self._headers(),
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/csv", res.headers.get("content-type", ""))
        csv_text = res.text
        self.assertIn("Finding ID,Title,Severity", csv_text)
        self.assertIn("SQL Injection in /api/items", csv_text)

    def test_bundle_download_and_merkle_verification(self):
        res = self.client.get(
            f"/api/v1/assessments/{self.assessment_id}/bundle",
            headers=self._headers(),
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/zip", res.headers.get("content-type", ""))
        valid, msg, manifest = EvidenceBundleBuilder.verify_bundle(res.content)
        self.assertTrue(valid, msg)
        self.assertIsNotNone(manifest)
        self.assertEqual(manifest["assessment_id"], self.assessment_id)

    def test_executive_dashboard_endpoint(self):
        res = self.client.get(
            f"/api/v1/assessments/{self.assessment_id}/executive-dashboard",
            headers=self._headers(),
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("posture_score", data)
        self.assertIn("risk_rating", data)
        self.assertIn("severity_distribution", data)
        self.assertEqual(data["severity_distribution"]["HIGH"], 1)

    def test_assessment_trends_endpoint(self):
        res = self.client.get(
            f"/api/v1/assessments/{self.assessment_id}/trends",
            headers=self._headers(),
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("counts", data)
        self.assertIn("posture_score_current", data)

    def test_ticketing_push_endpoint(self):
        res = self.client.post(
            f"/api/v1/findings/{self.finding_id}/ticket?platform=github",
            headers=self._headers(),
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "CREATED")
        self.assertEqual(data["platform"], "github")

        # Second push deduplicates
        res2 = self.client.post(
            f"/api/v1/findings/{self.finding_id}/ticket?platform=github",
            headers=self._headers(),
        )
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()
        self.assertEqual(data2["status"], "UPDATED")
        self.assertEqual(data2["update_count"], 2)
