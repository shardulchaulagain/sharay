"""Investigation graphs use proof from the selected assessment; readiness is configuration based."""

import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from sqlalchemy import select

from aegis.api import COOKIE, create_app
from aegis.auth import digest
from aegis.config import Settings
from aegis.models import (
    Assessment,
    AuditEvent,
    Finding,
    FindingEvidence,
    Observation,
    Organization,
    Project,
    SessionRecord,
    Target,
    User,
)
from aegis.worker import evidence_hash
from services.ai_analysis_worker.providers import ProviderConfig


class AIAssessmentIntegrityTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="ai-integrity-")
        self.addCleanup(folder.cleanup)
        self.settings = Settings(Path(folder.name), start_worker=False)
        self.app = create_app(self.settings)
        self.addCleanup(self.app.state.engine.dispose)
        self.client = TestClient(self.app, base_url=self.settings.origin)
        self.addCleanup(self.client.close)
        self.client.headers.update({"origin": self.settings.origin, "x-csrf-token": "fixture-csrf"})
        self.client.cookies.set(COOKIE, "fixture-ai-token")
        self.url = "http://127.0.0.1:8766/api"
        with self.app.state.sessions() as db:
            organization = Organization(name="AI integrity fixture")
            db.add(organization)
            db.flush()
            user = User(
                organization_id=organization.id,
                username="ai-fixture-owner",
                password_hash="unused-synthetic-hash",
                role="owner",
            )
            db.add(user)
            db.flush()
            db.add(
                SessionRecord(
                    token_hash=digest("fixture-ai-token"),
                    user_id=user.id,
                    csrf="fixture-csrf",
                    expires_at=time.time() + 600,
                )
            )
            project = Project(organization_id=organization.id, owner_id=user.id, name="Fixture")
            db.add(project)
            db.flush()
            target = Target(organization_id=organization.id, project_id=project.id, url=self.url, scope={})
            db.add(target)
            db.flush()
            self.org_id, self.user_id = organization.id, user.id
            self.project_id, self.target_id = project.id, target.id
            self.assessments = []
            for key in ("baseline", "selected"):
                row = Assessment(
                    organization_id=self.org_id,
                    project_id=self.project_id,
                    target_id=self.target_id,
                    created_by=self.user_id,
                    idempotency_key=key,
                    scope_version=1,
                    scope_snapshot={"target_url": self.url},
                    status="completed",
                )
                db.add(row)
                db.flush()
                self.assessments.append(row.id)
                data = {"kind": "crawler_summary", "endpoints": ["/api"], "parameters": ["id"]}
                db.add(
                    Observation(
                        organization_id=self.org_id,
                        assessment_id=row.id,
                        data=data,
                        evidence_hash=evidence_hash(data),
                    )
                )
            db.commit()
        self.counter = 0
        for context in (
            patch(
                "services.ai_analysis_worker.providers.config_from_environment", return_value=ProviderConfig()
            ),
            patch(
                "socket.create_connection",
                side_effect=AssertionError("No model/network calls in AI fixtures"),
            ),
            patch("socket.getaddrinfo", side_effect=AssertionError("No DNS in AI fixtures")),
        ):
            context.start()
            self.addCleanup(context.stop)

    def add_finding(self, assessment_id, status="confirmed", current_status=None, **proof):
        self.counter += 1
        data = {
            "fingerprint": f"finding-{self.counter}",
            "title": f"Synthetic finding {self.counter}",
            "category": "injection",
            "severity": "critical",
            "confidence": "high",
            "status": status,
            "description": "Synthetic finding; no target contacted.",
            "remediation": "Use parameters.",
            "affected_url": self.url,
            **proof,
        }
        with self.app.state.sessions() as db:
            row = Finding(
                organization_id=self.org_id,
                project_id=self.project_id,
                target_id=self.target_id,
                **{key: value for key, value in data.items() if key not in proof},
            )
            row.status = current_status or status
            db.add(row)
            db.flush()
            db.add(
                FindingEvidence(
                    finding_id=row.id,
                    assessment_id=assessment_id,
                    data=data,
                    evidence_hash=evidence_hash(data),
                )
            )
            db.commit()
        return data["fingerprint"]

    def investigate(self, method, assessment_id):
        url = f"/api/v1/ai/{'investigations' if method == 'get' else 'investigate'}/{assessment_id}"
        response = getattr(self.client, method)(url)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_empty_selected_assessment_does_not_import_other_assessment_findings(self):
        self.add_finding(self.assessments[0], lifecycle_state="REPRODUCED")
        for method in ("get", "post"):
            with self.subTest(method=method):
                data = self.investigate(method, self.assessments[1])
                self.assertEqual(data["total_findings"], 0)
                self.assertEqual(data["excluded_unverified_findings"], 0)
                self.assertFalse(any(node["kind"] == "vulnerability" for node in data["graph"]["nodes"]))
                self.assertEqual(data["attack_paths"], [])

    def test_only_selected_verified_snapshots_enter_graph_and_analysis(self):
        selected = self.assessments[1]
        valid = {
            self.add_finding(selected, current_status="suspected", lifecycle_state="REPRODUCED"),
            self.add_finding(selected, autopyverifier={"exit_code": 0, "mock_mode": False}),
        }
        self.add_finding(self.assessments[0], lifecycle_state="REPRODUCED")
        for status, proof in (
            ("suspected", {}),
            ("demoted", {"lifecycle_state": "REPRODUCED"}),
            ("confirmed", {}),
            ("confirmed", {"lifecycle_state": "DEMOTED"}),
            ("confirmed", {"autopyverifier": {"exit_code": False, "mock_mode": False}}),
            ("confirmed", {"autopyverifier": {"exit_code": 0, "mock_mode": True}}),
            ("confirmed", {"autopyverifier": {"exit_code": 0, "mock_mode": False, "status": "FAILED"}}),
        ):
            self.add_finding(selected, status=status, **proof)
        for method in ("get", "post"):
            with self.subTest(method=method):
                data = self.investigate(method, selected)
                ids = {
                    node["id"].removeprefix("finding:")
                    for node in data["graph"]["nodes"]
                    if node["kind"] == "vulnerability"
                }
                self.assertEqual(ids, valid)
                self.assertEqual(data["total_findings"], 2)
                self.assertEqual(data["excluded_unverified_findings"], 7)
                self.assertEqual(len(data["attack_paths"]), 2)

    def test_malformed_snapshot_status_cannot_crash_or_confirm(self):
        self.add_finding(
            self.assessments[1],
            status=["confirmed"],
            current_status="confirmed",
            lifecycle_state="REPRODUCED",
        )
        for method in ("get", "post"):
            with self.subTest(method=method):
                self.assertEqual(self.investigate(method, self.assessments[1])["total_findings"], 0)

    def test_historical_investigation_uses_its_snapshot_after_later_demotion(self):
        fingerprint = self.add_finding(
            self.assessments[0], current_status="demoted", lifecycle_state="REPRODUCED"
        )
        with self.app.state.sessions() as db:
            row = db.scalar(select(Finding).where(Finding.fingerprint == fingerprint))
            data = {
                "status": "demoted",
                "lifecycle_state": "DEMOTED",
                "title": "Later rejected finding",
                "category": "injection",
                "severity": "critical",
                "affected_url": self.url,
            }
            db.add(
                FindingEvidence(
                    finding_id=row.id,
                    assessment_id=self.assessments[1],
                    data=data,
                    evidence_hash=evidence_hash(data),
                )
            )
            db.commit()
        for method in ("get", "post"):
            with self.subTest(method=method):
                historical = self.investigate(method, self.assessments[0])
                nodes = [node for node in historical["graph"]["nodes"] if node["kind"] == "vulnerability"]
                self.assertEqual([node["id"] for node in nodes], [f"finding:{fingerprint}"])
                self.assertIn("Synthetic finding", nodes[0]["label"])
                self.assertEqual(self.investigate(method, self.assessments[1])["total_findings"], 0)

    def test_other_organization_cannot_investigate_selected_assessment(self):
        with self.app.state.sessions() as db:
            organization = Organization(name="Other AI fixture")
            db.add(organization)
            db.flush()
            user = User(
                organization_id=organization.id,
                username="other-ai-fixture",
                role="owner",
                password_hash="unused-synthetic-hash",
            )
            db.add(user)
            db.flush()
            db.add(
                SessionRecord(
                    token_hash=digest("other-ai-token"),
                    user_id=user.id,
                    csrf="fixture-csrf",
                    expires_at=time.time() + 600,
                )
            )
            db.commit()
        self.client.cookies.set(COOKIE, "other-ai-token")
        for method, endpoint in (("get", "investigations"), ("post", "investigate")):
            with self.subTest(method=method):
                response = getattr(self.client, method)(f"/api/v1/ai/{endpoint}/{self.assessments[1]}")
                self.assertEqual(response.status_code, 404)

    def test_provider_request_failure_reports_deterministic_fallback(self):
        config = ProviderConfig(
            provider="fixture",
            model="fixture-model",
            api_key_env="FIXTURE_AI_KEY",
            share_assessment_data=True,
        )
        provider = SimpleNamespace(
            name="fixture", propose=Mock(side_effect=RuntimeError("fixture-sensitive-error"))
        )
        with (
            patch.dict("services.ai_analysis_worker.providers.REGISTRY", {"fixture": lambda _cfg: provider}),
            patch.dict(os.environ, {"FIXTURE_AI_KEY": "valid-fixture-credential"}, clear=True),
            patch("services.ai_analysis_worker.providers.config_from_environment", return_value=config),
        ):
            data = self.investigate("post", self.assessments[1])
        provider.propose.assert_called_once()
        self.assertEqual(data["provider_status"], "failed")
        self.assertNotIn("fixture-sensitive-error", str(data))
        with self.app.state.sessions() as db:
            event = db.scalar(select(AuditEvent).where(AuditEvent.action == "ai.investigation_executed"))
            self.assertEqual(event.detail["provider"], "deterministic_engine")
            self.assertEqual(event.detail["provider_status"], "failed")

    def test_successful_provider_enriches_summary_without_confirming_candidate(self):
        self.add_finding(self.assessments[1], status="suspected")
        config = ProviderConfig(
            provider="fixture",
            model="fixture-model",
            api_key_env="FIXTURE_AI_KEY",
            share_assessment_data=True,
        )
        provider = SimpleNamespace(name="fixture", propose=Mock(return_value=b"Synthetic model summary."))
        with (
            patch.dict("services.ai_analysis_worker.providers.REGISTRY", {"fixture": lambda _cfg: provider}),
            patch.dict(os.environ, {"FIXTURE_AI_KEY": "valid-fixture-credential"}, clear=True),
            patch("services.ai_analysis_worker.providers.config_from_environment", return_value=config),
        ):
            data = self.investigate("post", self.assessments[1])
        self.assertEqual(data["ai_executive_summary"], "Synthetic model summary.")
        self.assertEqual(data["provider_status"], "ready")
        self.assertEqual(data["total_findings"], 0)
        self.assertEqual(data["excluded_unverified_findings"], 1)
        self.assertEqual(data["attack_paths"], [])
        provider.propose.assert_called_once()

    def test_configuration_exception_never_fabricates_ready_or_exposes_error(self):
        with patch(
            "services.ai_analysis_worker.providers.config_from_environment",
            side_effect=ValueError("fixture-sensitive-error"),
        ):
            status = self.client.get("/api/v1/ai/status").json()
            self.assertNotEqual(status["status"], "ready")
            self.assertEqual(status["active_provider"], "none")
            self.assertFalse(status["share_assessment_data"])
            self.assertNotIn("fixture-sensitive-error", str(status))
            analysis = self.investigate("post", self.assessments[1])
            self.assertEqual(analysis["provider_status"], "unavailable")
            self.assertTrue(analysis["provider_reason"])
        with self.app.state.sessions() as db:
            event = db.scalar(select(AuditEvent).where(AuditEvent.action == "ai.investigation_executed"))
            self.assertEqual(event.detail["provider"], "deterministic_engine")
            self.assertEqual(event.detail["provider_status"], "unavailable")

    def test_ready_requires_usable_credential_sharing_and_installed_provider(self):
        config = ProviderConfig(
            provider="fixture",
            model="fixture-model",
            api_key_env="FIXTURE_AI_KEY",
            share_assessment_data=True,
        )
        provider = SimpleNamespace(name="fixture", propose=Mock(side_effect=AssertionError("No model call")))
        with patch.dict("services.ai_analysis_worker.providers.REGISTRY", {"fixture": lambda _cfg: provider}):
            for credential in ("", " ", "line\nbreak", "valid-fixture-credential"):
                for sharing in (False, True):
                    cfg = config.model_copy(update={"share_assessment_data": sharing})
                    with (
                        self.subTest(credential=credential, sharing=sharing),
                        patch.dict(os.environ, {"FIXTURE_AI_KEY": credential}, clear=True),
                        patch(
                            "services.ai_analysis_worker.providers.config_from_environment", return_value=cfg
                        ),
                    ):
                        status = self.client.get("/api/v1/ai/status").json()
                        self.assertEqual(
                            status["status"] == "ready", credential == "valid-fixture-credential" and sharing
                        )
            with (
                patch.dict(os.environ, {"FIXTURE_AI_KEY": "valid-fixture-credential"}, clear=True),
                patch(
                    "services.ai_analysis_worker.providers.config_from_environment",
                    return_value=config.model_copy(update={"provider": "missing"}),
                ),
            ):
                self.assertNotEqual(self.client.get("/api/v1/ai/status").json()["status"], "ready")
        provider.propose.assert_not_called()


if __name__ == "__main__":
    unittest.main()
