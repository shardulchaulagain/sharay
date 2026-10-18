"""Canned scanner results must not manufacture confirmed vulnerability evidence."""

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from aegis.models import (
    Assessment,
    AuditEvent,
    Base,
    Finding,
    FindingEvidence,
    FindingHistory,
    Observation,
    Organization,
    Project,
    Target,
    User,
)
from aegis.worker import evidence_hash, run_one
from services.scanner_worker import IsolationError


class FindingVerificationGateTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="verification-gate-")
        self.addCleanup(folder.cleanup)
        engine = create_engine(f"sqlite:///{Path(folder.name) / 'fixture.db'}")
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(engine)
        self.sessions = sessionmaker(engine, expire_on_commit=False)
        self.url = "http://127.0.0.1:8766/"
        now = datetime.now(UTC)
        self.scope = {
            "hosts": ["127.0.0.1"],
            "allowed_origins": [self.url.rstrip("/")],
            "allowed_cidrs": ["127.0.0.1/32"],
            "categories": ["http_headers"],
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "request_rate": 1.0,
        }
        with self.sessions() as db:
            organization = Organization(name="Canned verification fixture")
            db.add(organization)
            db.flush()
            user = User(
                organization_id=organization.id,
                username="verification-fixture",
                password_hash="unused-synthetic-hash",
                role="owner",
            )
            db.add(user)
            db.flush()
            project = Project(organization_id=organization.id, owner_id=user.id, name="Synthetic")
            db.add(project)
            db.flush()
            target = Target(
                organization_id=organization.id,
                project_id=project.id,
                url=self.url,
                scope=self.scope,
                verification_status="operator_authorized",
                authorized_by=user.id,
            )
            db.add(target)
            db.flush()
            self.org_id, self.user_id = organization.id, user.id
            self.project_id, self.target_id = project.id, target.id
            db.commit()
        self.counter = 0
        for context in (
            patch("socket.socket", side_effect=AssertionError("No network in verification fixtures")),
            patch("socket.getaddrinfo", side_effect=AssertionError("No DNS in verification fixtures")),
        ):
            context.start()
            self.addCleanup(context.stop)
        context = patch(
            "services.ai_analysis_worker.autopyverifier.AutoPyVerifier.synthesize_script",
            return_value="# Synthetic fixture; never execute",
        )
        self.synthesize = context.start()
        self.addCleanup(context.stop)
        context = patch(
            "services.ai_analysis_worker.autopyverifier.AutoPyVerifier.execute_in_sandbox",
            return_value={"status": "error"},
        )
        self.execute = context.start()
        self.addCleanup(context.stop)

    def finding(self, **overrides):
        self.counter += 1
        return {
            "fingerprint": f"canned-finding-{self.counter}",
            "title": "Synthetic injection candidate",
            "category": "sqli",
            "severity": "high",
            "confidence": "high",
            "affected_url": self.url,
            "description": "Canned evidence; no target contacted.",
            "remediation": "Use parameterized queries.",
        } | overrides

    def assess(self, findings, checks=None, retest_of=None, scan_error=None):
        self.counter += 1
        with self.sessions() as db:
            job = Assessment(
                organization_id=self.org_id,
                project_id=self.project_id,
                target_id=self.target_id,
                created_by=self.user_id,
                idempotency_key=f"canned-assessment-{self.counter}",
                scope_version=1,
                scope_snapshot=self.scope | {"target_url": self.url},
                retest_of=retest_of,
            )
            db.add(job)
            db.flush()
            job_id = job.id
            db.commit()
        result = {
            "outcome": "completed",
            "observations": [],
            "findings": findings,
            "checks": checks
            if checks is not None
            else [{"category": "http_headers", "status": "completed", "url": self.url}],
        }
        with patch("aegis.worker.scan", return_value=result, side_effect=scan_error):
            self.assertTrue(run_one(self.sessions))
        return job_id

    def assert_saved_status(self, job_id, raw, expected):
        with self.sessions() as db:
            finding = db.scalar(select(Finding).where(Finding.fingerprint == raw["fingerprint"]))
            self.assertIsNotNone(finding)
            if isinstance(expected, set):
                self.assertIn(finding.status, expected)
            else:
                self.assertEqual(finding.status, expected)
            snapshot = db.scalar(
                select(FindingEvidence).where(
                    FindingEvidence.finding_id == finding.id,
                    FindingEvidence.assessment_id == job_id,
                )
            )
            self.assertIsNotNone(snapshot)
            self.assertEqual(snapshot.data["status"], finding.status)
            self.assertEqual(snapshot.evidence_hash, evidence_hash(snapshot.data))
            history = db.scalars(
                select(FindingHistory).where(
                    FindingHistory.finding_id == finding.id,
                    FindingHistory.reason.contains(job_id),
                )
            ).all()
            self.assertEqual([item.status for item in history], [finding.status])
            return snapshot.data

    def test_unverified_findings_and_poc_text_are_suspected(self):
        cases = [{}, {"status": "confirmed"}, {"poc": "curl http://127.0.0.1:8766/"}]
        cases += [{"lifecycle_state": state} for state in ("CANDIDATE", "OBSERVED")]
        findings = [self.finding(**case) for case in cases]
        job_id = self.assess(findings)
        for raw in findings:
            with self.subTest(raw=raw):
                snapshot = self.assert_saved_status(job_id, raw, "suspected")
                self.assertNotEqual(snapshot.get("lifecycle_state"), "REPRODUCED")

    def test_only_explicit_real_verification_confirms(self):
        cases = [
            ({"lifecycle_state": "REPRODUCED"}, "confirmed"),
            ({"autopyverifier": {"exit_code": 0, "mock_mode": False}}, "confirmed"),
            ({"autopyverifier": {"exit_code": 0, "mock_mode": True}}, "suspected"),
            ({"autopyverifier": {"exit_code": 0}}, "suspected"),
            ({"autopyverifier": {"mock_mode": False}}, "suspected"),
            ({"autopyverifier": {"exit_code": 1, "mock_mode": False}}, "suspected"),
            ({"autopyverifier": {"exit_code": False, "mock_mode": False}}, "suspected"),
            ({"autopyverifier": {"exit_code": "0", "mock_mode": False}}, "suspected"),
            ({"autopyverifier": {"exit_code": 0.0, "mock_mode": False}}, "suspected"),
        ]
        cases += [
            ({"autopyverifier": {"exit_code": 0, "mock_mode": False, "status": status}}, "suspected")
            for status in ("failed", "error", "timeout")
        ]
        findings = [self.finding(**case) for case, _ in cases]
        job_id = self.assess(findings)
        for raw, (_, expected) in zip(findings, cases):
            with self.subTest(proof=raw):
                self.assert_saved_status(job_id, raw, expected)
        with self.sessions() as db:
            proofs = [
                row.data
                for row in db.scalars(select(Observation).where(Observation.assessment_id == job_id))
                if row.data.get("kind") == "autopyverifier_execution"
            ]
            self.assertEqual(len(proofs), 1)
            self.assertEqual(proofs[0]["verified_count"], 1)
            self.assertEqual(proofs[0]["scripts"][0]["fingerprint"], findings[1]["fingerprint"])

    def test_demotion_overrides_reproduced_and_successful_verifier(self):
        proof = {"lifecycle_state": "REPRODUCED", "autopyverifier": {"exit_code": 0, "mock_mode": False}}
        findings = [
            self.finding(**(proof | {"lifecycle_state": "DEMOTED"})),
            self.finding(**(proof | {"status": "demoted"})),
            self.finding(**(proof | {"status": "false_positive"})),
        ]
        job_id = self.assess(findings)
        for raw in findings:
            with self.subTest(raw=raw):
                self.assert_saved_status(job_id, raw, {"demoted", "false_positive"})

    def test_existing_confirmed_is_demoted_and_fixed_reopens_only_with_proof(self):
        cases = [
            ("confirmed", {"lifecycle_state": "DEMOTED"}, {"demoted", "false_positive"}),
            ("fixed", {}, "suspected"),
            ("fixed", {"lifecycle_state": "REPRODUCED"}, "reopened"),
            ("false_positive", {}, "false_positive"),
            ("accepted_risk", {"lifecycle_state": "REPRODUCED"}, "accepted_risk"),
        ]
        findings = []
        with self.sessions() as db:
            for previous, proof, _ in cases:
                raw = self.finding(**proof)
                findings.append(raw)
                db.add(
                    Finding(
                        organization_id=self.org_id,
                        project_id=self.project_id,
                        target_id=self.target_id,
                        status=previous,
                        **{key: value for key, value in raw.items() if key != "lifecycle_state"},
                    )
                )
            db.commit()
        job_id = self.assess(findings)
        for raw, (previous, _, expected) in zip(findings, cases):
            with self.subTest(previous=previous, proof=raw):
                self.assert_saved_status(job_id, raw, expected)

    def test_ingestion_does_not_run_or_count_mock_verification(self):
        job_id = self.assess([self.finding(poc={"parameter": "id"})])
        self.synthesize.assert_not_called()
        self.execute.assert_not_called()
        with self.sessions() as db:
            checks = db.get(Assessment, job_id).checks
            verifier_checks = [item for item in checks if item["category"] == "autopyverifier"]
            self.assertEqual([item["status"] for item in verifier_checks], ["skipped"])
            observations = db.scalars(select(Observation).where(Observation.assessment_id == job_id))
            for observation in observations:
                self.assertNotEqual(observation.data.get("kind"), "autopyverifier_execution")
                self.assertFalse(observation.data.get("verified_count", 0))

    def test_failed_checks_override_completed_adapter_outcome(self):
        failure = {"category": "nuclei", "status": "failed", "detail": "Synthetic tool exit code 2"}
        cases = [
            ([failure], "failed"),
            ([{"category": "http_headers", "status": "completed"}, failure], "completed_with_errors"),
            ([failure | {"status": "completed", "exit_code": 2}], "failed"),
            ([failure | {"status": "completed", "returncode": 2}], "failed"),
            ([failure | {"status": "completed", "exit_code": 0, "returncode": 2}], "failed"),
        ]
        for checks, expected in cases:
            with self.subTest(checks=checks):
                job_id = self.assess([], checks=checks)
                with self.sessions() as db:
                    assessment = db.get(Assessment, job_id)
                    self.assertEqual(assessment.status, expected)
                    self.assertIn("Synthetic tool exit code 2", assessment.error)
                    failed_check = next(item for item in assessment.checks if item["category"] == "nuclei")
                    self.assertEqual(failed_check["status"], "failed")

    def test_clean_header_retest_does_not_resolve_sql_injection(self):
        raw = self.finding(lifecycle_state="REPRODUCED")
        baseline_id = self.assess([raw])
        self.assert_saved_status(baseline_id, raw, "confirmed")
        retest_id = self.assess([], retest_of=baseline_id)
        with self.sessions() as db:
            self.assertEqual(db.get(Assessment, retest_id).status, "completed")
            finding = db.scalar(select(Finding).where(Finding.fingerprint == raw["fingerprint"]))
            self.assertEqual(finding.status, "confirmed")
            self.assertIsNone(
                db.scalar(select(FindingEvidence).where(FindingEvidence.assessment_id == retest_id))
            )

    def test_configuration_and_isolation_errors_retain_sanitized_details(self):
        for exception_type in (ValueError, IsolationError):
            with self.subTest(exception_type=exception_type.__name__):
                message = "Scanner configuration invalid; password=fixture-sensitive-password"
                expected = "Scanner configuration invalid; password=[REDACTED]"
                job_id = self.assess([], scan_error=exception_type(message))
                with self.sessions() as db:
                    assessment = db.get(Assessment, job_id)
                    self.assertEqual(assessment.status, "failed")
                    self.assertEqual(assessment.error, expected)
                    self.assertEqual(assessment.checks[0]["status"], "failed")
                    self.assertEqual(assessment.checks[0]["error_class"], exception_type.__name__)
                    self.assertEqual(assessment.checks[0]["detail"], expected)
                    event = db.scalar(
                        select(AuditEvent).where(
                            AuditEvent.resource_id == job_id,
                            AuditEvent.action == "assessment.failed",
                        )
                    )
                    self.assertEqual(event.detail["checks"][0]["detail"], expected)
                    self.assertNotIn("fixture-sensitive-password", str(event.detail))


if __name__ == "__main__":
    unittest.main()
