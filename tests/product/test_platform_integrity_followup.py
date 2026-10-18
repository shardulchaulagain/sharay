"""Malformed adapter output must fail one durable job without stopping the queue."""

import unittest
from unittest.mock import patch

from sqlalchemy import select

from aegis.models import Assessment, Finding, FindingEvidence, Observation
from aegis.worker import run_one
from tests.product import test_finding_verification_gate as verification_fixture


class PlatformIntegrityFollowupTests(unittest.TestCase):
    setUp = verification_fixture.FindingVerificationGateTests.setUp
    finding = verification_fixture.FindingVerificationGateTests.finding

    def queue(self):
        self.counter += 1
        with self.sessions() as db:
            row = Assessment(
                organization_id=self.org_id,
                project_id=self.project_id,
                target_id=self.target_id,
                created_by=self.user_id,
                idempotency_key=f"malformed-assessment-{self.counter}",
                scope_version=1,
                scope_snapshot=self.scope | {"target_url": self.url},
            )
            db.add(row)
            db.flush()
            job_id = row.id
            db.commit()
        return job_id

    def result(self, **overrides):
        return {
            "outcome": "completed",
            "observations": [],
            "findings": [],
            "checks": [{"category": "http_headers", "status": "completed", "url": self.url}],
        } | overrides

    def assert_invalid_result_isolated(self, result):
        bad_id, next_id = self.queue(), self.queue()
        with patch("aegis.worker.scan", side_effect=[result, self.result()]):
            self.assertTrue(run_one(self.sessions))
            with self.sessions() as db:
                failed = db.get(Assessment, bad_id)
                self.assertEqual(failed.status, "failed")
                self.assertIsNotNone(failed.finished_at)
                self.assertTrue(failed.error)
                self.assertTrue(any(item["status"] == "failed" for item in failed.checks))
                self.assertEqual(db.get(Assessment, next_id).status, "queued")
                self.assertIsNone(db.scalar(select(FindingEvidence)))
                self.assertIsNone(db.scalar(select(Finding)))
                self.assertIsNone(db.scalar(select(Observation).where(Observation.assessment_id == bad_id)))
            self.assertTrue(run_one(self.sessions))
        with self.sessions() as db:
            self.assertEqual(db.get(Assessment, next_id).status, "completed")

    def test_malformed_result_envelopes_do_not_crash_worker(self):
        for result in (
            None,
            [],
            {"checks": []},
            self.result(outcome="unexpected"),
            self.result(outcome=[]),
            self.result(outcome={"status": "completed"}),
        ):
            with self.subTest(result=result):
                self.assert_invalid_result_isolated(result)

    def test_malformed_checks_do_not_crash_worker(self):
        for checks in (None, "failed", [None], [{"status": []}]):
            with self.subTest(checks=checks):
                self.assert_invalid_result_isolated(self.result(checks=checks))

    def test_malformed_findings_do_not_persist_partial_evidence(self):
        valid = self.finding(lifecycle_state="REPRODUCED")
        for findings in (None, [None], [valid, {}], [valid, self.finding(fingerprint=[])]):
            with self.subTest(findings=findings):
                self.assert_invalid_result_isolated(
                    self.result(observations=[{"url": self.url, "status": 200}], findings=findings)
                )

    def test_malformed_observations_do_not_crash_worker(self):
        for observations in (None, "evidence", [None], [{"url": self.url}, "evidence"]):
            with self.subTest(observations=observations):
                self.assert_invalid_result_isolated(self.result(observations=observations))

    def test_malformed_persisted_finding_fields_do_not_crash_worker(self):
        for fields in (
            {"severity": {"value": "high"}},
            {"description": None},
            {"remediation": ["patch"]},
            {"affected_url": {"value": self.url}},
        ):
            with self.subTest(fields=fields):
                self.assert_invalid_result_isolated(self.result(findings=[self.finding(**fields)]))

    def test_malformed_check_url_and_error_details_do_not_crash_worker(self):
        for checks in (
            [{"category": "http_headers", "status": "completed", "url": [self.url]}],
            [{"category": "nuclei", "status": "failed", "detail": {"message": "failed"}}],
        ):
            with self.subTest(checks=checks):
                self.assert_invalid_result_isolated(self.result(checks=checks))

    def test_non_json_evidence_is_rejected_before_persistence(self):
        circular = {}
        circular["nested"] = circular
        for value in (float("nan"), float("inf"), {"unexpected"}, object(), circular):
            with self.subTest(value=value):
                self.assert_invalid_result_isolated(self.result(observations=[{"raw": value}]))

    def test_redacted_key_collision_cannot_bypass_shape_validation(self):
        finding = {"\x00fingerprint": [], **self.finding()}
        self.assert_invalid_result_isolated(self.result(findings=[finding]))

    def test_redacted_lifecycle_key_cannot_manufacture_verification(self):
        finding = {"\x00lifecycle_state": "REPRODUCED", **self.finding(lifecycle_state="CANDIDATE")}
        self.assert_invalid_result_isolated(self.result(findings=[finding]))

    def test_redacted_status_key_cannot_override_demotion(self):
        finding = {"\x00status": "confirmed", **self.finding(status="demoted", lifecycle_state="REPRODUCED")}
        self.assert_invalid_result_isolated(self.result(findings=[finding]))

    def test_redacted_nested_exit_code_cannot_manufacture_verification(self):
        finding = self.finding(autopyverifier={"\x00exit_code": 0, "exit_code": 1, "mock_mode": False})
        self.assert_invalid_result_isolated(self.result(findings=[finding]))

    def test_malformed_or_failed_verifier_status_cannot_confirm(self):
        for status in ({}, [], "FAILED", " Error ", "TIMEOUT", "DEMOTED", "FALSE_POSITIVE", "UNVERIFIED"):
            with self.subTest(status=status):
                raw = self.finding(autopyverifier={"exit_code": 0, "mock_mode": False, "status": status})
                job_id = self.queue()
                with patch("aegis.worker.scan", return_value=self.result(findings=[raw])):
                    self.assertTrue(run_one(self.sessions))
                with self.sessions() as db:
                    finding = db.scalar(select(Finding).where(Finding.fingerprint == raw["fingerprint"]))
                    self.assertEqual(finding.status, "suspected")
                    evidence = db.scalar(
                        select(FindingEvidence).where(FindingEvidence.assessment_id == job_id)
                    )
                    self.assertEqual(evidence.data["status"], "suspected")


if __name__ == "__main__":
    unittest.main()
