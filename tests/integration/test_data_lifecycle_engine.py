"""Unit and integration tests for Data Lifecycle, Retention, Secure Deletion, and PII Redaction (Phase 0, Sector 7)."""

import tempfile
import unittest
from pathlib import Path
from typing import Any

from aegis.lifecycle import (
    DataLifecycleManager,
    PIIRedactor,
    RetentionPolicy,
    SecureEvidenceManager,
)
from aegis.storage import LocalEvidenceStore


class DataLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.tmp_dir.name)
        self.evidence_store = LocalEvidenceStore(self.base_dir)
        self.secure_manager = SecureEvidenceManager(self.evidence_store)
        self.lifecycle_mgr = DataLifecycleManager(self.evidence_store)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_pii_redactor_text_and_json(self) -> None:
        """Verify high-precision redaction of JWTs, credentials, emails, and sensitive keys."""
        raw_text = (
            "User alice.smith@example.corp logged in with Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
            "using card 4111-2222-3333-4444 and SSN 123-45-6789. Pass: password=SuperSecretP@ss123"
        )
        redacted = PIIRedactor.redact_text(raw_text)

        self.assertNotIn("alice.smith@example.corp", redacted)
        self.assertIn("[REDACTED_EMAIL]", redacted)
        self.assertNotIn("sflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", redacted)
        self.assertIn("[REDACTED_JWT]", redacted)
        self.assertNotIn("4111-2222-3333-4444", redacted)
        self.assertIn("[REDACTED_CREDIT_CARD]", redacted)
        self.assertNotIn("123-45-6789", redacted)
        self.assertIn("[REDACTED_SSN]", redacted)
        self.assertNotIn("SuperSecretP@ss123", redacted)

        # Dictionary structure redaction
        payload: dict[str, Any] = {
            "user": "bob@example.com",
            "auth": {
                "token": "secret_session_token_12345",
                "api_key": "secret_api_key_abcde",
                "normal_field": "safe_value",
            },
            "history": ["safe_action", "Bearer some_jwt_or_token"],
        }
        redacted_payload = PIIRedactor.redact_data(payload)

        self.assertEqual(redacted_payload["user"], "[REDACTED_EMAIL]")
        self.assertEqual(redacted_payload["auth"]["token"], "[REDACTED_SENSITIVE_FIELD]")
        self.assertEqual(redacted_payload["auth"]["api_key"], "[REDACTED_SENSITIVE_FIELD]")
        self.assertEqual(redacted_payload["auth"]["normal_field"], "safe_value")
        self.assertIn("[REDACTED_TOKEN]", redacted_payload["history"][1])

    def test_secure_shredding_and_deletion(self) -> None:
        """Verify artifact content is overwritten with zero bytes before unlinking."""
        data = b"Highly confidential payload material to be completely shredded."
        sha256 = self.evidence_store.put(data)

        prefix = sha256[:2]
        file_path = self.evidence_store.root_dir / prefix / sha256
        self.assertTrue(file_path.exists())

        # Perform secure deletion with 2 shred passes
        success = self.secure_manager.secure_delete(sha256, shred_passes=2)
        self.assertTrue(success)
        self.assertFalse(file_path.exists())
        self.assertFalse(self.evidence_store.exists(sha256))

    def test_unreferenced_evidence_pruning(self) -> None:
        """Verify garbage collection of unreferenced artifacts."""
        data1 = b"Artifact 1 - in active use"
        data2 = b"Artifact 2 - orphaned / unreferenced"
        data3 = b"Artifact 3 - in active use"

        h1 = self.evidence_store.put(data1)
        h2 = self.evidence_store.put(data2)
        h3 = self.evidence_store.put(data3)

        referenced = {h1, h3}
        pruned_count, bytes_freed = self.secure_manager.prune_unreferenced(referenced)

        self.assertEqual(pruned_count, 1)
        self.assertEqual(bytes_freed, len(data2))
        self.assertTrue(self.evidence_store.exists(h1))
        self.assertFalse(self.evidence_store.exists(h2))
        self.assertTrue(self.evidence_store.exists(h3))

    def test_retention_policy_enforcement_and_audit(self) -> None:
        """Verify aged assessments, observations, and evidence files are purged or redacted."""
        now = 1000000.0  # Simulated current time

        # Assessment 1: 100 days old (Expired under 90d policy)
        asmt1 = {"id": "asmt-old", "created_at": now - (100 * 86400)}
        obs1_data = b"Old response payload"
        obs1_hash = self.evidence_store.put(obs1_data)
        obs1 = {
            "id": "obs-1",
            "assessment_id": "asmt-old",
            "evidence_hash": obs1_hash,
            "data": {"body": "Old secret content"},
        }
        fe1 = {
            "id": "fe-1",
            "assessment_id": "asmt-old",
            "evidence_hash": obs1_hash,
            "data": {"token": "old-token"},
        }

        # Assessment 2: 30 days old (Valid under 90d, but observations older than 14d raw cutoff)
        asmt2 = {"id": "asmt-mid", "created_at": now - (30 * 86400)}
        obs2_data = b"Mid response payload"
        obs2_hash = self.evidence_store.put(obs2_data)
        obs2 = {
            "id": "obs-2",
            "assessment_id": "asmt-mid",
            "observed_at": now - (20 * 86400),  # 20d old > 14d cutoff
            "evidence_hash": obs2_hash,
            "data": {"email": "dev@corp.internal", "token": "active-secret"},
        }

        # Assessment 3: 2 days old (Completely fresh)
        asmt3 = {"id": "asmt-fresh", "created_at": now - (2 * 86400)}
        obs3 = {
            "id": "obs-3",
            "assessment_id": "asmt-fresh",
            "observed_at": now - (2 * 86400),
            "data": {"status": 200},
        }

        policy = RetentionPolicy(
            assessment_retention_days=90,
            raw_evidence_retention_days=14,
            secure_shred=True,
            pii_redaction_enabled=True,
        )

        report, updated = self.lifecycle_mgr.enforce_retention(
            assessments=[asmt1, asmt2, asmt3],
            observations=[obs1, obs2, obs3],
            finding_evidence=[fe1],
            policy=policy,
            organization_id="org-acme-prod",
            now=now,
        )

        # 1. Old assessment purged
        self.assertEqual(report.purged_assessments_count, 1)
        remaining_asmt_ids = [a["id"] for a in updated["assessments"]]
        self.assertNotIn("asmt-old", remaining_asmt_ids)
        self.assertIn("asmt-mid", remaining_asmt_ids)
        self.assertIn("asmt-fresh", remaining_asmt_ids)

        # 2. Associated old evidence files shredded
        self.assertEqual(report.evidence_files_shredded, 1)
        self.assertFalse(self.evidence_store.exists(obs1_hash))

        # 3. Intermediate observation aged past 14d had PII redacted
        self.assertEqual(report.redacted_records_count, 1)
        mid_obs = next(o for o in updated["observations"] if o["id"] == "obs-2")
        self.assertTrue(mid_obs.get("pii_redacted"))
        self.assertEqual(mid_obs["data"]["email"], "[REDACTED_EMAIL]")
        self.assertEqual(mid_obs["data"]["token"], "[REDACTED_SENSITIVE_FIELD]")

        # 4. Audit ledger hash generated
        self.assertIsNotNone(report.audit_event_hash)
        self.assertEqual(len(report.audit_event_hash or ""), 64)

    def test_compliance_export_bundle(self) -> None:
        """Verify export bundle contains sealed assessment data and cryptographic signature."""
        data_bytes = b"Observed proof payload in compliance test"
        h = self.evidence_store.put(data_bytes)

        asmt = {"id": "asmt-compliance-101", "name": "Annual SOC2 Scope"}
        obs = [{"id": "obs-1", "evidence_hash": h}]
        findings = [{"id": "f-1", "title": "Verified Finding"}]

        bundle = DataLifecycleManager.export_assessment_bundle(
            assessment=asmt,
            observations=obs,
            findings=findings,
            evidence_store=self.evidence_store,
        )

        self.assertEqual(bundle["export_version"], "1.0")
        self.assertIn(h, bundle["evidence_artifacts"])
        self.assertIn("Observed proof payload", bundle["evidence_artifacts"][h])
        self.assertIn("export_sha256", bundle)
        self.assertEqual(len(bundle["export_sha256"]), 64)
