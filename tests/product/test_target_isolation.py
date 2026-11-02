"""Verification tests for Per-Target Failure Isolation (Requirement A3)."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from aegis.models import Assessment
from aegis.worker import run_one
from packages.security_policies import PolicyError, ResolutionError, ResolutionErrorCode


class TestTargetIsolation(unittest.TestCase):
    """Asserts that an unresolvable destination emits a structured TARGET_UNRESOLVED observation
    and cleanly sets completed_with_errors without crashing the worker task."""

    def test_target_unresolved_emits_typed_record_and_completed_with_errors(self):
        # Mock database session and assessment
        assessment = Assessment()
        assessment.id = "test-assessment-isolation-001"
        assessment.project_id = "test-project"
        assessment.target_id = "test-target"
        assessment.profile = "approved_templates"
        assessment.status = "queued"
        assessment.cancel_requested = False
        assessment.scope_version = 1
        assessment.scope_snapshot = {
            "target_url": "https://unresolvable-ghost-domain-12345.org",
            "request_rate": 10,
            "max_concurrency": 1,
            "allowed_cidrs": [],
            "allowed_origins": ["https://unresolvable-ghost-domain-12345.org"],
            "hosts": ["unresolvable-ghost-domain-12345.org"],
            "allowed_paths": ["/"],
            "excluded_paths": [],
            "starts_at": "2026-06-01T00:00:00Z",
            "expires_at": "2026-06-01T04:00:00Z",
            "categories": ["http_headers"],
            "emergency_stop_conditions": ["operator_cancel", "scope_expired", "policy_violation"],
            "authorized_by": "operator",
            "approved_at": "2026-01-01T00:00:00Z",
        }

        target_mock = MagicMock()
        target_mock.verification_status = "operator_authorized"

        mock_db = MagicMock()
        mock_db.scalar.return_value = assessment
        mock_db.get.side_effect = lambda model, id_: target_mock if model.__name__ == "Target" else assessment
        mock_sessions = MagicMock()
        mock_sessions.return_value.__enter__.return_value = mock_db

        # Simulate resolve_pinned failing with PolicyError and chained ResolutionError(NXDOMAIN)
        inner_err = ResolutionError(
            ResolutionErrorCode.NXDOMAIN, "unresolvable-ghost-domain-12345.org", "NXDOMAIN"
        )
        policy_err = PolicyError("Target host did not resolve.")
        policy_err.__cause__ = inner_err

        with (
            patch("aegis.worker.check_execution_url") as mock_check,
            patch("aegis.worker.resolve_pinned", side_effect=policy_err),
            patch("aegis.worker.audit"),
        ):
            dest_mock = MagicMock()
            dest_mock.host = "unresolvable-ghost-domain-12345.org"
            dest_mock.url = "https://unresolvable-ghost-domain-12345.org"
            mock_check.return_value = dest_mock

            # Execute run_one
            finished = run_one(
                sessions=mock_sessions,
                stopping=lambda: False,
            )

            self.assertTrue(finished)
            # Must transition to completed_with_errors (not failed or aborted!)
            self.assertEqual(assessment.status, "completed_with_errors")
            # Verify checks recorded DNS failure with NXDOMAIN code
            dns_checks = [c for c in assessment.checks if c.get("category") == "dns_intelligence"]
            self.assertTrue(len(dns_checks) > 0)
            self.assertEqual(dns_checks[0]["status"], "failed")
            self.assertEqual(dns_checks[0]["error_code"], "NXDOMAIN")


if __name__ == "__main__":
    unittest.main()
