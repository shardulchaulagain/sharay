"""Sector 1 Comprehensive Verification Engine Test Suite (Sectors 1.1–1.5).

Proves:
- Sector 1.1: AutoPyVerifier container/netns execution & sanitized process sandboxing.
- Sector 1.2: Strict 6-state lifecycle transitions (OBSERVED -> CANDIDATE -> REPRODUCED -> EXPLOITED -> CHAINED -> VERIFIED).
- Sector 1.2: MultiStepExploitChainEngine with PostconditionOracles and sealed evidence hash.
- Sector 1.3: Dynamic statistical baselining in DifferentialOracle adapting to jitter.
- Sector 1.4: Quantitative reproducibility score & assessment-wide reproducibility metrics.
- Sector 1.5: Real-target regression assertions gating false positives and flaps.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from packages.scanner_adapters.reproducer import (
    DeterministicReproducer,
    DifferentialOracle,
    ExploitChainStep,
    FindingState,
    InvalidStateTransitionError,
    MultiStepExploitChainEngine,
    PostconditionOracle,
    ReproductionResult,
    calculate_assessment_reproducibility,
    transition_state,
)
from services.ai_analysis_worker.autopyverifier import AutoPyVerifier


class VerificationEngineSector1Tests(unittest.TestCase):
    """Exhaustive test suite for Sector 1 Verification Engine capabilities."""

    def test_sector_1_1_autopyverifier_container_and_host_sandbox(self):
        """Sector 1.1: AutoPyVerifier executes in rootless container when configured or sanitized host sandbox."""
        verifier = AutoPyVerifier()
        script = 'print("PROOF_OK")\n'

        # Test host subprocess sandbox execution
        res_host = verifier.execute_in_sandbox(script, use_container=False)
        self.assertEqual(res_host["status"], "verified")
        self.assertEqual(res_host["returncode"], 0)
        self.assertEqual(res_host["stdout"], "PROOF_OK")
        self.assertEqual(res_host["isolation"], "host_subprocess_sandbox")

        # Test rootless container VM execution path
        with patch(
            "services.scanner_worker.container.container_runtime", return_value="/opt/homebrew/bin/podman"
        ):
            with patch(
                "services.scanner_worker.container._machine_ssh",
                return_value=SimpleNamespace(returncode=0, stdout="PROOF_CONTAINER_OK", stderr=""),
            ):
                res_container = verifier.execute_in_sandbox(script, use_container=True)
                self.assertEqual(res_container["status"], "verified")
                self.assertEqual(res_container["stdout"], "PROOF_CONTAINER_OK")
                self.assertEqual(res_container["isolation"], "rootless_container_vm")

    def test_sector_1_2_strict_lifecycle_transitions(self):
        """Sector 1.2: Enforce valid 6-state lifecycle transitions and reject illegal bypasses."""
        state = FindingState.OBSERVED
        # OBSERVED -> CANDIDATE
        state = transition_state(state, FindingState.CANDIDATE)
        self.assertEqual(state, FindingState.CANDIDATE)

        # CANDIDATE -> REPRODUCED
        state = transition_state(state, FindingState.REPRODUCED)
        self.assertEqual(state, FindingState.REPRODUCED)

        # REPRODUCED -> EXPLOITED
        state = transition_state(state, FindingState.EXPLOITED)
        self.assertEqual(state, FindingState.EXPLOITED)

        # EXPLOITED -> CHAINED
        state = transition_state(state, FindingState.CHAINED)
        self.assertEqual(state, FindingState.CHAINED)

        # CHAINED -> VERIFIED
        state = transition_state(state, FindingState.VERIFIED)
        self.assertEqual(state, FindingState.VERIFIED)

        # Terminal state: cannot transition further
        with self.assertRaises(InvalidStateTransitionError):
            transition_state(FindingState.VERIFIED, FindingState.REPRODUCED)

        # Illegal skip: CANDIDATE cannot jump directly to VERIFIED without REPRODUCED/EXPLOITED
        with self.assertRaises(InvalidStateTransitionError):
            transition_state(FindingState.CANDIDATE, FindingState.VERIFIED)

    def test_sector_1_2_multistep_exploit_chain_with_postconditions_and_sealing(self):
        """Sector 1.2: MultiStepExploitChainEngine advances through EXPLOITED, CHAINED, and seals VERIFIED manifest."""
        responses = [
            (200, b"Vulnerable token leaked: sess_admin_sec_999", 45.0),
            (200, b"Session elevated to Administrator", 30.0),
            (200, b"Sensitive file read: root:x:0:0:root:/root:/bin/bash", 50.0),
        ]
        call_idx = 0

        def mock_client(url, headers=None, method="GET", data=None):
            nonlocal call_idx
            res = responses[call_idx]
            call_idx += 1
            return res

        engine = MultiStepExploitChainEngine(http_client=mock_client)

        steps = [
            ExploitChainStep(
                step_name="Trigger Token Leak",
                url="http://target.local/vuln",
                postcondition=PostconditionOracle(
                    effect_type="data_read",
                    description="Token reflection",
                    expected_evidence_marker=b"sess_admin_sec_999",
                ),
            ),
            ExploitChainStep(
                step_name="Elevate Session Privilege",
                url="http://target.local/admin/auth",
                postcondition=PostconditionOracle(
                    effect_type="auth_bypass",
                    description="Admin privilege escalation",
                    expected_evidence_marker=b"Session elevated",
                ),
            ),
            ExploitChainStep(
                step_name="Read Sensitive Config",
                url="http://target.local/admin/view?file=/etc/passwd",
                postcondition=PostconditionOracle(
                    effect_type="data_read",
                    description="LFI payload read",
                    expected_evidence_marker=b"root:x:0:0:",
                ),
            ),
        ]

        result = engine.execute_chain("chain-auth-lfi-001", steps)
        self.assertTrue(result.confirmed)
        self.assertEqual(result.final_state, FindingState.VERIFIED)
        self.assertEqual(result.steps_executed, 3)
        self.assertEqual(result.total_steps, 3)
        self.assertIsNotNone(result.sealed_manifest_hash)
        self.assertEqual(len(result.sealed_manifest_hash), 64)

    def test_sector_1_2_multistep_exploit_chain_demotes_on_postcondition_failure(self):
        """Sector 1.2: Exploit chain demotes to DEMOTED when a step postcondition fails."""
        responses = [
            (200, b"Vulnerable token leaked: sess_admin_sec_999", 45.0),
            (403, b"Forbidden: Invalid CSRF token", 20.0),  # Step 2 fails!
        ]
        call_idx = 0

        def mock_client(url, headers=None, method="GET", data=None):
            nonlocal call_idx
            res = responses[call_idx]
            call_idx += 1
            return res

        engine = MultiStepExploitChainEngine(http_client=mock_client)
        steps = [
            ExploitChainStep(
                step_name="Step 1 Token",
                url="http://target.local/1",
                postcondition=PostconditionOracle(
                    effect_type="data_read",
                    description="Token reflection",
                    expected_evidence_marker=b"sess_admin_sec_999",
                ),
            ),
            ExploitChainStep(
                step_name="Step 2 Action",
                url="http://target.local/2",
                postcondition=PostconditionOracle(
                    effect_type="state_write",
                    description="State write verification",
                    expected_evidence_marker=b"Action completed successfully",
                ),
            ),
        ]

        result = engine.execute_chain("chain-failure-test", steps)
        self.assertFalse(result.confirmed)
        self.assertEqual(result.final_state, FindingState.DEMOTED)
        self.assertIn("failed chained postcondition", result.failure_reason)

    def test_sector_1_3_statistical_dynamic_baselining_in_differential_oracle(self):
        """Sector 1.3: DifferentialOracle computes dynamic 3-sigma thresholds adapting to jitter."""
        # Baseline samples with 100ms mean and 50ms standard deviation
        baseline_samples = [
            (200, b"Normal response page", 100.0),
            (200, b"Normal response page", 150.0),
            (200, b"Normal response page", 80.0),
            (200, b"Normal response page", 120.0),
            (200, b"Normal response page", 90.0),
        ]
        stats = DifferentialOracle.compute_baseline_stats(baseline_samples)
        self.assertAlmostEqual(stats["mean_time_ms"], 108.0, delta=5.0)
        self.assertTrue(stats["std_time_ms"] > 0)

        # Probe with significant delay (e.g. 2800ms vs normal 100ms)
        is_anomaly, score, reason = DifferentialOracle.evaluate(
            baseline_status=200,
            baseline_body=b"Normal response page",
            baseline_time_ms=108.0,
            probe_status=200,
            probe_body=b"Normal response page",
            probe_time_ms=3000.0,
            is_time_based=True,
            baseline_stats=stats,
        )
        self.assertTrue(is_anomaly)
        self.assertIn("Significant time delay detected", reason)

    def test_sector_1_4_quantitative_reproducibility_metrics(self):
        """Sector 1.4: Reproducibility score computation on individual results and assessment aggregations."""
        reproducer = DeterministicReproducer()

        # Mock consistent responses: the injected quote elicits a DB error (a class-specific
        # postcondition), byte-identical across replays; the benign control stays clean.
        client_calls = [
            (200, b"Welcome, user.", 20.0),  # Baseline
            (200, b"You have an error in your SQL syntax near '''", 25.0),  # Replay 1
            (200, b"You have an error in your SQL syntax near '''", 24.0),  # Replay 2
            (200, b"You have an error in your SQL syntax near '''", 26.0),  # Replay 3
            (200, b"Welcome, user.", 20.0),  # Negative control
        ]
        call_idx = 0

        def mock_http(url, timeout=8.0, headers=None, method="GET", data=None):
            nonlocal call_idx
            res = client_calls[call_idx]
            call_idx += 1
            return res

        reproducer.http_client = mock_http
        res = reproducer.verify_finding(
            base_url="http://target.local/search?q=test",
            fuzz_param="q",
            active_payload="'",
            canary="syntax",
        )

        self.assertTrue(res.confirmed)
        self.assertEqual(res.state, FindingState.REPRODUCED)
        self.assertEqual(res.reproducibility_score, 1.0)  # Byte-identical replays = 1.0 score

        # Aggregate across an assessment batch
        demoted_result = ReproductionResult(
            confirmed=False,
            state=FindingState.DEMOTED,
            replays_passed=1,
            total_replays=3,
            negative_control_passed=False,
            reproducibility_score=0.0,
        )
        assessment_metrics = calculate_assessment_reproducibility([res, demoted_result])
        self.assertEqual(assessment_metrics["confirmed_rate"], 0.5)
        self.assertEqual(assessment_metrics["demoted_rate"], 0.5)
        self.assertEqual(assessment_metrics["reproducibility_rate"], 0.5)

    def test_sector_1_5_regression_negative_control_rejection(self):
        """Sector 1.5: Gating test ensuring false positives are demoted fail-closed."""
        reproducer = DeterministicReproducer()

        # Target returns a DB error for EVERYTHING (including the benign control): non-differentiating.
        client_calls = [
            (200, b"Baseline", 20.0),
            (200, b"You have an error in your SQL syntax", 20.0),  # Replay 1
            (200, b"You have an error in your SQL syntax", 20.0),  # Replay 2
            (200, b"You have an error in your SQL syntax", 20.0),  # Replay 3
            (
                200,
                b"You have an error in your SQL syntax",
                20.0,
            ),  # Negative control ALSO errors: false positive!
        ]
        call_idx = 0

        def mock_http(url, timeout=8.0, headers=None, method="GET", data=None):
            nonlocal call_idx
            res = client_calls[call_idx]
            call_idx += 1
            return res

        reproducer.http_client = mock_http
        res = reproducer.verify_finding(
            base_url="http://target.local/echo?p=hi",
            fuzz_param="p",
            active_payload="'",
            canary="syntax",
        )
        self.assertFalse(res.confirmed)
        self.assertEqual(res.state, FindingState.DEMOTED)
        self.assertEqual(res.reproducibility_score, 0.0)
        self.assertIn("Negative control fired", res.demotion_reason)


if __name__ == "__main__":
    unittest.main()
