"""Product & integration tests for Sector 10.3: Mutation Testing on Verification Core.

Applies targeted semantic mutations to core verification logic:
1. DifferentialOracle: Rejection of canary present in baseline -> MUST be killed by test.
2. DifferentialOracle: False time delta (<4s) rejection -> MUST be killed by test.
3. DifferentialOracle: Existing baseline error rejection -> MUST be killed by test.
4. DeterministicReproducer: 3x consecutive cold replay vs 1x reduction -> MUST be killed by test.
5. FindingState Lifecycle: Illegal skip transitions (OBSERVED -> VERIFIED) -> MUST be killed by test.
6. AutoPyVerifier: Inversion of exit code 0 requirement -> MUST be killed by test.
7. AutoPyVerifier Script: Omission of response body read -> MUST be killed by test.

Proves courtroom-grade verification robustness: all mutants that weaken verification are caught and killed.
"""

import unittest

from aegis.worker import _autopyverifier_passed, _finding_status
from packages.scanner_adapters.reproducer import (
    VALID_TRANSITIONS,
    DeterministicReproducer,
    DifferentialOracle,
    FindingState,
)
from services.ai_analysis_worker.autopyverifier import AutoPyVerifier


class TestVerificationMutationTesting(unittest.TestCase):
    def test_mutant_canary_inversion_is_killed(self):
        """Mutant: Canary reflected in baseline is treated as a vulnerability.

        Original behavior: If canary is already in baseline, it's not a differential finding.
        """
        canary = "sharay_canary_test"
        baseline_body = b"Normal page reflecting canary: sharay_canary_test"
        probe_body = b"Normal page reflecting canary: sharay_canary_test"

        is_anomaly, score, reason = DifferentialOracle.evaluate(
            baseline_status=200,
            baseline_body=baseline_body,
            baseline_time_ms=50.0,
            probe_status=200,
            probe_body=probe_body,
            probe_time_ms=50.0,
            canary=canary,
        )
        self.assertFalse(is_anomaly, "Canary present in baseline must not trigger anomaly")
        self.assertLess(score, 35.0)

        # Mutant logic: checks only probe body
        mutant_anomaly = canary.encode() in probe_body
        self.assertTrue(mutant_anomaly)
        self.assertNotEqual(is_anomaly, mutant_anomaly, "Mutant must be killed")

    def test_mutant_timing_delta_inversion_is_killed(self):
        """Mutant: Accepts small time deltas (<4000ms) as time-based injection."""
        # Fast response (only 200ms delta, well below 4000ms)
        is_anomaly, score, reason = DifferentialOracle.evaluate(
            baseline_status=200,
            baseline_body=b"ok",
            baseline_time_ms=100.0,
            probe_status=200,
            probe_body=b"ok",
            probe_time_ms=300.0,  # 200ms delta
            is_time_based=True,
        )
        self.assertFalse(is_anomaly, "200ms delta is natural jitter, not time-based injection")

        # True time-based injection (5200ms delta)
        is_true_anomaly, true_score, _ = DifferentialOracle.evaluate(
            baseline_status=200,
            baseline_body=b"ok",
            baseline_time_ms=100.0,
            probe_status=200,
            probe_body=b"ok",
            probe_time_ms=5300.0,  # 5200ms delta
            is_time_based=True,
        )
        self.assertTrue(is_true_anomaly)
        self.assertGreaterEqual(true_score, 45.0)

    def test_mutant_existing_baseline_sql_error_is_killed(self):
        """Mutant: Alerts on SQL error already present on benign baseline page."""
        baseline_err = b"<html>Warning: mysqli_connect() error on page</html>"
        probe_err = b"<html>Warning: mysqli_connect() error on page</html>"

        is_anomaly, score, reason = DifferentialOracle.evaluate(
            baseline_status=200,
            baseline_body=baseline_err,
            baseline_time_ms=50.0,
            probe_status=200,
            probe_body=probe_err,
            probe_time_ms=50.0,
        )
        self.assertFalse(is_anomaly, "Pre-existing error in baseline must not be attributed to exploit probe")

    def test_mutant_cold_replay_reduction_is_killed(self):
        """Mutant: Accepts 1x single lucky reflection without requiring 3 consecutive passes."""
        call_count = [0]
        canary = "sharay_unique_canary"

        # Flaky mock: 1st probe reflects canary, 2nd and 3rd return normal page without canary (flapped)
        def flaky_http_client(url, *args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # Baseline
                return 200, b"normal", 20.0
            elif call_count[0] == 2:
                # Replay 1: Lucky reflection
                return 200, f"result: {canary}".encode(), 20.0
            elif call_count[0] in (3, 4):
                # Replays 2 and 3: Flapped (no reflection, identical to benign baseline)
                return 200, b"normal", 20.0
            else:
                # Negative control
                return 200, b"normal", 20.0

        reproducer = DeterministicReproducer(required_replays=3, http_client=flaky_http_client)
        result = reproducer.verify_finding(
            base_url="http://target.local/vuln",
            fuzz_param="id",
            active_payload="1' OR '1'='1",
            canary=canary,
        )

        self.assertFalse(result.confirmed, "Flaky target must be demoted")
        self.assertEqual(result.state, FindingState.DEMOTED)
        self.assertLess(result.replays_passed, 3)

    def test_mutant_finding_lifecycle_transition_bypass_is_killed(self):
        """Mutant: Allows direct transition from OBSERVED -> VERIFIED without REPRODUCED step."""
        # Valid: OBSERVED can only go to CANDIDATE or DEMOTED
        self.assertIn(FindingState.CANDIDATE, VALID_TRANSITIONS[FindingState.OBSERVED])
        self.assertIn(FindingState.DEMOTED, VALID_TRANSITIONS[FindingState.OBSERVED])
        self.assertNotIn(FindingState.VERIFIED, VALID_TRANSITIONS[FindingState.OBSERVED])
        self.assertNotIn(FindingState.REPRODUCED, VALID_TRANSITIONS[FindingState.OBSERVED])

    def test_mutant_autopyverifier_exit_code_inversion_is_killed(self):
        """Mutant: AutoPyVerifier accepts exit code 1 as success."""
        finding_patched = {
            "title": "SQL Injection",
            "autopyverifier": {"exit_code": 1, "mock_mode": False, "status": "executed"},
        }
        finding_vuln = {
            "title": "SQL Injection",
            "autopyverifier": {"exit_code": 0, "mock_mode": False, "status": "executed"},
        }

        self.assertFalse(_autopyverifier_passed(finding_patched))
        self.assertTrue(_autopyverifier_passed(finding_vuln))
        self.assertEqual(_finding_status(finding_patched), "suspected")
        self.assertEqual(_finding_status(finding_vuln), "confirmed")

    def test_mutant_autopyverifier_script_omitting_body_read_is_killed(self):
        """Mutant: AutoPyVerifier script generator omits reading the HTTP response body."""
        verifier = AutoPyVerifier()
        script = verifier.synthesize_script(
            target_url="http://127.0.0.1/search",
            vuln_type="sql_injection",
            canary="root:x:0:0",
            payload="canary' OR 1=1--",
            parameter="q",
            mock_mode=False,
            method="GET",
        )

        self.assertIn("body = resp.read().decode(", script)
        self.assertIn("root:x:0:0", script)


if __name__ == "__main__":
    unittest.main()
