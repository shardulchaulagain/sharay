"""Unit tests for Finding State Machine, Deterministic Reproducer & Differential Oracle (Requirements C1, C2, C3, C4)."""

from __future__ import annotations

import unittest

from packages.scanner_adapters.reproducer import (
    VALID_TRANSITIONS,
    DeterministicReproducer,
    DifferentialOracle,
    FindingState,
)


class TestReproducer(unittest.TestCase):
    """Test suite for 3x cold replay verification, negative control assertions, and state machine."""

    def test_01_state_machine_valid_transitions(self):
        # OBSERVED -> CANDIDATE is valid
        self.assertIn(FindingState.CANDIDATE, VALID_TRANSITIONS[FindingState.OBSERVED])
        # CANDIDATE -> REPRODUCED is valid
        self.assertIn(FindingState.REPRODUCED, VALID_TRANSITIONS[FindingState.CANDIDATE])
        # REPRODUCED -> EXPLOITED is valid
        self.assertIn(FindingState.EXPLOITED, VALID_TRANSITIONS[FindingState.REPRODUCED])
        # Direct CANDIDATE -> VERIFIED is invalid
        self.assertNotIn(FindingState.VERIFIED, VALID_TRANSITIONS[FindingState.CANDIDATE])

    def test_02_deterministic_reproducer_promotes_confirmed_finding(self):
        # Mock HTTP client:
        # Baseline returns 200, normal page, 50ms
        # Active probe returns 200, page reflecting canary "sharay_canary_sql", 55ms
        # Benign negative control returns 200, normal page, 50ms (no canary)
        def mock_client(url: str):
            if "sharay_canary_sql" in url:
                return 200, b"<html>Hello User! Logged in with sharay_canary_sql</html>", 55.0
            return 200, b"<html>Hello Guest! Welcome to our portal.</html>", 50.0

        reproducer = DeterministicReproducer(required_replays=3, http_client=mock_client)
        result = reproducer.verify_finding(
            base_url="https://pentest-ground.com:4280/vulnerabilities/sqli/?id=1",
            fuzz_param="id",
            active_payload="1' UNION SELECT 'sharay_canary_sql'--",
            benign_control_payload="1",
            canary="sharay_canary_sql",
        )

        self.assertTrue(result.confirmed)
        self.assertEqual(result.state, FindingState.REPRODUCED)
        self.assertEqual(result.replays_passed, 3)
        self.assertTrue(result.negative_control_passed)
        self.assertIsNone(result.demotion_reason)
        self.assertEqual(len(result.replay_attempts), 3)
        for a in result.replay_attempts:
            self.assertTrue(a.matched_oracle)

    def test_03_negative_control_fires_demotes_finding(self):
        # Scenario: Target page reflects ANY input into the response regardless of vulnerability.
        # Active payload reflects canary; but negative control ALSO reflects!
        def mock_client(url: str):
            if "sharay_canary_sql" in url:
                return 200, b"<html>Query error or reflection: sharay_canary_sql</html>", 50.0
            if "sharay_benign" in url:
                # Negative control also triggers the reflection/error!
                return 200, b"<html>Query error or reflection: sharay_canary_sql</html>", 50.0
            return 200, b"<html>Normal baseline</html>", 50.0

        reproducer = DeterministicReproducer(required_replays=3, http_client=mock_client)
        result = reproducer.verify_finding(
            base_url="https://target.com/search?q=test",
            fuzz_param="q",
            active_payload="bad' OR 'sharay_canary_sql'",
            benign_control_payload="sharay_benign_safe",
            canary="sharay_canary_sql",
        )

        # Must be DEMOTED because negative control also fired!
        self.assertFalse(result.confirmed)
        self.assertEqual(result.state, FindingState.DEMOTED)
        self.assertFalse(result.negative_control_passed)
        self.assertIn("Negative control fired", result.demotion_reason)

    def test_04_intermittent_jitter_flapping_demotes_finding(self):
        # Scenario: Flaky target responds with anomaly only on 1st and 3rd replay, but 2nd replay fails
        call_count = [0]

        def mock_client(url: str):
            call_count[0] += 1
            if call_count[0] == 1:
                # baseline
                return 200, b"Normal", 50.0
            if call_count[0] == 2:
                # replay 1: anomaly
                return 500, b"SQL syntax error in query", 50.0
            if call_count[0] == 3:
                # replay 2: normal (flapped!)
                return 200, b"Normal", 50.0
            # replay 3: anomaly
            return 500, b"SQL syntax error in query", 50.0

        reproducer = DeterministicReproducer(required_replays=3, http_client=mock_client)
        result = reproducer.verify_finding(
            base_url="https://flaky-server.com/api?id=1",
            fuzz_param="id",
            active_payload="' OR 1=1--",
        )

        self.assertFalse(result.confirmed)
        self.assertEqual(result.state, FindingState.DEMOTED)
        self.assertIn("Reproduction flapped: only 2/3 replays matched oracle", result.demotion_reason)

    def test_05_time_based_differential_oracle(self):
        # Blind SQL injection: baseline is 80ms, probe is 5050ms (sleep 5s)
        is_anomaly, score, reason = DifferentialOracle.evaluate(
            baseline_status=200,
            baseline_body=b"Response data",
            baseline_time_ms=80.0,
            probe_status=200,
            probe_body=b"Response data",
            probe_time_ms=5080.0,
            is_time_based=True,
        )
        self.assertTrue(is_anomaly)
        self.assertGreaterEqual(score, 45.0)
        self.assertIn("Significant time delay detected", reason)


if __name__ == "__main__":
    unittest.main()
