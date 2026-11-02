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
        # Confirmation binds a class-specific postcondition: the injected quote elicits a DB syntax
        # error (an effect signature), NOT a mere reflection of our own token -- a reflected nonce
        # that is just our input echoed back is a benign reflection and must never confirm (E01/B1).
        # Baseline (id=1) is clean; the active probe (id=1') errors; the benign control (id=1) is clean.
        def mock_client(url: str):
            if "%27" in url:  # active single-quote injection id=1' -> id=1%27
                return (
                    200,
                    b"<html>You have an error in your SQL syntax; check the MariaDB manual</html>",
                    55.0,
                )
            return 200, b"<html>Hello Guest! Welcome to our portal.</html>", 50.0

        reproducer = DeterministicReproducer(required_replays=3, http_client=mock_client)
        result = reproducer.verify_finding(
            base_url="https://pentest-ground.com:4280/vulnerabilities/sqli/?id=1",
            fuzz_param="id",
            active_payload="1'",
            benign_control_payload="1",
            canary="syntax",
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
        # Scenario: the target returns a DB error for ANY input (even the benign control), so the
        # probe is non-differentiating -- it must DEMOTE even though the active replays "fire".
        def mock_client(url: str):
            if "q=test" in url:  # the clean baseline request
                return 200, b"<html>Normal baseline</html>", 50.0
            # Any other input (active payload AND benign control) triggers the same error.
            return 200, b"<html>You have an error in your SQL syntax near your input</html>", 50.0

        reproducer = DeterministicReproducer(required_replays=3, http_client=mock_client)
        result = reproducer.verify_finding(
            base_url="https://target.com/search?q=test",
            fuzz_param="q",
            active_payload="bad' OR '1'='1",
            benign_control_payload="sharay_benign_safe",
            canary="syntax",
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


class BenignReflectionRegressions(unittest.TestCase):
    """E01/B1: a reflected canary that is merely our injected input echoed back is benign.

    Confirmation must bind a class-specific postcondition -- an executable (XSS) context or an
    independent effect signature -- never a plain echo of the nonce we sent.
    """

    @staticmethod
    def _search_app(url, timeout=8.0, headers=None, method="GET", data=None):
        import urllib.parse as up

        value = (up.parse_qs(up.urlsplit(url).query).get("q") or [""])[0]
        return 200, f"<html><body><p>No results for: {value}</p></body></html>".encode(), 5.0

    def test_inert_input_echo_is_demoted_not_confirmed(self):
        rep = DeterministicReproducer(http_client=self._search_app)
        res = rep.verify_finding(
            base_url="http://t/search?q=x",
            fuzz_param="q",
            active_payload="sharay_canary_7f3a",
            canary="sharay_canary_7f3a",
        )
        self.assertFalse(res.confirmed)
        self.assertEqual(res.state, FindingState.DEMOTED)

    def test_unescaped_markup_reflection_confirms_xss(self):
        def xss_app(url, timeout=8.0, headers=None, method="GET", data=None):
            import urllib.parse as up

            value = (up.parse_qs(up.urlsplit(url).query).get("q") or [""])[0]
            return 200, f"<html><body>{value}</body></html>".encode(), 5.0  # raw, unescaped

        payload = '"><sharay_canary_abcd>'
        rep = DeterministicReproducer(http_client=xss_app)
        res = rep.verify_finding(
            base_url="http://t/s?q=x", fuzz_param="q", active_payload=payload, canary=payload
        )
        self.assertTrue(res.confirmed)
        self.assertEqual(res.state, FindingState.REPRODUCED)

    def test_effect_signature_reflection_still_confirms(self):
        # The canary is an effect signature ("root:") the payload did NOT contain, and the file
        # disclosure uses a passwd line the oracle's literal markers do not cover -- still confirms.
        def lfi_app(url, timeout=8.0, headers=None, method="GET", data=None):
            errored = "passwd" in url
            body = b"root:!:0:0:root:/root:/bin/bash\ndaemon:x:1:1" if errored else b"<html>home</html>"
            return 200, body, 5.0

        rep = DeterministicReproducer(http_client=lfi_app)
        res = rep.verify_finding(
            base_url="http://t/p?file=home",
            fuzz_param="file",
            active_payload="/etc/passwd",
            benign_control_payload="home",
            canary="root:",
        )
        self.assertTrue(res.confirmed)
        self.assertEqual(res.state, FindingState.REPRODUCED)
