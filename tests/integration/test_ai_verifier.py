"""Acceptance tests for the L7 verifier: provenance, assessment scoping, guarded transitions, budget.

Written by Claude (owner of services/ai_analysis_worker) to review Gemini's draft before adoption.
The verifier may only move a hypothesis through the existing guarded `advance()`, so every change
here is also subject to the role and evidence rules in services/ai_analysis_worker/__init__.py.
"""

import hashlib
import json
import unittest

from services.ai_analysis_worker import Hypothesis, InvestigationError, _event
from services.ai_analysis_worker.verifier import (
    ChallengeVerdict,
    StoredObservation,
    TokenBudgetExceeded,
    TokenUsageLedger,
    apply_adversarial_challenge,
    parse_challenge_verdict,
    verify_testing_outcome,
)

SECRET = "synthetic-secret-value"
ASSESS = "assessment:1"


def observation(ref, outcome, assessment=ASSESS, payload=None):
    body = {"ref": ref} if payload is None else payload
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return StoredObservation(ref, assessment, hashlib.sha256(canonical).hexdigest(), outcome, body)


def store(*observations):
    return {obs.observation_id: obs for obs in observations}


def hypothesis(state, identifier="hypothesis:1"):
    return Hypothesis(
        identifier=identifier,
        statement="The /admin response lacks an effective framing restriction.",
        observation_refs=("observation:1",),
        plan_sha256="a" * 64,
        state=state,
        history=(_event(state, "worker", "Set up for the test."),),
    )


def verdict(kind, flaws=(), refs=("observation:1",), identifier="hypothesis:1", **impact):
    calib = {"theoretical": "t", "observed": "o", "not_yet_tested": ()} | impact
    return ChallengeVerdict(
        hypothesis_id=identifier,
        verdict=kind,
        flaws_detected=flaws,
        cited_observation_refs=refs,
        critique_summary="Summary of the challenge.",
        impact_calibration=calib,
    )


class VerifyTestingOutcomeTests(unittest.TestCase):
    def test_only_a_testing_hypothesis_can_be_verified(self):
        for state in (
            "proposed",
            "awaiting_approval",
            "approved",
            "supported",
            "confirmed",
            "disproved",
            "closed",
        ):
            with self.subTest(state=state), self.assertRaisesRegex(InvestigationError, "state 'testing'"):
                verify_testing_outcome(
                    hypothesis(state),
                    assessment_id=ASSESS,
                    evidence_refs=("observation:1",),
                    observation_store=store(),
                )

    def test_the_outcome_is_decided_by_the_stored_observations(self):
        cases = {
            "supported": ["supporting_signal"],
            "supported ": ["confirmed_reproducible"],
            "inconclusive": ["inconclusive"],
            "disproved": ["contradicted"],
        }
        for expected, outcomes in cases.items():
            refs = tuple(f"observation:{i}" for i, _ in enumerate(outcomes))
            obs = store(*[observation(ref, outcome) for ref, outcome in zip(refs, outcomes)])
            result = verify_testing_outcome(
                hypothesis("testing"), assessment_id=ASSESS, evidence_refs=refs, observation_store=obs
            )
            self.assertEqual(result.state, expected.strip())
            self.assertEqual(result.history[-1].actor, "verifier")
            self.assertEqual(set(result.history[-1].evidence_refs), set(refs))

    def test_evidence_must_be_in_scope_and_pass_provenance(self):
        good = observation("observation:1", "supporting_signal")
        with self.assertRaisesRegex(InvestigationError, "at least one observation"):
            verify_testing_outcome(
                hypothesis("testing"), assessment_id=ASSESS, evidence_refs=(), observation_store=store(good)
            )
        with self.assertRaisesRegex(InvestigationError, "active assessment"):
            verify_testing_outcome(
                hypothesis("testing"),
                assessment_id=ASSESS,
                evidence_refs=("observation:missing",),
                observation_store=store(good),
            )
        other = observation("observation:2", "supporting_signal", assessment="assessment:2")
        with self.assertRaisesRegex(InvestigationError, "active assessment"):
            verify_testing_outcome(
                hypothesis("testing"),
                assessment_id=ASSESS,
                evidence_refs=("observation:2",),
                observation_store=store(other),
            )
        tampered = StoredObservation(
            "observation:3", ASSESS, "b" * 64, "supporting_signal", {"ref": "observation:3"}
        )
        with self.assertRaisesRegex(InvestigationError, "provenance"):
            verify_testing_outcome(
                hypothesis("testing"),
                assessment_id=ASSESS,
                evidence_refs=("observation:3",),
                observation_store=store(tampered),
            )


class AdversarialChallengeTests(unittest.TestCase):
    def test_only_a_supported_hypothesis_can_be_challenged(self):
        with self.assertRaisesRegex(InvestigationError, "state 'supported'"):
            apply_adversarial_challenge(
                hypothesis("testing"),
                verdict("uphold"),
                assessment_id=ASSESS,
                observation_store=store(observation("observation:1", "confirmed_reproducible")),
            )

    def test_confirm_needs_an_upholding_verdict_and_a_reproducible_observation(self):
        obs = store(observation("observation:1", "confirmed_reproducible"))
        result = apply_adversarial_challenge(
            hypothesis("supported"), verdict("uphold"), assessment_id=ASSESS, observation_store=obs
        )
        self.assertEqual(result.state, "confirmed")
        self.assertEqual(result.history[-1].actor, "verifier")

    def test_an_uphold_without_reproducible_proof_is_only_inconclusive(self):
        obs = store(observation("observation:1", "supporting_signal"))
        result = apply_adversarial_challenge(
            hypothesis("supported"), verdict("uphold"), assessment_id=ASSESS, observation_store=obs
        )
        self.assertEqual(result.state, "inconclusive")

    def test_downgrade_and_disprove_verdicts(self):
        obs = store(observation("observation:1", "confirmed_reproducible"))
        down = apply_adversarial_challenge(
            hypothesis("supported"),
            verdict("downgrade_inconclusive", flaws=("overstated_impact",)),
            assessment_id=ASSESS,
            observation_store=obs,
        )
        self.assertEqual(down.state, "inconclusive")
        dis = apply_adversarial_challenge(
            hypothesis("supported"),
            verdict("disprove", flaws=("confounded_observation",)),
            assessment_id=ASSESS,
            observation_store=obs,
        )
        self.assertEqual(dis.state, "disproved")

    def test_the_verdict_must_name_this_hypothesis_and_cite_in_scope_evidence(self):
        obs = store(observation("observation:1", "confirmed_reproducible"))
        with self.assertRaisesRegex(InvestigationError, "does not match"):
            apply_adversarial_challenge(
                hypothesis("supported"),
                verdict("uphold", identifier="hypothesis:other"),
                assessment_id=ASSESS,
                observation_store=obs,
            )
        with self.assertRaisesRegex(InvestigationError, "active assessment"):
            apply_adversarial_challenge(
                hypothesis("supported"),
                verdict("uphold", refs=("observation:missing",)),
                assessment_id=ASSESS,
                observation_store=obs,
            )
        other = observation("observation:2", "confirmed_reproducible", assessment="assessment:2")
        with self.assertRaisesRegex(InvestigationError, "active assessment"):
            apply_adversarial_challenge(
                hypothesis("supported"),
                verdict("uphold", refs=("observation:2",)),
                assessment_id=ASSESS,
                observation_store=store(other),
            )
        tampered = StoredObservation(
            "observation:3", ASSESS, "b" * 64, "confirmed_reproducible", {"ref": "x"}
        )
        with self.assertRaisesRegex(InvestigationError, "provenance"):
            apply_adversarial_challenge(
                hypothesis("supported"),
                verdict("uphold", refs=("observation:3",)),
                assessment_id=ASSESS,
                observation_store=store(tampered),
            )


class ChallengeVerdictParsingTests(unittest.TestCase):
    def test_a_valid_verdict_round_trips(self):
        raw = json.dumps(
            {
                "hypothesis_id": "hypothesis:1",
                "verdict": "disprove",
                "flaws_detected": ["missing_control_baseline"],
                "cited_observation_refs": ["observation:1"],
                "critique_summary": "No baseline was captured.",
                "impact_calibration": {"theoretical": "t", "observed": "o", "not_yet_tested": []},
            }
        ).encode()
        self.assertEqual(parse_challenge_verdict(raw).verdict, "disprove")

    def test_malformed_or_inconsistent_verdicts_are_rejected_without_echoing_input(self):
        base = {
            "hypothesis_id": "hypothesis:1",
            "verdict": "uphold",
            "flaws_detected": [],
            "cited_observation_refs": ["observation:1"],
            "critique_summary": SECRET,
            "impact_calibration": {"theoretical": "t", "observed": "o"},
        }
        cases = [
            b"not json",
            b"7",
            ("[" * 20000).encode(),
            json.dumps(base | {"verdict": "accept"}).encode(),
            json.dumps(base | {"flaws_detected": ["unverified_assumption"]}).encode(),  # uphold with flaws
            json.dumps(base | {"verdict": "disprove", "flaws_detected": []}).encode(),  # non-uphold, no flaw
            json.dumps(base | {"cited_observation_refs": []}).encode(),
            json.dumps(base | {"extra": SECRET}).encode(),
            json.dumps(base | {"flaws_detected": ["not-a-code"]}).encode(),
        ]
        for i, raw in enumerate(cases):
            with self.subTest(i=i), self.assertRaises(InvestigationError) as caught:
                parse_challenge_verdict(raw)
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
        for wrong in ("a string", None, bytearray(b"{}")):
            with self.assertRaises(InvestigationError):
                parse_challenge_verdict(wrong)


class TokenBudgetTests(unittest.TestCase):
    def test_calls_and_tokens_are_both_capped_and_a_refused_call_does_not_count(self):
        ledger = TokenUsageLedger(ASSESS, max_calls=2, max_total_tokens=1000)
        ledger.record_call(prompt_tokens=100, completion_tokens=100)
        self.assertEqual((ledger.calls_made, ledger.total_tokens_used), (1, 200))
        with self.assertRaisesRegex(TokenBudgetExceeded, "token budget"):
            ledger.record_call(prompt_tokens=900, completion_tokens=1)
        self.assertEqual((ledger.calls_made, ledger.total_tokens_used), (1, 200))  # unchanged
        ledger.record_call(prompt_tokens=10, completion_tokens=10)
        with self.assertRaisesRegex(TokenBudgetExceeded, "call budget"):
            ledger.record_call(prompt_tokens=1, completion_tokens=1)
        with self.assertRaisesRegex(InvestigationError, "non-negative"):
            TokenUsageLedger(ASSESS).record_call(prompt_tokens=-1, completion_tokens=0)


if __name__ == "__main__":
    unittest.main()
