"""Deterministic hypothesis verifier, adversarial multi-agent challenge engine, and token ledger (L7).

Prepared in drafts/gemini/ for Claude (`services/ai_analysis_worker/verifier.py`) to extend
`services/ai_analysis_worker/__init__.py`. Implements the missing `verifier` actor in `_MOVES`,
assessment-scoped observation provenance verification, adversarial multi-agent challenge
(`ChallengeVerdict`), and per-assessment token/call budget accounting.
Approved by human architect directive (signature: shardul).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from packages.scanner_adapters.integrations._parsing import load_json
from packages.shared_schemas import Reference
from services.ai_analysis_worker import (
    Hypothesis,
    InvestigationError,
    Text,
    advance,
)

MAX_CHALLENGE_BYTES = 32768
VerdictKind = Literal["uphold", "downgrade_inconclusive", "disprove"]
ReasoningFlawCode = Literal[
    "unverified_assumption",
    "missing_control_baseline",
    "confounded_observation",
    "scope_or_boundary_mismatch",
    "overstated_impact",
    "insufficient_reproducibility",
]


class ImpactCalibrationProposal(BaseModel):
    """Three-state impact calibration attached to an adversarial review."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    theoretical: Text
    observed: Text
    not_yet_tested: tuple[Text, ...] = Field(default=(), max_length=10)


class ChallengeVerdict(BaseModel):
    """Typed output of an independent challenger agent inspecting a `supported` hypothesis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: Reference
    verdict: VerdictKind
    flaws_detected: tuple[ReasoningFlawCode, ...] = Field(default=(), max_length=6)
    cited_observation_refs: tuple[Reference, ...] = Field(min_length=1, max_length=20)
    critique_summary: Text
    impact_calibration: ImpactCalibrationProposal

    @model_validator(mode="after")
    def _consistent_verdict_and_flaws(self) -> ChallengeVerdict:
        if self.verdict == "uphold" and self.flaws_detected:
            raise ValueError("An upholding verdict cannot list reasoning flaws.")
        if self.verdict != "uphold" and not self.flaws_detected:
            raise ValueError("A non-upholding verdict must name at least one reasoning flaw.")
        return self


@dataclass(frozen=True)
class StoredObservation:
    """Trusted control-plane record of an observation belonging to a specific assessment."""

    observation_id: str
    assessment_id: str
    evidence_sha256: str
    outcome: Literal[
        "confirmed_reproducible",
        "supporting_signal",
        "inconclusive",
        "contradicted",
    ]
    payload: dict[str, Any]


def parse_challenge_verdict(raw: bytes) -> ChallengeVerdict:
    """Validate an adversarial challenger agent's JSON output with fixed error messages."""
    if not isinstance(raw, bytes) or len(raw) > MAX_CHALLENGE_BYTES:
        raise InvestigationError("Challenger output is not bytes within the challenge budget.")
    try:
        doc = load_json(raw, "Challenger output")
    except ValueError:
        raise InvestigationError("Challenger output is not a valid challenge verdict.") from None
    if isinstance(doc, dict):
        raw_verdict = doc.get("verdict")
        raw_flaws = doc.get("flaws_detected")
        if raw_verdict == "uphold" and isinstance(raw_flaws, list) and raw_flaws:
            raise InvestigationError("An upholding verdict cannot list reasoning flaws.")
        if raw_verdict in {"downgrade_inconclusive", "disprove"} and (
            not isinstance(raw_flaws, list) or not raw_flaws
        ):
            raise InvestigationError("A non-upholding verdict must name at least one reasoning flaw.")
    try:
        return ChallengeVerdict.model_validate(doc)
    except (ValidationError, ValueError):
        raise InvestigationError("Challenger output is not a valid challenge verdict.") from None


def verify_testing_outcome(
    hypothesis: Hypothesis,
    *,
    assessment_id: str,
    evidence_refs: tuple[str, ...],
    observation_store: dict[str, StoredObservation],
) -> Hypothesis:
    """Act as the deterministic `verifier` to transition a `testing` hypothesis to
    `supported`, `inconclusive`, or `disproved` based on assessment-scoped observations
    and verified SHA-256 digests.
    """
    if hypothesis.state != "testing":
        raise InvestigationError("Only a hypothesis in state 'testing' can be verified.")
    if not evidence_refs:
        raise InvestigationError("Verification requires at least one observation reference.")

    scoped_ids: set[str] = set()
    outcomes: list[str] = []
    for ref in evidence_refs:
        obs = observation_store.get(ref)
        if obs is None or obs.assessment_id != assessment_id:
            raise InvestigationError("Evidence reference does not belong to the active assessment.")
        canonical = json.dumps(obs.payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        actual_sha256 = hashlib.sha256(canonical).hexdigest()
        if actual_sha256 != obs.evidence_sha256:
            raise InvestigationError("Stored observation failed SHA-256 provenance verification.")
        scoped_ids.add(ref)
        outcomes.append(obs.outcome)

    has_positive = "confirmed_reproducible" in outcomes or "supporting_signal" in outcomes
    has_contradicted = "contradicted" in outcomes
    if has_contradicted and has_positive:
        return advance(
            hypothesis,
            "inconclusive",
            "verifier",
            "Deterministic verification found conflicting supporting and contradicting evidence.",
            evidence_refs=evidence_refs,
            known_observations=scoped_ids,
        )
    if has_contradicted:
        return advance(
            hypothesis,
            "disproved",
            "verifier",
            "Deterministic verification found contradicting target evidence.",
            evidence_refs=evidence_refs,
            known_observations=scoped_ids,
        )
    if has_positive:
        return advance(
            hypothesis,
            "supported",
            "verifier",
            "Deterministic verification confirmed assessment-scoped supporting evidence.",
            evidence_refs=evidence_refs,
            known_observations=scoped_ids,
        )
    return advance(
        hypothesis,
        "inconclusive",
        "verifier",
        "Deterministic verification found only inconclusive target observations.",
        evidence_refs=evidence_refs,
        known_observations=scoped_ids,
    )


def apply_adversarial_challenge(
    hypothesis: Hypothesis,
    verdict: ChallengeVerdict,
    *,
    assessment_id: str,
    observation_store: dict[str, StoredObservation],
) -> Hypothesis:
    """Combine deterministic provenance checks with an adversarial `ChallengeVerdict`
    to transition a `supported` hypothesis to `confirmed`, `inconclusive`, or `disproved`.
    """
    if hypothesis.state != "supported":
        raise InvestigationError("Adversarial challenge requires a hypothesis in state 'supported'.")
    if verdict.hypothesis_id != hypothesis.identifier:
        raise InvestigationError("Challenge verdict hypothesis_id does not match the hypothesis.")

    scoped_ids: set[str] = set()
    has_reproducible_proof = False
    has_contradicted = False
    for ref in verdict.cited_observation_refs:
        obs = observation_store.get(ref)
        if obs is None or obs.assessment_id != assessment_id:
            raise InvestigationError("Challenge verdict cites an observation outside the active assessment.")
        canonical = json.dumps(obs.payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if hashlib.sha256(canonical).hexdigest() != obs.evidence_sha256:
            raise InvestigationError("Cited observation failed SHA-256 provenance verification.")
        scoped_ids.add(ref)
        if obs.outcome == "confirmed_reproducible":
            has_reproducible_proof = True
        elif obs.outcome == "contradicted":
            has_contradicted = True

    if verdict.verdict == "disprove":
        flaws = ", ".join(verdict.flaws_detected)
        return advance(
            hypothesis,
            "disproved",
            "verifier",
            f"Disproved by adversarial verification ({flaws}): {verdict.critique_summary[:300]}",
            evidence_refs=verdict.cited_observation_refs,
            known_observations=scoped_ids,
        )
    if verdict.verdict == "downgrade_inconclusive" or not has_reproducible_proof or has_contradicted:
        flaws = ", ".join(verdict.flaws_detected) or (
            "contradicted_observation_cited"
            if has_contradicted
            else "missing_confirmed_reproducible_observation"
        )
        return advance(
            hypothesis,
            "inconclusive",
            "verifier",
            f"Downgraded to inconclusive ({flaws}): {verdict.critique_summary[:300]}",
            evidence_refs=verdict.cited_observation_refs,
            known_observations=scoped_ids,
        )
    return advance(
        hypothesis,
        "confirmed",
        "verifier",
        f"Confirmed after reproducible verification and adversarial review: {verdict.critique_summary[:300]}",
        evidence_refs=verdict.cited_observation_refs,
        known_observations=scoped_ids,
    )


class TokenBudgetExceeded(InvestigationError):
    """Assessment AI token or call budget was exceeded."""


@dataclass
class TokenUsageLedger:
    """Per-assessment token and call accounting to prevent unbounded AI invocation."""

    assessment_id: str
    max_calls: int = 10
    max_total_tokens: int = 64000
    calls_made: int = 0
    prompt_tokens_used: int = 0
    completion_tokens_used: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.max_calls) is not int
            or self.max_calls < 0
            or type(self.max_total_tokens) is not int
            or self.max_total_tokens < 0
            or type(self.calls_made) is not int
            or self.calls_made < 0
            or type(self.prompt_tokens_used) is not int
            or self.prompt_tokens_used < 0
            or type(self.completion_tokens_used) is not int
            or self.completion_tokens_used < 0
        ):
            raise InvestigationError("Token ledger budgets and counters must be non-negative integers.")

    @property
    def total_tokens_used(self) -> int:
        return self.prompt_tokens_used + self.completion_tokens_used

    def record_call(self, *, prompt_tokens: int, completion_tokens: int) -> None:
        if (
            type(prompt_tokens) is not int
            or type(completion_tokens) is not int
            or prompt_tokens < 0
            or completion_tokens < 0
        ):
            raise InvestigationError("Token counts must be non-negative integers.")
        if self.calls_made + 1 > self.max_calls:
            raise TokenBudgetExceeded("Assessment AI call budget exceeded.")
        if self.total_tokens_used + prompt_tokens + completion_tokens > self.max_total_tokens:
            raise TokenBudgetExceeded("Assessment AI token budget exceeded.")
        self.calls_made += 1
        self.prompt_tokens_used += prompt_tokens
        self.completion_tokens_used += completion_tokens


__all__ = [
    "ChallengeVerdict",
    "ImpactCalibrationProposal",
    "ReasoningFlawCode",
    "StoredObservation",
    "TokenBudgetExceeded",
    "TokenUsageLedger",
    "VerdictKind",
    "apply_adversarial_challenge",
    "parse_challenge_verdict",
    "verify_testing_outcome",
]
