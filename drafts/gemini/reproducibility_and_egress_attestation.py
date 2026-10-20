"""Reproducibility Score Tracking & Egress Attestation Engine.

Phase 2 / Phase 3 (Sector 1: Verification Engine & Sector 3: Execution Sandbox).
Implements:
1. ReproducibilityScoreTracker: Computes empirical reproducibility scores, tracks false-positive/negative
   rates across scanner runs, and formats metadata badges for UI display and executive reports.
2. EgressAttestationLogger: Captures exact firewall rulesets (nftables/iptables/pf) applied and torn down
   per scan run, calculates cryptographic digests, and anchors immutable attestations into the audit ledger.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class AttestationState(str, Enum):
    APPLIED = "applied"
    ACTIVE = "active"
    TEARDOWN_CONFIRMED = "teardown_confirmed"
    TEARDOWN_FAILED = "teardown_failed"
    TAMPER_DETECTED = "tamper_detected"


@dataclass
class AssessmentReproducibilityMetrics:
    """Empirical reproducibility and detection accuracy metrics for a scan assessment."""

    assessment_id: str
    total_findings: int
    confirmed_reproducible: int
    suspected: int
    inconclusive: int
    validation_failed: int
    true_positives: int
    false_positives: int
    false_negatives: int
    reproducibility_score: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "total_findings": self.total_findings,
            "confirmed_reproducible": self.confirmed_reproducible,
            "suspected": self.suspected,
            "inconclusive": self.inconclusive,
            "validation_failed": self.validation_failed,
            "reproducibility_score": round(self.reproducibility_score, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "ground_truth_verified": (self.true_positives + self.false_positives + self.false_negatives) > 0,
        }


class ReproducibilityScoreTracker:
    """Evaluates reproducibility and classification rigor across scanner findings."""

    def compute_assessment_metrics(
        self,
        assessment_id: str,
        findings: List[Dict[str, Any]],
        ground_truth: Optional[Dict[str, Any]] = None,
    ) -> AssessmentReproducibilityMetrics:
        total = len(findings)
        confirmed = sum(1 for f in findings if f.get("status") in ("confirmed", "confirmed_reproducible"))
        suspected = sum(1 for f in findings if f.get("status") == "suspected")
        inconclusive = sum(1 for f in findings if f.get("status") == "inconclusive")
        failed = sum(1 for f in findings if f.get("status") == "validation_failed")

        # Reproducibility score is the ratio of rigorously proven findings to total findings
        reproducibility_score = (confirmed / total) if total > 0 else 1.0

        tp = 0
        fp = 0
        fn = 0

        if ground_truth:
            expected_set = set(ground_truth.get("expected_vulnerabilities", []))
            detected_set = {f.get("vuln_type") or f.get("id") for f in findings if f.get("status") in ("confirmed", "confirmed_reproducible")}
            tp = len(detected_set & expected_set)
            fp = len(detected_set - expected_set)
            fn = len(expected_set - detected_set)

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else (1.0 if fp == 0 and total > 0 else 0.0)
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else (1.0 if fn == 0 else 0.0)
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        fpr = (fp / (tp + fp)) if (tp + fp) > 0 else 0.0

        return AssessmentReproducibilityMetrics(
            assessment_id=assessment_id,
            total_findings=total,
            confirmed_reproducible=confirmed,
            suspected=suspected,
            inconclusive=inconclusive,
            validation_failed=failed,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            reproducibility_score=reproducibility_score,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_positive_rate=fpr,
        )


@dataclass
class EgressRuleEntry:
    rule_id: str
    action: str  # "ALLOW" or "DROP"
    destination_cidr: str
    protocol: str  # "tcp", "udp", "all"
    destination_ports: List[int]

    def normalized_string(self) -> str:
        ports_str = ",".join(map(str, sorted(self.destination_ports)))
        return f"{self.action}:{self.protocol}:{self.destination_cidr}:{ports_str}"


@dataclass
class EgressAttestationReceipt:
    attestation_id: str
    assessment_id: str
    target_scope: str
    state: AttestationState
    applied_ruleset_hash: str
    applied_timestamp_utc: float
    teardown_timestamp_utc: Optional[float]
    rules_count: int
    ledger_entry_id: str
    signature_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "assessment_id": self.assessment_id,
            "target_scope": self.target_scope,
            "state": self.state.value,
            "applied_ruleset_hash": self.applied_ruleset_hash,
            "applied_timestamp_utc": self.applied_timestamp_utc,
            "teardown_timestamp_utc": self.teardown_timestamp_utc,
            "rules_count": self.rules_count,
            "ledger_entry_id": self.ledger_entry_id,
            "signature_sha256": self.signature_sha256,
        }


class EgressAttestationLogger:
    """Manages cryptographic attestation of egress firewall policies per assessment."""

    def __init__(self, notary_secret: str = "SHARAY_EGRESS_ATTESTATION_MASTER_KEY"):
        self.notary_secret = notary_secret.encode("utf-8")
        self._active_attestations: Dict[str, EgressAttestationReceipt] = {}
        self._ruleset_cache: Dict[str, List[EgressRuleEntry]] = {}

    def _hash_ruleset(self, rules: List[EgressRuleEntry]) -> str:
        normalized_rules = sorted([r.normalized_string() for r in rules])
        canonical = "\n".join(normalized_rules).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def record_ruleset_applied(
        self,
        assessment_id: str,
        target_scope: str,
        rules: List[EgressRuleEntry],
    ) -> EgressAttestationReceipt:
        ruleset_hash = self._hash_ruleset(rules)
        now = time.time()
        attestation_id = f"attest-{hashlib.sha256(f'{assessment_id}:{now}'.encode()).hexdigest()[:16]}"
        ledger_entry_id = f"ledger-egress-{assessment_id}"

        # Sign receipt payload using HMAC-SHA256
        import hmac

        sig_payload = f"{attestation_id}:{assessment_id}:{ruleset_hash}:{now}".encode("utf-8")
        signature = hmac.new(self.notary_secret, sig_payload, hashlib.sha256).hexdigest()

        receipt = EgressAttestationReceipt(
            attestation_id=attestation_id,
            assessment_id=assessment_id,
            target_scope=target_scope,
            state=AttestationState.APPLIED,
            applied_ruleset_hash=ruleset_hash,
            applied_timestamp_utc=now,
            teardown_timestamp_utc=None,
            rules_count=len(rules),
            ledger_entry_id=ledger_entry_id,
            signature_sha256=signature,
        )

        self._active_attestations[assessment_id] = receipt
        self._ruleset_cache[assessment_id] = list(rules)
        return receipt

    def verify_active_ruleset_integrity(
        self,
        assessment_id: str,
        current_active_rules: List[EgressRuleEntry],
    ) -> bool:
        """Confirms runtime firewall ruleset has not experienced out-of-band tampering."""
        receipt = self._active_attestations.get(assessment_id)
        if not receipt:
            return False

        current_hash = self._hash_ruleset(current_active_rules)
        if current_hash != receipt.applied_ruleset_hash:
            receipt.state = AttestationState.TAMPER_DETECTED
            return False
        return True

    def record_ruleset_teardown(
        self,
        assessment_id: str,
        teardown_successful: bool,
    ) -> EgressAttestationReceipt:
        receipt = self._active_attestations.get(assessment_id)
        if not receipt:
            raise KeyError(f"No active attestation found for assessment {assessment_id}")

        now = time.time()
        receipt.teardown_timestamp_utc = now
        receipt.state = AttestationState.TEARDOWN_CONFIRMED if teardown_successful else AttestationState.TEARDOWN_FAILED

        # Re-sign the completed receipt
        import hmac

        completed_payload = f"{receipt.attestation_id}:{receipt.state.value}:{now}".encode("utf-8")
        receipt.signature_sha256 = hmac.new(self.notary_secret, completed_payload, hashlib.sha256).hexdigest()

        return receipt
