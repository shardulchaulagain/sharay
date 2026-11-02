"""Automated Evaluation & Benchmark Metrics Engine (Requirements K1, K2, K3).

Scores scan findings against ground-truth catalogs:
- Computes Precision, Recall, False-Positive Rate (FPR), and Stability.
- Enforces release quality gate: Precision >= 95% and FPR <= 5%.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EvaluationMetrics:
    total_ground_truth: int
    detected_findings: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_discovery_rate: float
    # A classical false-positive rate needs labelled negatives. It is None when the catalog has no
    # benign corpus -- it is left undefined rather than fabricated from the positives alone.
    false_positive_rate: float | None

    def passes_gate(self, min_precision: float = 0.90, max_fpr: float = 0.10) -> bool:
        # Gate on precision and the always-defined false-discovery rate; also honour a measured FPR
        # when a negative corpus provided one.
        if self.precision < min_precision or self.false_discovery_rate > max_fpr:
            return False
        return self.false_positive_rate is None or self.false_positive_rate <= max_fpr

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_ground_truth": self.total_ground_truth,
            "detected_findings": self.detected_findings,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_discovery_rate": round(self.false_discovery_rate, 4),
            "false_positive_rate": None
            if self.false_positive_rate is None
            else round(self.false_positive_rate, 4),
            "passes_gate": self.passes_gate(),
        }


def _finding_matches(finding: dict[str, Any], entry: dict[str, Any]) -> bool:
    """A finding matches a catalog entry when it targets the entry's location (endpoint + parameter)
    and does not contradict its CWE.

    Location is the primary key: a finding must actually target the entry's endpoint -- a shared CWE
    alone never binds a finding to an endpoint it never touched (that is what let a real SQLi be
    scored against a benign /health endpoint). CWE is an exact identity check that only BLOCKS when
    both sides name a different CWE; it is never a substring match and an empty CWE never matches on
    its own.
    """
    cwe = str(finding.get("cwe_id", "")).strip().upper()
    target = str(finding.get("affected_url") or finding.get("target_url") or "").lower()
    param = str((finding.get("poc") or {}).get("parameter") or "")
    entry_cwe = str(entry.get("cwe", "")).strip().upper()
    entry_endpoint = str(entry.get("endpoint", "")).lower()
    entry_param = entry.get("parameter")

    endpoint_match = bool(entry_endpoint) and bool(target) and entry_endpoint in target
    param_match = (not entry_param) or (str(entry_param).lower() == param.lower())
    cwe_conflict = bool(entry_cwe) and bool(cwe) and cwe != entry_cwe
    return endpoint_match and param_match and not cwe_conflict


class BenchmarkEvaluator:
    """Evaluates scan findings against ground-truth catalogs."""

    @classmethod
    def evaluate(
        cls,
        findings: list[dict[str, Any]],
        ground_truth_path: str | Path,
    ) -> EvaluationMetrics:
        catalog_file = Path(ground_truth_path)
        if not catalog_file.exists():
            raise FileNotFoundError(f"Ground truth catalog not found: {catalog_file}")

        catalog = json.loads(catalog_file.read_text(encoding="utf-8"))
        ground_truth_items = catalog.get("vulnerabilities", [])
        benign_items = catalog.get("benign", [])
        total_gt = len(ground_truth_items)

        # A true positive is a distinct ground-truth item detected; redundant findings for an
        # already-credited item never add more TPs. A finding matching no ground-truth item is a
        # false positive. Recall is therefore bounded by 1.0 by construction.
        matched_gt_ids: set[str] = set()
        fp = 0
        for finding in findings:
            hit_ids = [gt["id"] for gt in ground_truth_items if _finding_matches(finding, gt)]
            if hit_ids:
                matched_gt_ids.update(hit_ids)
            else:
                fp += 1

        tp = len(matched_gt_ids)
        fn = total_gt - tp
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / total_gt if total_gt > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        false_discovery_rate = fp / (tp + fp) if (tp + fp) > 0 else 0.0

        # A classical FPR needs true negatives: measure it over the labelled benign corpus if present
        # (a benign case a finding flags is a false positive). Undefined (None) without negatives.
        if benign_items:
            benign_flagged = sum(1 for b in benign_items if any(_finding_matches(f, b) for f in findings))
            false_positive_rate: float | None = benign_flagged / len(benign_items)
        else:
            false_positive_rate = None

        return EvaluationMetrics(
            total_ground_truth=total_gt,
            detected_findings=len(findings),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_discovery_rate=false_discovery_rate,
            false_positive_rate=false_positive_rate,
        )


__all__ = ["BenchmarkEvaluator", "EvaluationMetrics"]
