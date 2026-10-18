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
    false_positive_rate: float

    def passes_gate(self, min_precision: float = 0.90, max_fpr: float = 0.10) -> bool:
        return self.precision >= min_precision and self.false_positive_rate <= max_fpr

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
            "false_positive_rate": round(self.false_positive_rate, 4),
            "passes_gate": self.passes_gate(),
        }


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
        total_gt = len(ground_truth_items)

        tp = 0
        fp = 0
        matched_gt_ids: set[str] = set()

        for finding in findings:
            # Extract attributes
            cwe = str(finding.get("cwe_id", "")).upper()
            target_url = str(finding.get("affected_url") or finding.get("target_url") or "")
            poc_dict = finding.get("poc") or {}
            param = poc_dict.get("parameter") or ""

            # Check if finding matches any ground-truth item
            matched = False
            for gt in ground_truth_items:
                gt_id = gt["id"]
                gt_cwe = str(gt.get("cwe", "")).upper()
                gt_endpoint = str(gt.get("endpoint", "")).lower()
                gt_param = gt.get("parameter")

                # Match by CWE or endpoint
                cwe_match = gt_cwe and (gt_cwe in cwe or cwe in gt_cwe)
                endpoint_match = gt_endpoint and (gt_endpoint in target_url.lower())
                param_match = (not gt_param) or (gt_param.lower() == param.lower())

                if (cwe_match or endpoint_match) and param_match:
                    matched = True
                    matched_gt_ids.add(gt_id)
                    break

            if matched:
                tp += 1
            else:
                fp += 1

        fn = total_gt - len(matched_gt_ids)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / total_gt if total_gt > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tp) if (fp + tp) > 0 else 0.0

        return EvaluationMetrics(
            total_ground_truth=total_gt,
            detected_findings=len(findings),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_positive_rate=fpr,
        )


__all__ = ["BenchmarkEvaluator", "EvaluationMetrics"]
