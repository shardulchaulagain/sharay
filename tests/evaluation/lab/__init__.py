"""SHARAY Ground-Truth Evaluation Lab Package.

Contains paired vulnerable and patched/remediated test fixtures, ground-truth manifests,
and verification harnesses for empirical detector evaluation.
"""

from packages.evaluation_lab import (
    DetectorMetrics,
    EvaluationCase,
    EvaluationLabRunner,
    VulnClass,
    get_ground_truth_corpus,
)

__all__ = [
    "DetectorMetrics",
    "EvaluationCase",
    "EvaluationLabRunner",
    "VulnClass",
    "get_ground_truth_corpus",
]
