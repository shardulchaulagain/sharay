"""Formal CVSS v3.1 Calculation Engine & Vector Parser (FIRST.org compliant).

Sector 5 & Phase 5.2: Formal CVSS vectoring (CVSS v3.1 calculation,
Base/Temporal/Environmental scores, vector string parser and generator).

Specification Reference:
FIRST Common Vulnerability Scoring System v3.1: Specification Document
https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping

# --- FIRST.org CVSS v3.1 Metric Constants and Weights ---

# Base Metrics
AV_WEIGHTS = {
    "N": 0.85,  # Network
    "A": 0.62,  # Adjacent
    "L": 0.55,  # Local
    "P": 0.20,  # Physical
}

AC_WEIGHTS = {
    "L": 0.77,  # Low
    "H": 0.44,  # High
}

# Privileges Required depends on Scope (Unchanged vs Changed)
PR_WEIGHTS = {
    "U": {  # Scope Unchanged
        "N": 0.85,
        "L": 0.62,
        "H": 0.27,
    },
    "C": {  # Scope Changed
        "N": 0.85,
        "L": 0.68,
        "H": 0.50,
    },
}

UI_WEIGHTS = {
    "N": 0.85,  # None
    "R": 0.62,  # Required
}

# Confidentiality, Integrity, Availability Impact weights
CIA_WEIGHTS = {
    "H": 0.56,  # High
    "L": 0.22,  # Low
    "N": 0.00,  # None
}

# Temporal Metrics
E_WEIGHTS = {
    "X": 1.00,  # Not Defined
    "H": 1.00,  # High
    "F": 0.97,  # Functional
    "P": 0.94,  # Proof-of-Concept
    "U": 0.91,  # Unproven
}

RL_WEIGHTS = {
    "X": 1.00,  # Not Defined
    "U": 1.00,  # Unavailable
    "W": 0.97,  # Workaround
    "T": 0.96,  # Temporary Fix
    "O": 0.95,  # Official Fix
}

RC_WEIGHTS = {
    "X": 1.00,  # Not Defined
    "C": 1.00,  # Confirmed
    "R": 0.96,  # Reasonable
    "U": 0.92,  # Unknown
}

# Environmental Metrics (Requirements)
REQ_WEIGHTS = {
    "X": 1.00,  # Not Defined
    "H": 1.50,  # High
    "M": 1.00,  # Medium
    "L": 0.50,  # Low
}

# Canonical CVSS 3.1 Vector order per FIRST.org
CANONICAL_METRIC_ORDER = [
    # Base (Mandatory)
    "AV",
    "AC",
    "PR",
    "UI",
    "S",
    "C",
    "I",
    "A",
    # Temporal (Optional)
    "E",
    "RL",
    "RC",
    # Environmental (Optional)
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MPR",
    "MUI",
    "MS",
    "MC",
    "MI",
    "MA",
]

BASE_METRIC_KEYS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
TEMPORAL_METRIC_KEYS = {"E", "RL", "RC"}
ENVIRONMENTAL_METRIC_KEYS = {
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MPR",
    "MUI",
    "MS",
    "MC",
    "MI",
    "MA",
}

VALID_METRIC_VALUES: dict[str, set[str]] = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"H", "L", "N"},
    "I": {"H", "L", "N"},
    "A": {"H", "L", "N"},
    "E": {"X", "H", "F", "P", "U"},
    "RL": {"X", "U", "W", "T", "O"},
    "RC": {"X", "C", "R", "U"},
    "CR": {"X", "H", "M", "L"},
    "IR": {"X", "H", "M", "L"},
    "AR": {"X", "H", "M", "L"},
    "MAV": {"X", "N", "A", "L", "P"},
    "MAC": {"X", "L", "H"},
    "MPR": {"X", "N", "L", "H"},
    "MUI": {"X", "N", "R"},
    "MS": {"X", "U", "C"},
    "MC": {"X", "H", "L", "N"},
    "MI": {"X", "H", "L", "N"},
    "MA": {"X", "H", "L", "N"},
}

METRIC_NAME_ALIASES: dict[str, str] = {
    # Base
    "attack_vector": "AV",
    "attackvector": "AV",
    "av": "AV",
    "attack_complexity": "AC",
    "attackcomplexity": "AC",
    "ac": "AC",
    "privileges_required": "PR",
    "privilegesrequired": "PR",
    "pr": "PR",
    "user_interaction": "UI",
    "userinteraction": "UI",
    "ui": "UI",
    "scope": "S",
    "s": "S",
    "confidentiality": "C",
    "confidentiality_impact": "C",
    "c": "C",
    "integrity": "I",
    "integrity_impact": "I",
    "i": "I",
    "availability": "A",
    "availability_impact": "A",
    "a": "A",
    # Temporal
    "exploit_code_maturity": "E",
    "exploitability": "E",
    "e": "E",
    "remediation_level": "RL",
    "rl": "RL",
    "report_confidence": "RC",
    "rc": "RC",
    # Environmental
    "confidentiality_requirement": "CR",
    "cr": "CR",
    "integrity_requirement": "IR",
    "ir": "IR",
    "availability_requirement": "AR",
    "ar": "AR",
    "modified_attack_vector": "MAV",
    "mav": "MAV",
    "modified_attack_complexity": "MAC",
    "mac": "MAC",
    "modified_privileges_required": "MPR",
    "mpr": "MPR",
    "modified_user_interaction": "MUI",
    "mui": "MUI",
    "modified_scope": "MS",
    "ms": "MS",
    "modified_confidentiality": "MC",
    "mc": "MC",
    "modified_integrity": "MI",
    "mi": "MI",
    "modified_availability": "MA",
    "ma": "MA",
}

VALUE_NAME_ALIASES: dict[str, str] = {
    # General
    "NETWORK": "N",
    "ADJACENT": "A",
    "ADJACENT_NETWORK": "A",
    "LOCAL": "L",
    "PHYSICAL": "P",
    "LOW": "L",
    "HIGH": "H",
    "NONE": "N",
    "REQUIRED": "R",
    "UNCHANGED": "U",
    "CHANGED": "C",
    "NOT_DEFINED": "X",
    "UNPROVEN": "U",
    "PROOF_OF_CONCEPT": "P",
    "PROOF-OF-CONCEPT": "P",
    "FUNCTIONAL": "F",
    "OFFICIAL_FIX": "O",
    "TEMPORARY_FIX": "T",
    "WORKAROUND": "W",
    "UNAVAILABLE": "U",
    "UNKNOWN": "U",
    "REASONABLE": "R",
    "CONFIRMED": "C",
    "MEDIUM": "M",
}


def cvss_roundup(input_val: float) -> float:
    """Smallest number, specified to one decimal place, equal to or higher than input.

    Implements FIRST CVSS v3.1 Appendix A floating point precision handling:
    int_input = round(input * 100000)
    if (int_input % 10000 == 0): return int_input / 100000.0
    else: return (floor(int_input / 10000) + 1) / 10.0
    """
    if input_val <= 0.0:
        return 0.0
    int_input = round(input_val * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    else:
        return (math.floor(int_input / 10000) + 1) / 10.0


def score_to_severity(score: float) -> str:
    """Map numeric score to CVSS v3.1 qualitative severity rating."""
    if score == 0.0:
        return "NONE"
    elif 0.1 <= score <= 3.9:
        return "LOW"
    elif 4.0 <= score <= 6.9:
        return "MEDIUM"
    elif 7.0 <= score <= 8.9:
        return "HIGH"
    elif 9.0 <= score <= 10.0:
        return "CRITICAL"
    else:
        raise ValueError(f"Score {score} is out of CVSS range [0.0, 10.0]")


def normalize_metric_key(key: str) -> str:
    """Normalize metric key to canonical abbreviation."""
    k = key.strip().lower()
    if k in METRIC_NAME_ALIASES:
        return METRIC_NAME_ALIASES[k]
    upper = key.strip().upper()
    if upper in VALID_METRIC_VALUES:
        return upper
    raise KeyError(f"Unknown CVSS metric key: {key}")


def normalize_metric_value(val: str) -> str:
    """Normalize metric value string to canonical single-character code."""
    v_clean = val.strip().upper()
    if v_clean in VALUE_NAME_ALIASES:
        return VALUE_NAME_ALIASES[v_clean]
    return v_clean


def parse_cvss_vector(vector_str: str) -> dict[str, str]:
    """Parse CVSS v3.1 vector string into metric dictionary."""
    if not isinstance(vector_str, str):
        raise TypeError("Vector string must be a string")

    clean_str = vector_str.strip()
    prefix = "CVSS:3.1"
    if not clean_str.startswith(f"{prefix}/"):
        if clean_str.startswith("CVSS:3.0/"):
            raise ValueError("CVSS 3.0 vector provided; this engine strictly requires CVSS:3.1")
        raise ValueError(f"Vector string must start with '{prefix}/'")

    body = clean_str[len(prefix) + 1 :]
    parts = body.split("/")
    metrics: dict[str, str] = {}
    seen_keys: set[str] = set()

    for part in parts:
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"Malformed metric pair: '{part}' (missing ':')")
        k_raw, v_raw = part.split(":", 1)
        k = k_raw.strip().upper()
        v = v_raw.strip().upper()

        if k not in VALID_METRIC_VALUES:
            raise ValueError(f"Unknown CVSS v3.1 metric key: '{k}'")
        if k in seen_keys:
            raise ValueError(f"Duplicate metric key in vector string: '{k}'")
        if v not in VALID_METRIC_VALUES[k]:
            raise ValueError(
                f"Invalid value '{v}' for metric '{k}'. Allowed: {sorted(VALID_METRIC_VALUES[k])}"
            )

        metrics[k] = v
        seen_keys.add(k)

    # Validate that mandatory base metrics are present
    missing_base = BASE_METRIC_KEYS - set(metrics.keys())
    if missing_base:
        raise ValueError(f"Missing mandatory base metrics: {sorted(missing_base)}")

    return metrics


def validate_cvss_vector(vector_str: str) -> tuple[bool, list[str]]:
    """Validate a CVSS v3.1 vector string; returns (is_valid, list_of_errors)."""
    errors: list[str] = []
    try:
        parse_cvss_vector(vector_str)
        return (True, [])
    except Exception as exc:
        errors.append(str(exc))
        return (False, errors)


def generate_cvss_vector(**kwargs: Any) -> str:
    """Generate canonical CVSS:3.1 vector string from metric arguments.

    Supports short keys (e.g. av='N', ac='L') or full metric names
    (e.g. attack_vector='NETWORK', attack_complexity='LOW').
    Omitted temporal or environmental metrics default to 'X' and are omitted
    from the canonical vector unless explicitly provided.
    """
    raw_metrics: dict[str, str] = {}
    for k, v in kwargs.items():
        if v is None:
            continue
        try:
            canon_k = normalize_metric_key(str(k))
            canon_v = normalize_metric_value(str(v))
        except KeyError as err:
            raise ValueError(str(err)) from err

        if canon_v not in VALID_METRIC_VALUES[canon_k]:
            raise ValueError(
                f"Invalid value '{canon_v}' for metric '{canon_k}'. "
                f"Allowed: {sorted(VALID_METRIC_VALUES[canon_k])}"
            )
        raw_metrics[canon_k] = canon_v

    missing_base = BASE_METRIC_KEYS - set(raw_metrics.keys())
    if missing_base:
        raise ValueError(f"Missing mandatory base metrics to generate vector: {sorted(missing_base)}")

    # Build canonical string in official order
    parts = ["CVSS:3.1"]
    for k in CANONICAL_METRIC_ORDER:
        if k in raw_metrics:
            val = raw_metrics[k]
            # Omit X (Not Defined) for optional temporal/environmental unless explicitly requested
            if k in BASE_METRIC_KEYS or val != "X":
                parts.append(f"{k}:{val}")

    return "/".join(parts)


@dataclass
class CVSSResult:
    """Structured result of formal CVSS v3.1 calculations."""

    version: str
    vector_string: str
    canonical_vector: str
    base_score: float
    base_severity: str
    temporal_score: float | None
    temporal_severity: str | None
    environmental_score: float | None
    environmental_severity: str | None
    overall_score: float
    overall_severity: str
    sub_scores: dict[str, Any]
    metrics: dict[str, dict[str, str]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "vector_string": self.vector_string,
            "canonical_vector": self.canonical_vector,
            "base_score": self.base_score,
            "base_severity": self.base_severity,
            "temporal_score": self.temporal_score,
            "temporal_severity": self.temporal_severity,
            "environmental_score": self.environmental_score,
            "environmental_severity": self.environmental_severity,
            "overall_score": self.overall_score,
            "overall_severity": self.overall_severity,
            "sub_scores": self.sub_scores,
            "metrics": self.metrics,
        }


class CVSSCalculator:
    """Full-featured CVSS v3.1 calculation and vector manipulation engine."""

    @classmethod
    def calculate_from_metrics(cls, metrics: Mapping[str, str]) -> CVSSResult:
        """Calculate CVSS v3.1 Base, Temporal, and Environmental scores from parsed metrics."""
        # Ensure mandatory base metrics exist
        missing = BASE_METRIC_KEYS - set(metrics.keys())
        if missing:
            raise ValueError(f"Missing mandatory base metrics: {sorted(missing)}")

        # Extract base values
        av = metrics["AV"]
        ac = metrics["AC"]
        pr = metrics["PR"]
        ui = metrics["UI"]
        s = metrics["S"]
        c = metrics["C"]
        i = metrics["I"]
        a = metrics["A"]

        # 1. Base Score Calculation
        iss = 1.0 - ((1.0 - CIA_WEIGHTS[c]) * (1.0 - CIA_WEIGHTS[i]) * (1.0 - CIA_WEIGHTS[a]))

        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        pr_weight = PR_WEIGHTS[s][pr]
        exploitability = 8.22 * AV_WEIGHTS[av] * AC_WEIGHTS[ac] * pr_weight * UI_WEIGHTS[ui]

        if impact <= 0.0:
            base_score = 0.0
        else:
            if s == "U":
                base_score = cvss_roundup(min(impact + exploitability, 10.0))
            else:
                base_score = cvss_roundup(min(1.08 * (impact + exploitability), 10.0))

        base_severity = score_to_severity(base_score)

        # 2. Temporal Score Calculation
        has_temporal = any(k in metrics and metrics[k] != "X" for k in TEMPORAL_METRIC_KEYS)
        e = metrics.get("E", "X")
        rl = metrics.get("RL", "X")
        rc = metrics.get("RC", "X")

        t_mult = E_WEIGHTS[e] * RL_WEIGHTS[rl] * RC_WEIGHTS[rc]
        if has_temporal:
            temporal_score = cvss_roundup(base_score * t_mult)
            temporal_severity = score_to_severity(temporal_score)
        else:
            temporal_score = None
            temporal_severity = None

        # 3. Environmental Score Calculation
        has_environmental = any(k in metrics and metrics[k] != "X" for k in ENVIRONMENTAL_METRIC_KEYS)
        cr = metrics.get("CR", "X")
        ir = metrics.get("IR", "X")
        ar = metrics.get("AR", "X")
        mav = metrics.get("MAV", "X")
        mac = metrics.get("MAC", "X")
        mpr = metrics.get("MPR", "X")
        mui = metrics.get("MUI", "X")
        ms = metrics.get("MS", "X")
        mc = metrics.get("MC", "X")
        mi = metrics.get("MI", "X")
        ma = metrics.get("MA", "X")

        # Determine effective values for environmental metrics
        eff_scope = s if ms == "X" else ms
        eff_mc = CIA_WEIGHTS[c] if mc == "X" else CIA_WEIGHTS[mc]
        eff_mi = CIA_WEIGHTS[i] if mi == "X" else CIA_WEIGHTS[mi]
        eff_ma = CIA_WEIGHTS[a] if ma == "X" else CIA_WEIGHTS[ma]

        eff_mav = AV_WEIGHTS[av] if mav == "X" else AV_WEIGHTS[mav]
        eff_mac = AC_WEIGHTS[ac] if mac == "X" else AC_WEIGHTS[mac]
        eff_mui = UI_WEIGHTS[ui] if mui == "X" else UI_WEIGHTS[mui]

        eff_pr_val = pr if mpr == "X" else mpr
        eff_mpr = PR_WEIGHTS[eff_scope][eff_pr_val]

        miss = min(
            1.0 - (
                (1.0 - REQ_WEIGHTS[cr] * eff_mc)
                * (1.0 - REQ_WEIGHTS[ir] * eff_mi)
                * (1.0 - REQ_WEIGHTS[ar] * eff_ma)
            ),
            0.915,
        )

        if eff_scope == "U":
            mod_impact = 6.42 * miss
        else:
            mod_impact = 7.52 * (miss - 0.029) - 3.25 * ((miss * 0.9731 - 0.02) ** 13)

        mod_exploitability = 8.22 * eff_mav * eff_mac * eff_mpr * eff_mui

        if has_environmental:
            if mod_impact <= 0.0:
                environmental_score = 0.0
            else:
                if eff_scope == "U":
                    environmental_score = cvss_roundup(
                        cvss_roundup(min(mod_impact + mod_exploitability, 10.0)) * t_mult
                    )
                else:
                    environmental_score = cvss_roundup(
                        cvss_roundup(min(1.08 * (mod_impact + mod_exploitability), 10.0)) * t_mult
                    )
            environmental_severity = score_to_severity(environmental_score)
        else:
            environmental_score = None
            environmental_severity = None

        # Overall score determination
        if environmental_score is not None:
            overall_score = environmental_score
            overall_severity = environmental_severity or base_severity
        elif temporal_score is not None:
            overall_score = temporal_score
            overall_severity = temporal_severity or base_severity
        else:
            overall_score = base_score
            overall_severity = base_severity

        # Canonical vector representation
        canonical_vector = generate_cvss_vector(**metrics)

        sub_scores = {
            "iss": round(iss, 5),
            "impact": round(impact, 5),
            "exploitability": round(exploitability, 5),
            "miss": round(miss, 5) if has_environmental else None,
            "modified_impact": round(mod_impact, 5) if has_environmental else None,
            "modified_exploitability": (
                round(mod_exploitability, 5) if has_environmental else None
            ),
        }

        base_dict = {k: metrics[k] for k in CANONICAL_METRIC_ORDER if k in BASE_METRIC_KEYS and k in metrics}
        temp_dict = {k: metrics[k] for k in CANONICAL_METRIC_ORDER if k in TEMPORAL_METRIC_KEYS and k in metrics}
        env_dict = {
            k: metrics[k]
            for k in CANONICAL_METRIC_ORDER
            if k in ENVIRONMENTAL_METRIC_KEYS and k in metrics
        }

        return CVSSResult(
            version="3.1",
            vector_string=canonical_vector,
            canonical_vector=canonical_vector,
            base_score=base_score,
            base_severity=base_severity,
            temporal_score=temporal_score,
            temporal_severity=temporal_severity,
            environmental_score=environmental_score,
            environmental_severity=environmental_severity,
            overall_score=overall_score,
            overall_severity=overall_severity,
            sub_scores=sub_scores,
            metrics={
                "base": base_dict,
                "temporal": temp_dict,
                "environmental": env_dict,
            },
        )

    @classmethod
    def calculate_from_vector(cls, vector_str: str) -> CVSSResult:
        """Parse vector string and compute all CVSS v3.1 scores."""
        metrics = parse_cvss_vector(vector_str)
        res = cls.calculate_from_metrics(metrics)
        # Retain original vector string in result for reference
        res.vector_string = vector_str.strip()
        return res


def compute_cvss_score(vector_str: str) -> dict[str, Any]:
    """Compute formal CVSS v3.1 scores from a vector string.

    Returns dictionary containing base_score, temporal_score, environmental_score,
    overall_score, severities, sub_scores, and parsed metrics.
    """
    res = CVSSCalculator.calculate_from_vector(vector_str)
    return res.as_dict()


__all__ = [
    "CANONICAL_METRIC_ORDER",
    "CVSSCalculator",
    "CVSSResult",
    "compute_cvss_score",
    "cvss_roundup",
    "generate_cvss_vector",
    "parse_cvss_vector",
    "score_to_severity",
    "validate_cvss_vector",
]
