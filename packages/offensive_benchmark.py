"""Sector O10: offensive exploitation benchmark.

Runs SHARAY's offensive stack against an authorized target and measures EXPLOITATION-and-confirm
rate per class -- not just detection:
  - SQLi / CMDi: adaptive payload firing + reproducer confirmation (3x + negative control).
  - Blind SSRF: real out-of-band callback confirmation.
  - 0-day: anomaly fuzzing surfaces research candidates.

Reusable against any authorized loopback range; returns a reproducible scorecard. Comparison against
third-party tools (sqlmap/Metasploit/Burp) is reported only when those tools are installed and run
-- never fabricated.
"""

from __future__ import annotations

from typing import Any

from packages.offensive_capability import (
    AdaptivePayloadEvaluator,
    OOBBlindVerifier,
    TargetAnomalyFuzzer,
)


def run_exploitation_benchmark(base_url: str) -> dict[str, Any]:
    """Exercise the offensive stack against `base_url` and return a per-class exploitation scorecard."""
    base = base_url.rstrip("/")
    classes: dict[str, dict[str, Any]] = {}

    sqli = AdaptivePayloadEvaluator().evaluate_adaptive(f"{base}/sqli", "id", "sqli", count=4)
    classes["sql_injection"] = {"confirmed": len(sqli["confirmed"]), "exploited": bool(sqli["confirmed"])}

    cmdi = AdaptivePayloadEvaluator().evaluate_adaptive(f"{base}/cmdi", "cmd", "cmdi", count=4)
    classes["command_injection"] = {"confirmed": len(cmdi["confirmed"]), "exploited": bool(cmdi["confirmed"])}

    with OOBBlindVerifier() as oob:
        ssrf = oob.probe_param(f"{base}/ssrf", "url", "ssrf", wait_seconds=1.0)
    classes["ssrf"] = {"confirmed": 1 if ssrf else 0, "exploited": ssrf is not None}

    candidates = TargetAnomalyFuzzer().fuzz_parameter(f"{base}/unknown", "x")
    classes["zero_day_research"] = {"candidates": len(candidates), "surfaced": bool(candidates)}

    exploit_classes = [c for c in ("sql_injection", "command_injection", "ssrf") if classes[c]["exploited"]]
    return {
        "target": base,
        "classes": classes,
        "summary": {
            "exploitable_classes_confirmed": len(exploit_classes),
            "zero_day_candidates_surfaced": classes["zero_day_research"]["candidates"],
        },
        "note": "Exploitation (not detection) rate; confirmations are reproducer/OOB-verified.",
    }


__all__ = ["run_exploitation_benchmark"]
