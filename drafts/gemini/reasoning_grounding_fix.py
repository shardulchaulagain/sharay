"""Reference fix and drop-in integration of Anti-Hallucination Grounding Gate into reasoning.py.

Shows how generate_defensive_root_cause_analysis invokes AntiHallucinationGate, verifies
LLM responses before adoption, rejects hallucinations fail-closed, and records cryptographic
grounding audits.
"""

from __future__ import annotations

import logging
from typing import Any

from drafts.gemini.anti_hallucination_gate import (
    AntiHallucinationGate,
    GroundingCorpusIndex,
    GroundingVerdict,
)
from services.ai_analysis_worker import Provider
from services.ai_analysis_worker.reasoning import (
    AttackGraph,
)
from services.ai_analysis_worker.reasoning import (
    generate_defensive_root_cause_analysis as original_generate_analysis,
)

logger = logging.getLogger(__name__)


def generate_grounded_defensive_root_cause_analysis(
    graph: AttackGraph,
    findings: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    target_url: str = "",
    provider: Provider | None = None,
    strict_grounding: bool = True,
) -> dict[str, Any]:
    """Execute root cause analysis with strict anti-hallucination validation on any AI narrative."""
    # Run the underlying deterministic graph and baseline analysis
    analysis = original_generate_analysis(
        graph=graph,
        findings=findings,
        observations=observations,
        target_url=target_url,
        provider=None,  # Run baseline deterministically first
    )

    deterministic_summary = analysis.get("ai_executive_summary", "")

    # Index the ground truth corpus
    corpus = GroundingCorpusIndex(
        findings=findings,
        observations=observations,
        target_url=target_url,
    )
    gate = AntiHallucinationGate(strict_mode=strict_grounding)

    grounding_audit: dict[str, Any] = {
        "status": "deterministic_only",
        "is_grounded": True,
        "grounding_ratio": 1.0,
        "hallucinations_detected": 0,
    }
    provenance_manifest: dict[str, Any] = {}

    if provider is not None and provider.name != "none":
        try:
            finding_bullets = "\n".join(
                f"- [{f.get('severity', 'medium').upper()}] {f.get('title')}: {f.get('description', '')[:100]}"
                for f in findings[:10]
            )
            prompt = {
                "objective": f"Synthesize executive threat modeling and defensive root-cause summary for {target_url}.",
                "instructions": (
                    "Provide a professional 2-3 paragraph executive summary of the target's defensive security posture, "
                    "root causes, and prioritization for the White Team / C-Team. Do not include markdown code fences."
                ),
                "evidence": [
                    f"Target: {target_url}",
                    f"Overall Posture Score: {analysis.get('posture_score')}/100",
                    f"Total Nodes: {len(graph.nodes)}, Total Edges: {len(graph.edges)}",
                    f"Findings:\n{finding_bullets}",
                ],
            }
            res_bytes = provider.propose(prompt)
            if res_bytes:
                ai_text = res_bytes.decode("utf-8", errors="replace").strip()
                if ai_text:
                    verdict: GroundingVerdict = gate.verify_narrative(
                        narrative=ai_text,
                        corpus=corpus,
                        fallback_narrative=deterministic_summary,
                    )
                    grounding_audit = verdict.to_dict()

                    if verdict.is_grounded:
                        analysis["ai_executive_summary"] = verdict.sanitized_narrative
                        provenance_manifest = verdict.provenance_manifest
                    else:
                        logger.warning(
                            "AI analysis output failed anti-hallucination grounding gate: %s",
                            verdict.rejection_reason,
                        )
                        # Revert strictly to deterministic summary
                        analysis["ai_executive_summary"] = deterministic_summary
        except Exception as exc:
            logger.error("AI provider proposal failed: %s", exc)
            grounding_audit = {
                "status": "provider_error",
                "error": str(exc),
                "is_grounded": True,
            }

    analysis["ai_grounding_audit"] = grounding_audit
    if provenance_manifest:
        analysis["provenance_manifest"] = provenance_manifest

    return analysis
