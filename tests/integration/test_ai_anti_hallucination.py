"""Unit and integration test suite for the Anti-Hallucination Grounding Gate."""

from __future__ import annotations

import unittest
from typing import Any

from services.ai_analysis_worker import Provider
from services.ai_analysis_worker.reasoning import (
    AntiHallucinationGate,
    ClaimType,
    GroundingCorpusIndex,
    synthesize_threat_model,
)


class MockHallucinatingProvider(Provider):
    def __init__(self, output: str) -> None:
        self.name = "hallucinating_llm"
        self._output = output.encode("utf-8")

    def propose(self, prompt: dict) -> bytes:
        return self._output


class MockGroundedProvider(Provider):
    def __init__(self, output: str) -> None:
        self.name = "grounded_llm"
        self._output = output.encode("utf-8")

    def propose(self, prompt: dict) -> bytes:
        return self._output


class AntiHallucinationGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AntiHallucinationGate(strict_mode=True)
        self.target_url = "https://example.com"
        self.observations: list[dict[str, Any]] = [
            {
                "kind": "crawler_summary",
                "endpoints": ["/api/v1/auth", "/api/v1/users", "/profile"],
                "parameters": ["token", "id"],
                "evidence_sha256": "a" * 64,
            },
            {
                "kind": "network_service",
                "address": "93.184.216.34",
                "port": 443,
                "service": "https",
                "evidence_sha256": "b" * 64,
            },
        ]
        self.findings: list[dict[str, Any]] = [
            {
                "fingerprint": "zap:10020",
                "title": "X-Frame-Options Header Missing",
                "severity": "medium",
                "category": "clickjacking",
                "cwe_id": "CWE-693",
                "affected_url": "https://example.com/profile",
                "evidence_sha256": "c" * 64,
            },
            {
                "fingerprint": "nuclei:cors-wildcard",
                "title": "Insecure CORS Wildcard Header",
                "severity": "low",
                "category": "http_headers",
                "cwe_id": "CWE-942",
                "affected_url": "https://example.com/api/v1/users",
                "evidence_sha256": "d" * 64,
            },
        ]
        self.corpus = GroundingCorpusIndex(
            findings=self.findings,
            observations=self.observations,
            target_url=self.target_url,
        )

    def test_legitimate_grounded_narrative_passes_gate(self) -> None:
        """A truthful narrative citing verified findings and real endpoints must pass with 1.0 ratio."""
        truthful_narrative = (
            "Assessment of https://example.com revealed missing security headers on /profile, "
            "specifically clickjacking risks due to absent frame controls (CWE-693). "
            "Furthermore, /api/v1/users exhibited permissive cross-origin configuration."
        )

        verdict = self.gate.verify_narrative(
            narrative=truthful_narrative,
            corpus=self.corpus,
            fallback_narrative="Deterministic fallback",
        )

        self.assertTrue(verdict.is_grounded)
        self.assertEqual(len(verdict.hallucinated_claims), 0)
        self.assertGreaterEqual(len(verdict.verified_claims), 2)
        self.assertEqual(verdict.grounding_ratio, 1.0)
        self.assertEqual(verdict.sanitized_narrative, truthful_narrative)
        self.assertIn("zap:10020", verdict.cited_fingerprints)
        self.assertIn("c" * 64, verdict.cited_evidence_hashes)
        self.assertIn("merkle_seal_sha256", verdict.provenance_manifest)

    def test_phantom_critical_vulnerability_rejected(self) -> None:
        """Fabricating high-impact vulnerabilities not in findings must fail the gate."""
        hallucinated_narrative = (
            "Critical finding: Detected unauthenticated remote code execution via SpEL injection on /api/v1/auth. "
            "Attacker can achieve root access."
        )

        verdict = self.gate.verify_narrative(
            narrative=hallucinated_narrative,
            corpus=self.corpus,
            fallback_narrative="Verified deterministic summary",
        )

        self.assertFalse(verdict.is_grounded)
        self.assertGreaterEqual(len(verdict.hallucinated_claims), 1)
        vuln_hallucinations = [
            h for h in verdict.hallucinated_claims if h.claim.claim_type == ClaimType.VULNERABILITY
        ]
        self.assertTrue(any("remote code execution" in h.claim.claim_text for h in vuln_hallucinations))
        self.assertIn("GROUNDING REJECTION", verdict.sanitized_narrative)

    def test_fabricated_endpoint_rejected(self) -> None:
        """Fabricating un-crawled endpoints must be flagged and rejected."""
        hallucinated_endpoint = "During testing of https://example.com, missing security headers were discovered on /admin/supersecret/db_dump."

        verdict = self.gate.verify_narrative(
            narrative=hallucinated_endpoint,
            corpus=self.corpus,
            fallback_narrative="Safe fallback",
        )

        self.assertFalse(verdict.is_grounded)
        endpoint_hallucinations = [
            h for h in verdict.hallucinated_claims if h.claim.claim_type == ClaimType.ENDPOINT
        ]
        self.assertTrue(
            any("/admin/supersecret/db_dump" in h.claim.claim_text for h in endpoint_hallucinations)
        )

    def test_severity_inflation_rejected(self) -> None:
        """Asserting 'critical vulnerability' when 0 critical findings exist must fail."""
        inflated_narrative = (
            "We discovered a critical vulnerability on /profile related to missing security headers."
        )

        verdict = self.gate.verify_narrative(
            narrative=inflated_narrative,
            corpus=self.corpus,
            fallback_narrative="Safe fallback",
        )

        self.assertFalse(verdict.is_grounded)
        sev_hallucinations = [
            h for h in verdict.hallucinated_claims if h.claim.claim_type == ClaimType.SEVERITY
        ]
        self.assertEqual(len(sev_hallucinations), 1)
        self.assertIn("0 critical findings exist", sev_hallucinations[0].reason)

    def test_synthesize_threat_model_with_hallucinating_provider(self) -> None:
        """End-to-end integration: synthesize_threat_model sanitizes hallucinating provider output."""
        hallucinating_provider = MockHallucinatingProvider(
            "Found critical remote code execution on /ghost_endpoint leading to full database compromise."
        )

        result = synthesize_threat_model(
            target_url=self.target_url,
            findings=self.findings,
            observations=self.observations,
            provider=hallucinating_provider,
        )

        verdict = result["grounding_verdict"]
        self.assertFalse(verdict["is_grounded"])
        self.assertIn("GROUNDING REJECTION", result["ai_executive_summary"])


if __name__ == "__main__":
    unittest.main()
