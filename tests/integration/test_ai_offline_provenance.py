"""Unit tests for Offline Local-Model Reasoning Adapter & Confidence Calibration Engine."""

from __future__ import annotations

import json
import unittest
from urllib.request import Request

from services.ai_analysis_worker.provenance import (
    ConfidenceCalibrationEngine,
    LocalInferenceBackend,
    LocalOfflineReasoningProvider,
    ProvenanceLink,
    VerificationState,
)


class TestOfflineReasoningAndProvenance(unittest.TestCase):
    def setUp(self) -> None:
        self.calibrator = ConfidenceCalibrationEngine()

    def test_calibrated_confidence_confirmed_reproducible_with_evidence(self) -> None:
        evidence = [
            {
                "sha256": "a" * 64,
                "target_entity": "vulnerable_param_id",
                "source_uri": "https://target.local/vuln?id=1",
                "observation_id": "obs-101",
            }
        ]
        result = self.calibrator.calibrate(
            claim_text="SQL injection detected in 'id' parameter",
            raw_confidence=0.95,
            verification_state=VerificationState.CONFIRMED_REPRODUCIBLE,
            evidence_records=evidence,
        )
        self.assertEqual(result.verification_state, VerificationState.CONFIRMED_REPRODUCIBLE)
        self.assertAlmostEqual(result.calibrated_confidence, 0.95, places=2)
        self.assertEqual(len(result.provenance_links), 1)
        self.assertEqual(result.provenance_links[0].evidence_sha256, "a" * 64)
        self.assertIn("Verified against 1 cryptographic evidence", result.calibration_basis)

    def test_calibrated_confidence_unverified_penalty(self) -> None:
        result = self.calibrator.calibrate(
            claim_text="Speculative RCE via file upload",
            raw_confidence=0.90,
            verification_state=VerificationState.UNVERIFIED,
            evidence_records=None,
        )
        self.assertEqual(result.verification_state, VerificationState.UNVERIFIED)
        self.assertAlmostEqual(result.calibrated_confidence, 0.135, places=3)
        self.assertIn("Base weight 0.15", result.calibration_basis)

    def test_calibrated_confidence_missing_evidence_penalty(self) -> None:
        result = self.calibrator.calibrate(
            claim_text="Unsubstantiated SSRF flaw",
            raw_confidence=1.0,
            verification_state=VerificationState.CONFIRMED_REPRODUCIBLE,
            evidence_records=[],
        )
        self.assertAlmostEqual(result.calibrated_confidence, 0.70, places=2)
        self.assertIn("Lacked direct evidence records", result.calibration_basis)

    def test_provenance_link_serialization(self) -> None:
        link = ProvenanceLink(
            claim_text="XSS in query parameter",
            target_entity="q",
            evidence_sha256="b" * 64,
            source_uri="http://test.local/search?q=foo",
            observation_id="obs-202",
            verification_state=VerificationState.SUPPORTING_SIGNAL,
        )
        d = link.to_dict()
        self.assertEqual(d["claim_text"], "XSS in query parameter")
        self.assertEqual(d["evidence_sha256"], "b" * 64)
        self.assertEqual(d["verification_state"], "supporting_signal")

    def test_ollama_mock_transport_reasoning(self) -> None:
        recorded_requests: list[Request] = []

        def mock_ollama_transport(req: Request) -> bytes:
            recorded_requests.append(req)
            if "api/tags" in req.full_url:
                return json.dumps({"models": [{"name": "mistral-7b-instruct"}]}).encode("utf-8")
            return json.dumps(
                {
                    "response": "Analysis: The target input lacks sanitization; potential blind SQLi.",
                    "eval_count": 42,
                }
            ).encode("utf-8")

        provider = LocalOfflineReasoningProvider(
            backend=LocalInferenceBackend.OLLAMA,
            base_url="http://127.0.0.1:11434",
            model_name="mistral-7b-instruct",
            transport_fn=mock_ollama_transport,
        )

        health = provider.check_health()
        self.assertTrue(health["healthy"])
        self.assertEqual(health["backend"], "ollama")

        response = provider.generate_reasoning(
            prompt="Evaluate findings for SQL injection.",
            system_instructions="You are a strict security auditor.",
        )
        self.assertEqual(response.backend, LocalInferenceBackend.OLLAMA)
        self.assertEqual(response.model_name, "mistral-7b-instruct")
        self.assertIn("blind SQLi", response.content)
        self.assertEqual(response.tokens_generated, 42)
        self.assertFalse(response.is_offline_deterministic)

    def test_vllm_mock_transport_reasoning(self) -> None:
        def mock_vllm_transport(req: Request) -> bytes:
            if "v1/models" in req.full_url:
                return json.dumps({"data": [{"id": "llama-3-8b"}]}).encode("utf-8")
            return json.dumps(
                {
                    "choices": [{"message": {"content": "VLLM identified auth bypass flaw."}}],
                    "usage": {"total_tokens": 15},
                }
            ).encode("utf-8")

        provider = LocalOfflineReasoningProvider(
            backend=LocalInferenceBackend.VLLM,
            base_url="http://127.0.0.1:8000",
            model_name="llama-3-8b",
            transport_fn=mock_vllm_transport,
        )

        health = provider.check_health()
        self.assertTrue(health["healthy"])

        response = provider.generate_reasoning("Test auth bypass.")
        self.assertEqual(response.backend, LocalInferenceBackend.VLLM)
        self.assertIn("auth bypass", response.content)
        self.assertEqual(response.tokens_generated, 15)

    def test_air_gapped_fallback_on_unreachable_endpoint(self) -> None:
        def failing_transport(req: Request) -> bytes:
            raise ConnectionRefusedError("Connection refused to 127.0.0.1:11434")

        provider = LocalOfflineReasoningProvider(
            backend=LocalInferenceBackend.OLLAMA,
            base_url="http://127.0.0.1:11434",
            model_name="mistral-7b-instruct",
            transport_fn=failing_transport,
        )

        response = provider.generate_reasoning("Evaluate SQL injection in user parameter.")
        self.assertEqual(response.backend, LocalInferenceBackend.AIR_GAPPED_FALLBACK)
        self.assertTrue(response.is_offline_deterministic)
        self.assertIn("Air-Gapped Deterministic Rule Synthesis", response.content)
        self.assertIn("SQL injection vector identified", response.content)


if __name__ == "__main__":
    unittest.main()
