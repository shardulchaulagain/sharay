"""The AI investigation's remediation patches must pass the deployability validator.

Covers the wiring in aegis/api.py (run_ai_investigation) where every patch's diff is validated
by RemediationValidator before the UI can present it as deployable.
"""

import unittest

from services.ai_analysis_worker.reasoning import generate_defensive_root_cause_analysis
from services.ai_analysis_worker.remediation import RemediationValidator


class RemediationValidationWiringTests(unittest.TestCase):
    def test_every_generated_patch_is_a_valid_deployable_diff(self):
        findings = [
            {
                "id": "f1",
                "title": "Missing X-Frame-Options",
                "severity": "medium",
                "category": "security_misconfiguration",
                "status": "confirmed",
                "affected_url": "http://127.0.0.1:8766/",
            }
        ]
        analysis = generate_defensive_root_cause_analysis(
            findings=findings, observations=[], target_url="http://127.0.0.1:8766/"
        )
        patches = analysis.get("remediation_patches", [])
        self.assertTrue(patches, "the engine should propose remediation patches")
        for patch in patches:
            with self.subTest(patch=patch.get("id")):
                self.assertIsInstance(patch.get("diff"), str)
                result = RemediationValidator.validate_patch(patch["diff"], "diff")
                self.assertTrue(result.is_valid, f"{patch.get('id')}: {result.syntax_error}")
                self.assertTrue(result.deployable)

    def test_the_validator_rejects_a_malformed_diff(self):
        result = RemediationValidator.validate_patch("not a diff at all", "diff")
        self.assertFalse(result.is_valid)
        self.assertFalse(result.deployable)


if __name__ == "__main__":
    unittest.main()
