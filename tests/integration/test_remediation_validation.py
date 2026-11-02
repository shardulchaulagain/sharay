"""Remediation-patch validation (roadmap P0-E4 / F08).

The validator performs structural checks only, so it must label patches as suggestions
(`is_valid` reflects structure, `deployable` is never True from heuristics) and reject
structurally-empty or unrecognized content.
"""

import unittest

from services.ai_analysis_worker.reasoning import generate_defensive_root_cause_analysis
from services.ai_analysis_worker.remediation import RemediationValidator


class RemediationValidationWiringTests(unittest.TestCase):
    def test_generated_patches_are_structurally_valid_but_only_suggestions(self):
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
                self.assertFalse(result.deployable, "heuristic validation must never claim deployable")
                self.assertIn("suggestion", result.details.lower())

    def test_nothing_is_ever_deployable_from_heuristic_validation(self):
        cases = [
            ("import os\n", "python"),
            ('{"a": 1}', "json"),
            ("server { add_header X 1; }", "nginx"),
            ("--- a\n+++ b\n@@ -1 +1,2 @@\n x\n+y\n", "diff"),
        ]
        for code, lang in cases:
            with self.subTest(lang=lang):
                result = RemediationValidator.validate_patch(code, lang)
                self.assertTrue(result.is_valid)
                self.assertFalse(result.deployable)

    def test_overstated_content_is_rejected(self):
        """E04: a hunk-less diff, nonsensical config and an unknown language are not valid."""
        bad = [
            ("--- a\n+++ b\n", "diff"),  # header, no hunk — changes nothing
            ("this is not nginx config at all", "nginx"),  # no blocks
            ("@@@ random $$$ content", "cobol"),  # unrecognized language
            ("   ", "python"),  # empty
        ]
        for code, lang in bad:
            with self.subTest(lang=lang, code=code[:20]):
                result = RemediationValidator.validate_patch(code, lang)
                self.assertFalse(result.is_valid)
                self.assertFalse(result.deployable)


if __name__ == "__main__":
    unittest.main()
