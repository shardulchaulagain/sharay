"""The secret detector's measured results on corpus v1, and the harness's own scoring."""

import json
import unittest

from tests.evaluation.secret_detection import CORPUS, evaluate


class MeasuredDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = evaluate()

    def test_every_case_was_scanned(self):
        cases = json.loads(CORPUS.read_text())["cases"]
        self.assertEqual((self.report["files_scanned"], self.report["files_skipped"]), (len(cases), 0))
        self.assertEqual(self.report["totals"]["cases"], len(cases))

    def test_seeded_secrets_are_all_found_and_no_look_alike_is_reported(self):
        seeded, look_alike = self.report["by_subset"]["seeded"], self.report["by_subset"]["look-alike"]
        self.assertEqual(
            (seeded["false_negatives"], seeded["false_positives"], seeded["recall"]), (0, 0, 1.0)
        )
        self.assertEqual((look_alike["true_positives"], look_alike["false_positives"]), (0, 0))
        # Nothing expected and nothing reported is undefined, not a perfect score.
        self.assertIsNone(look_alike["precision"])

    def test_independently_labelled_corpus_v2_has_no_miss_and_no_false_alarm(self):
        # Written by another author without reading the rules; its first run scored 0.8 / 0.8.
        report = evaluate(CORPUS.with_name("secret_detection.v2.json"))
        self.assertEqual((report["files_scanned"], report["totals"]["cases"]), (30, 30))
        totals = report["totals"]
        self.assertEqual(
            (totals["true_positives"], totals["false_positives"], totals["false_negatives"]), (12, 0, 0)
        )

    def test_the_corpus_file_holds_no_contiguous_token_and_the_harness_scores_misses(self):
        from services.source_analysis_worker.secrets import detect

        self.assertEqual(detect(CORPUS.parent)["matches"], [])
        blind = evaluate(detector=lambda root: {"matches": [], "files_scanned": 0, "skipped": []})
        self.assertEqual(blind["by_subset"]["seeded"]["recall"], 0.0)
        noisy = evaluate(
            detector=lambda root: {
                "matches": [{"file": "docs/aws.md", "rule": "aws_access_key_id"}],
                "files_scanned": 1,
                "skipped": [],
            }
        )
        self.assertEqual(noisy["by_subset"]["look-alike"]["false_positives"], 1)


if __name__ == "__main__":
    unittest.main()
