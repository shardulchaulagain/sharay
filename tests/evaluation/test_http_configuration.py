"""The evaluation harness's arithmetic, and the adapter's measured results on corpus v1."""

import json
import tempfile
import unittest
from pathlib import Path

from tests.evaluation.http_configuration import CORPUS, evaluate

CHECKS = {
    "missing_csp",
    "missing_nosniff",
    "missing_referrer_policy",
    "missing_frame_policy",
    "cookie_httponly",
}
# The four ineffective-value misses first measured on this corpus were fixed in the adapter
# on October 12; none is tolerated now, so any miss fails.
KNOWN_MISSES: set[tuple[str, str]] = set()
CORPUS_V2 = CORPUS.with_name("http_configuration.v2.json")
# Adapter 1.1.1 disagreed on eight 'browser-parsing' cases (two false alarms, six misses);
# 1.1.2 fixed them on October 12. None is tolerated now, so any disagreement fails.
V2_FALSE_ALARMS: set[tuple[str, str]] = set()
V2_MISSES: set[tuple[str, str]] = set()


class HarnessTests(unittest.TestCase):
    def test_scoring_counts_correct_unexpected_and_missed_checks(self):
        corpus = {
            "id": "synthetic",
            "version": 1,
            "cases": [
                {"id": "both", "subset": "a", "response_headers": [], "expected": ["x", "y"]},
                {"id": "none", "subset": "b", "response_headers": [], "expected": []},
                {"id": "failed", "subset": "b", "response_headers": [], "expected": ["x"]},
            ],
        }
        reported = {"both": ["x", "z"], "none": [], "failed": []}

        def scanner(_scope, url, _cancelled, _emit):
            case = url.rsplit("/", 1)[1]
            findings = [{"evidence": {"check": check}} for check in reported[case]]
            return {"outcome": "failed" if case == "failed" else "completed", "findings": findings}

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "corpus.json"
            path.write_text(json.dumps(corpus))
            report = evaluate(path, scanner)
        self.assertEqual(
            report["totals"],
            {
                "cases": 3,
                "true_positives": 1,
                "false_positives": 1,
                "false_negatives": 2,
                "precision": 0.5,
                "recall": 0.3333,
            },
        )
        # Nothing expected and nothing reported is undefined, not a perfect score.
        self.assertEqual(report["by_subset"]["a"]["recall"], 0.5)
        self.assertIsNone(report["by_subset"]["b"]["precision"])
        self.assertEqual(report["incomplete_scans"], ["failed"])
        self.assertEqual(report["cases"][0]["unexpected"], ["z"])

    def test_corpus_labels_are_well_formed(self):
        for path in (CORPUS, CORPUS_V2):
            corpus = json.loads(path.read_text())
            identifiers = [case["id"] for case in corpus["cases"]]
            self.assertEqual(len(identifiers), len(set(identifiers)))
            for case in corpus["cases"]:
                with self.subTest(case["id"]):
                    self.assertRegex(case["id"], r"^[a-z0-9-]+$")
                    self.assertLessEqual(set(case["expected"]), CHECKS)
                    self.assertIn(case["subset"], {"clear", "ineffective-value", "browser-parsing"})
                    # A label that depends on how browsers treat a value must say why.
                    self.assertEqual("basis" in case, case["subset"] != "clear")


class MeasuredAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = evaluate()

    def test_every_case_was_actually_scanned(self):
        self.assertEqual(self.report["incomplete_scans"], [])
        self.assertEqual(self.report["totals"]["cases"], 16)
        self.assertEqual(len(self.report["corpus"]["sha256"]), 64)

    def test_plainly_absent_or_valid_headers_are_classified_exactly(self):
        clear = self.report["by_subset"]["clear"]
        self.assertEqual((clear["false_positives"], clear["false_negatives"]), (0, 0))
        self.assertEqual((clear["precision"], clear["recall"]), (1.0, 1.0))

    def test_no_check_is_reported_where_the_protection_exists(self):
        self.assertEqual(self.report["totals"]["false_positives"], 0)

    def test_misses_are_limited_to_the_reported_ineffective_value_gaps(self):
        misses = {(case["id"], check) for case in self.report["cases"] for check in case["missed"]}
        self.assertLessEqual(misses, KNOWN_MISSES)


class MeasuredAdapterOnCorpusV2Tests(unittest.TestCase):
    """Thirty cases by another author plus six of ours; three of the thirty labels were corrected."""

    @classmethod
    def setUpClass(cls):
        cls.report = evaluate(CORPUS_V2)

    def test_every_case_was_actually_scanned(self):
        self.assertEqual(self.report["incomplete_scans"], [])
        self.assertEqual(self.report["totals"]["cases"], 36)

    def test_plain_and_ineffective_value_cases_are_classified_exactly(self):
        for name in ("clear", "ineffective-value"):
            subset = self.report["by_subset"][name]
            self.assertEqual((subset["false_positives"], subset["false_negatives"]), (0, 0), name)

    def test_no_disagreement_is_tolerated_on_any_subset(self):
        cases = self.report["cases"]
        self.assertLessEqual({(c["id"], check) for c in cases for check in c["unexpected"]}, V2_FALSE_ALARMS)
        self.assertLessEqual({(c["id"], check) for c in cases for check in c["missed"]}, V2_MISSES)
        self.assertEqual(self.report["totals"]["true_positives"], 29)


if __name__ == "__main__":
    unittest.main()
