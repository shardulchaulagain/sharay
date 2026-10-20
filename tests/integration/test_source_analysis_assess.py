"""Source-analysis engine: path confinement (the trust boundary) and native detection."""

import tempfile
import unittest
from pathlib import Path

from services.source_analysis_worker.assess import (
    SourceAnalysisError,
    analyze_source_tree,
    resolve_within,
)


class ConfinementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / "source"
        (self.root / "project").mkdir(parents=True)
        self.outside = Path(self.tmp.name).resolve() / "outside"
        self.outside.mkdir()

    def test_a_directory_inside_the_root_resolves(self):
        self.assertEqual(resolve_within("project", self.root), self.root / "project")
        self.assertEqual(resolve_within(str(self.root / "project"), self.root), self.root / "project")
        self.assertEqual(resolve_within(".", self.root), self.root)

    def test_paths_outside_the_root_are_rejected(self):
        for bad in (
            str(self.outside),
            "../outside",
            "project/../../outside",
            "/etc",
            "",
            "   ",
        ):
            with self.subTest(bad=bad), self.assertRaises(SourceAnalysisError):
                resolve_within(bad, self.root)

    def test_a_symlink_escaping_the_root_is_not_followed(self):
        link = self.root / "escape"
        link.symlink_to(self.outside)
        with self.assertRaises(SourceAnalysisError):
            resolve_within("escape", self.root)
        # A symlink that stays inside the root is fine.
        inside = self.root / "alias"
        inside.symlink_to(self.root / "project")
        self.assertEqual(resolve_within("alias", self.root), self.root / "project")

    def test_a_file_or_missing_path_is_rejected(self):
        (self.root / "project" / "f.txt").write_text("x")
        with self.assertRaises(SourceAnalysisError):
            resolve_within("project/f.txt", self.root)
        with self.assertRaises(SourceAnalysisError):
            resolve_within("project/nope", self.root)

    def test_a_missing_root_rejects_cleanly(self):
        with self.assertRaises(SourceAnalysisError):
            resolve_within(".", self.root / "does-not-exist")


class AnalysisTests(unittest.TestCase):
    def test_native_analysis_finds_a_secret_and_lists_a_dependency_without_naming_an_external_tool(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            # A synthetic AWS key shape (two halves so this test file holds no contiguous token).
            (root / "config.py").write_text('AWS_KEY = "AKIA' + "IOSFODNN7REALKEY" + '"\n')
            (root / "requirements.txt").write_text("requests==2.32.0\n")
            result = analyze_source_tree(root)
        self.assertTrue(result["findings"], "expected at least one secret finding")
        finding = result["findings"][0]
        self.assertEqual(finding["category"], "secret_exposure")
        self.assertEqual(finding["status"], "suspected")
        self.assertTrue(finding["fingerprint"].startswith("sharay_secret:"))
        self.assertNotIn("gitleaks", finding["description"].lower())  # the native detector ran, not Gitleaks
        self.assertTrue(any(p["name"] == "requests" for p in result["packages"]))
        categories = {c["category"] for c in result["checks"]}
        self.assertEqual(categories, {"secret_detection", "dependency_inventory"})

    def test_a_clean_tree_yields_no_findings_but_still_reports_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / "main.py").write_text("print('nothing secret here')\n")
            result = analyze_source_tree(root)
        self.assertEqual(result["findings"], [])
        self.assertEqual(len(result["checks"]), 2)
        self.assertIn("no scanner binary ran", result["basis"])


if __name__ == "__main__":
    unittest.main()
