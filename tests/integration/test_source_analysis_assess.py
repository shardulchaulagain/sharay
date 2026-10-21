"""Source-analysis engine: path confinement (the trust boundary) and native detection."""

import os
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


class NativeAnalysisTests(unittest.TestCase):
    """Force the built-in detector (Gitleaks unavailable) so the fallback path is deterministic."""

    def setUp(self):
        self._prev = os.environ.get("SHARAY_GITLEAKS_BIN")
        os.environ["SHARAY_GITLEAKS_BIN"] = "/nonexistent/gitleaks"
        self.addCleanup(
            lambda: (
                os.environ.__setitem__("SHARAY_GITLEAKS_BIN", self._prev)
                if self._prev is not None
                else os.environ.pop("SHARAY_GITLEAKS_BIN", None)
            )
        )

    def test_built_in_analysis_finds_a_secret_and_lists_a_dependency(self):
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
        self.assertTrue(finding["affected_url"].startswith("file://"))
        self.assertTrue(any(p["name"] == "requests" for p in result["packages"]))
        categories = {c["category"] for c in result["checks"]}
        self.assertIn("secret_detection", categories)
        self.assertIn("dependency_inventory", categories)
        gitleaks_check = next(c for c in result["checks"] if c["category"] == "gitleaks")
        self.assertEqual(gitleaks_check["status"], "skipped")
        self.assertIn("built-in", result["basis"])

    def test_a_clean_tree_yields_no_findings_but_still_reports_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / "main.py").write_text("print('nothing secret here')\n")
            result = analyze_source_tree(root)
        self.assertEqual(result["findings"], [])
        self.assertIn("dependency_inventory", {c["category"] for c in result["checks"]})

    def test_an_openapi_schema_in_the_tree_is_ingested_into_an_api_schema_check(self):
        import json

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / "openapi.json").write_text(
                json.dumps(
                    {
                        "openapi": "3.0.1",
                        "info": {"title": "t", "version": "1"},
                        "paths": {"/public": {"get": {"responses": {"200": {"description": "ok"}}}}},
                    }
                )
            )
            result = analyze_source_tree(root)
        api = next(c for c in result["checks"] if c["category"] == "api_schema")
        self.assertEqual(api["status"], "completed")
        self.assertIn("endpoint(s)", api["detail"])

    def test_no_schema_present_is_a_skipped_api_schema_check(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / "main.py").write_text("x = 1\n")
            result = analyze_source_tree(root)
        api = next(c for c in result["checks"] if c["category"] == "api_schema")
        self.assertEqual(api["status"], "skipped")


class GitleaksPathTests(unittest.TestCase):
    """When the pinned Gitleaks binary and the sandbox are present, the real scanner runs."""

    def setUp(self):
        binary = Path(__file__).resolve().parents[2] / "tools" / "bin"
        installs = sorted(binary.glob("gitleaks-*/gitleaks"))
        if not installs:
            self.skipTest("No pinned Gitleaks binary installed.")
        try:
            from services.scanner_worker import attest

            if not attest().get("available"):
                self.skipTest("Isolation sandbox unavailable here.")
        except Exception:
            self.skipTest("Isolation sandbox unavailable here.")
        os.environ.pop("SHARAY_GITLEAKS_BIN", None)

    def test_gitleaks_runs_and_normalizes_into_the_product_finding_shape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / "config.py").write_text('AWS_KEY = "AKIA' + "IOSFODNN7REALKEY" + '"\n')
            result = analyze_source_tree(root)
        gitleaks_check = next(c for c in result["checks"] if c["category"] == "gitleaks")
        self.assertEqual(gitleaks_check["status"], "completed", gitleaks_check["detail"])
        self.assertIn("Gitleaks", result["basis"])
        self.assertTrue(result["findings"], "Gitleaks should report the synthetic AWS key")
        finding = result["findings"][0]
        self.assertEqual(finding["category"], "secret_exposure")
        self.assertTrue(finding["fingerprint"].startswith("gitleaks:"))
        self.assertTrue(finding["affected_url"].startswith("file://"))
        # The redacted report never carries the raw secret value.
        self.assertNotIn("IOSFODNN7REALKEY", str(result))


if __name__ == "__main__":
    unittest.main()
