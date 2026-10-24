"""P1-3 (SAST): semgrep runs over a source tree with the pinned SHARAY ruleset."""

import shutil
import tempfile
import unittest
from pathlib import Path

from services.source_analysis_worker.assess import _semgrep_binary, analyze_source_tree


@unittest.skipIf(_semgrep_binary() is None, "semgrep is not installed in this environment")
class SemgrepSastTests(unittest.TestCase):
    def _tree(self, filename, content):
        d = Path(tempfile.mkdtemp(prefix="sast-"))
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        (d / filename).write_text(content)
        return d

    def test_dangerous_pattern_is_flagged_as_sast(self):
        root = self._tree(
            "vuln.py",
            "def f(x):\n    return eval(x)\nimport subprocess\ndef g(c):\n    subprocess.run(c, shell=True)\n",
        )
        res = analyze_source_tree(root)
        sast = [f for f in res["findings"] if f.get("category") == "sast_vulnerability"]
        cwes = {f["cwe_id"] for f in sast}
        self.assertIn("CWE-95", cwes)  # eval()
        self.assertIn("CWE-78", cwes)  # subprocess shell=True
        for f in sast:
            self.assertEqual(f["tool"], "semgrep")
        self.assertTrue(
            any(c["category"] == "sast_semgrep" and c["status"] == "completed" for c in res["checks"])
        )
        self.assertIn("SAST via Semgrep", res["basis"])

    def test_clean_tree_produces_no_sast_findings(self):
        root = self._tree("ok.py", "def add(a, b):\n    return a + b\n")
        res = analyze_source_tree(root)
        self.assertEqual([f for f in res["findings"] if f.get("category") == "sast_vulnerability"], [])
        self.assertTrue(
            any(c["category"] == "sast_semgrep" and c["status"] == "completed" for c in res["checks"])
        )


if __name__ == "__main__":
    unittest.main()
