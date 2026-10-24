"""P1-3 (SCA): declared dependencies are matched against the configured OSV advisory feed."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from services.source_analysis_worker.assess import analyze_source_tree

_ADVISORY = [
    {
        "id": "OSV-TEST-REQUESTS",
        "aliases": ["CVE-2018-18074"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
            }
        ],
    }
]


class OsvScaTests(unittest.TestCase):
    def _tree(self):
        d = Path(tempfile.mkdtemp(prefix="sca-"))
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        (d / "requirements.txt").write_text("requests==2.19.0\nflask==1.0\n")
        return d

    def _feed(self):
        f = Path(tempfile.mktemp(suffix=".json"))
        f.write_text(json.dumps(_ADVISORY))
        self.addCleanup(lambda: f.unlink(missing_ok=True))
        return f

    def test_vulnerable_dependency_is_matched(self):
        feed = self._feed()
        with patch.dict("os.environ", {"SHARAY_OSV_ADVISORIES": str(feed)}):
            res = analyze_source_tree(self._tree())
        sca = [f for f in res["findings"] if f.get("category") == "vulnerable_dependency"]
        self.assertEqual(len(sca), 1)
        self.assertIn("requests", sca[0]["title"])
        check = next(c for c in res["checks"] if c["category"] == "sca_osv")
        self.assertEqual(check["status"], "completed")
        self.assertIn(feed.name, check["detail"])  # feed identity recorded
        self.assertIn("updated", check["detail"])  # freshness recorded
        self.assertIn("SCA via OSV", res["basis"])

    def test_sca_skipped_without_a_feed(self):
        with patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop("SHARAY_OSV_ADVISORIES", None)
            res = analyze_source_tree(self._tree())
        check = next(c for c in res["checks"] if c["category"] == "sca_osv")
        self.assertEqual(check["status"], "skipped")
        self.assertEqual([f for f in res["findings"] if f.get("category") == "vulnerable_dependency"], [])


if __name__ == "__main__":
    unittest.main()
