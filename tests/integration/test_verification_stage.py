"""Native-arm64 verification stage (replaces emulated Metasploit): nuclei-backed, honest on timeout."""

import unittest
from types import SimpleNamespace

from packages.scanner_adapters import scan_live_verification
from packages.security_policies import Destination


class VerificationStageTests(unittest.TestCase):
    def setUp(self):
        self.dest = Destination(
            url="https://example.com/",
            scheme="https",
            host="example.com",
            port=443,
            origin="https://example.com",
            ip="93.184.216.34",
            path="/",
        )

    def test_clean_pass_relabels_as_verification(self):
        nuclei_raw = (
            b'{"template-id":"CVE-2024-9999","info":{"name":"RCE","severity":"critical"},'
            b'"matched-at":"https://example.com/api"}\n'
        )
        argv_seen = {}

        def runner(image, argv, **kwargs):
            argv_seen["image"] = image
            argv_seen["argv"] = argv
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=nuclei_raw, output_truncated=False)

        res = scan_live_verification(self.dest, "93.184.216.34", run=runner)
        self.assertEqual(res["adapter"], "verification_live")
        self.assertIn("nuclei", argv_seen["image"])  # native nuclei image, not metasploit
        self.assertIn("-tags", argv_seen["argv"])  # verification runs the tag-scoped families
        cats = {c["category"]: c for c in res["checks"]}
        self.assertIn("verification", cats)
        self.assertNotIn("nuclei", cats)  # relabeled away from a generic nuclei pass
        self.assertEqual(cats["verification"]["status"], "completed")
        self.assertIn("replaces emulated Metasploit", cats["verification"]["detail"])
        self.assertTrue(any(f["fingerprint"].startswith("nuclei:") for f in res["findings"]))

    def test_timeout_is_amber_not_green(self):
        def runner(image, argv, **kwargs):
            return SimpleNamespace(
                outcome="failed", exit_code=124, stdout=b"", stderr=b"timed out", output_truncated=False
            )

        res = scan_live_verification(self.dest, "93.184.216.34", run=runner)
        cats = {c["category"]: c for c in res["checks"]}
        self.assertEqual(cats["verification"]["status"], "completed_with_errors")
        self.assertIn("execution budget", cats["verification"]["detail"])
        self.assertNotIn("replaces emulated Metasploit", cats["verification"]["detail"])


if __name__ == "__main__":
    unittest.main()
