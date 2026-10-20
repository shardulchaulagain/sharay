"""Product & integration tests for Sector 2.5: Signed, Versioned Detection-Pack System.

Verifies:
1. DetectionTemplate Ed25519 asymmetric signing and verification.
2. Tamper rejection: any modification to template definition invalidates signature.
3. NucleiTemplateImporter translates community Nuclei templates into SHARAY templates.
4. DetectionPackManager bundle export, import, signature enforcement, and execution.
"""

import unittest

from packages.crypto.ed25519 import generate_keypair
from packages.detection_packs import (
    DetectionPackManager,
    DetectionTemplate,
    MatcherType,
    NucleiTemplateImporter,
    PackMatcher,
)


class TestDetectionPacks(unittest.TestCase):
    def setUp(self):
        self.priv_key, self.pub_key = generate_keypair()
        self.pub_hex = self.pub_key.hex()

    def test_ed25519_sign_and_verify(self):
        """Ensure templates can be signed with Ed25519 and verified with public key."""
        tpl = DetectionTemplate(
            id="cve-2024-0001",
            name="Test Vulnerability",
            author="sharay-sec",
            version="1.0.0",
            severity="critical",
            category="rce",
            cwe_id="CWE-78",
            method="POST",
            path="/api/admin/exec",
            body="cmd=id",
            matchers=[
                PackMatcher(MatcherType.STATUS, status_codes=[200]),
                PackMatcher(MatcherType.WORD, words=["uid=0(root)"]),
            ],
        )

        sig = tpl.sign_ed25519(self.priv_key)
        self.assertTrue(len(sig) == 128, "Ed25519 signature must be 64 bytes (128 hex chars)")
        self.assertTrue(tpl.verify_ed25519())
        self.assertTrue(tpl.verify_ed25519(self.pub_hex))

        # Tampering invalidates verification
        tpl.path = "/api/hacked/path"
        self.assertFalse(tpl.verify_ed25519(), "Tampered template path must fail signature check")

    def test_nuclei_template_importer(self):
        """Ensure NucleiTemplateImporter parses standard Nuclei definitions."""
        nuclei_def = {
            "id": "git-config-exposure",
            "info": {
                "name": "Git Config File Exposure",
                "author": "geeknik",
                "severity": "medium",
                "classification": {"cwe-id": ["CWE-538"]},
            },
            "http": [
                {
                    "method": "GET",
                    "path": ["{{BaseURL}}/.git/config"],
                    "matchers": [
                        {"type": "status", "status": [200]},
                        {"type": "word", "words": ["[core]", "repositoryformatversion"], "condition": "and"},
                    ],
                }
            ],
        }

        tpl = NucleiTemplateImporter.from_nuclei_dict(nuclei_def)
        self.assertEqual(tpl.id, "git-config-exposure")
        self.assertEqual(tpl.cwe_id, "CWE-538")
        self.assertEqual(tpl.path, "/.git/config")
        self.assertEqual(len(tpl.matchers), 2)

    def test_pack_manager_bundle_export_import_and_execution(self):
        """Verify DetectionPackManager exports signed bundles, validates signatures upon import, and executes."""
        manager = DetectionPackManager(trusted_public_keys=[self.pub_hex])

        tpl = DetectionTemplate(
            id="env-exposure",
            name="Environment File Disclosure",
            author="sharay",
            version="1.0.0",
            severity="high",
            category="information_disclosure",
            cwe_id="CWE-538",
            method="GET",
            path="/.env",
            matchers=[
                PackMatcher(MatcherType.STATUS, status_codes=[200]),
                PackMatcher(MatcherType.WORD, words=["DB_PASSWORD="]),
            ],
        )
        tpl.sign_ed25519(self.priv_key)
        manager.register_template(tpl)

        # Export bundle
        bundle_json = manager.export_pack_bundle()
        self.assertIn("env-exposure", bundle_json)

        # Import into fresh manager with trusted public key
        consumer_mgr = DetectionPackManager(trusted_public_keys=[self.pub_hex])
        imported = consumer_mgr.import_pack_bundle(bundle_json, enforce_signatures=True)
        self.assertEqual(imported, ["env-exposure"])

        # Execute template against simulated vulnerable target
        def mock_vuln_request(origin, ip, method, path, headers=None, body=None):
            if path == "/.env":
                return 200, {"content-type": "text/plain"}, "APP_ENV=production\nDB_PASSWORD=secret123\n", 5.0
            return 404, {}, "Not Found", 2.0

        finding = consumer_mgr.execute_template(
            "env-exposure",
            mock_vuln_request,
            target_origin="http://target.corp",
            allow_ip="127.0.0.1",
        )

        self.assertIsNotNone(finding)
        self.assertEqual(finding["status"], "confirmed")
        self.assertEqual(finding["cwe_id"], "CWE-538")
        self.assertEqual(finding["lifecycle_state"], "REPRODUCED")
        self.assertIn("DB_PASSWORD=", finding["evidence"][0]["snippet"])

        # Execute template against patched target
        def mock_patched_request(origin, ip, method, path, headers=None, body=None):
            return 404, {}, "Not Found", 2.0

        clean_finding = consumer_mgr.execute_template(
            "env-exposure",
            mock_patched_request,
            target_origin="http://target.corp",
            allow_ip="127.0.0.1",
        )
        self.assertIsNone(clean_finding, "Patched endpoint must not trigger finding")


if __name__ == "__main__":
    unittest.main()
