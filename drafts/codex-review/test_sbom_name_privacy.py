"""Requester acceptance for SBOM name redaction; no real credential or network."""

import json
import unittest

from packages.secret_patterns import redact_tokens
from services.source_analysis_worker.sbom import parse_cyclonedx


class SbomNamePrivacyTests(unittest.TestCase):
    def test_recognized_token_in_package_name_is_not_echoed(self):
        token = "sk-proj-" + "a" * 48
        self.assertNotEqual(redact_tokens(token, "[REDACTED]"), token)
        for body in (f"pypi/{token}", f"npm/{token}", f"npm/%40{token}/fixture"):
            with self.subTest(ecosystem=body.split("/", 1)[0]):
                document = {"bomFormat": "CycloneDX", "components": [{"purl": f"pkg:{body}@1.2.3"}]}
                result = parse_cyclonedx(json.dumps(document).encode())
                self.assertTrue(token not in json.dumps(result), "Synthetic known-token name was echoed")


if __name__ == "__main__":
    unittest.main()
