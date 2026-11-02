"""Product & integration tests for Sector 2.3: Out-of-Band (OOB) Interaction Server.

Verifies:
1. OOBTokenGenerator produces signed, tamper-proof correlation tokens and rejects tampered signatures.
2. OOBInteractionServer starts, receives HTTP callbacks, and extracts correlation tokens.
3. Live SSRF callback confirmation: Target executing outbound fetch transitions finding to confirmed (CWE-918).
4. Blind XXE callback confirmation: Target fetching external DTD confirms finding (CWE-611).
5. Zero false-positive guarantee: Uncontacted probes remain unconfirmed without OOB signals.
"""

import unittest
import urllib.request

from packages.scanner_adapters.integrations.oob import (
    OOBCollector,
    OOBInteractionServer,
    OOBTokenGenerator,
)


class TestOOBInteractionServer(unittest.TestCase):
    def setUp(self):
        self.generator = OOBTokenGenerator(secret_key=b"test_oob_key_12345")
        self.collector = OOBCollector(token_generator=self.generator)

    def test_oob_token_tamper_proof(self):
        """Ensure OOB tokens have valid HMAC-SHA256 signatures and forged tokens are rejected."""
        token = self.generator.generate_token("probe-999", "ssrf")
        self.assertIn("sharay-ssrf-probe999", token)

        # Valid token validates correctly
        meta = self.generator.validate_token(token)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["probe_type"], "ssrf")
        self.assertEqual(meta["probe_id"], "probe999")

        # Tampered token is rejected
        tampered = token.replace("probe999", "hacked00")
        self.assertIsNone(self.generator.validate_token(tampered))

    def test_live_ssrf_callback_confirmation(self):
        """Verify target executing outbound HTTP fetch triggers callback and confirms SSRF."""
        with OOBInteractionServer(self.collector, host="127.0.0.1", port=0) as server:
            token, _ = self.collector.register_probe(
                probe_id="ssrf-task-42",
                probe_type="ssrf",
                target_endpoint="http://target.corp/api/fetch-url",
                parameter="target_url",
            )

            # Before target calls back: finding is not confirmed
            self.assertIsNone(self.collector.confirm_vulnerability(token))

            # Target server executes outbound HTTP request to OOB callback listener
            callback_url = server.get_callback_url(token)
            req = urllib.request.Request(callback_url, headers={"User-Agent": "Target-Internal-Curl/7.88"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read().decode("utf-8")
                self.assertEqual(body, "OK")

            # After callback: collector confirms vulnerability
            interaction = self.collector.poll(token)
            self.assertIsNotNone(interaction)
            self.assertEqual(interaction.protocol, "http")

            finding = self.collector.confirm_vulnerability(token)
            self.assertIsNotNone(finding)
            self.assertEqual(finding["category"], "ssrf")
            self.assertEqual(finding["cwe_id"], "CWE-918")
            self.assertEqual(finding["status"], "confirmed")
            self.assertEqual(finding["lifecycle_state"], "REPRODUCED")
            self.assertEqual(finding["poc"]["oob_token"], token)

    def test_live_xxe_dtd_callback_confirmation(self):
        """Verify target executing external DTD fetch triggers callback and confirms XXE."""
        with OOBInteractionServer(self.collector, host="127.0.0.1", port=0) as server:
            token, _ = self.collector.register_probe(
                probe_id="xxe-task-77",
                probe_type="xxe",
                target_endpoint="http://target.corp/api/xml-parser",
                parameter="xml_body",
            )

            # Target XML parser fetches external DTD with token in path
            callback_url = f"http://127.0.0.1:{server.port}/xxe-{token}.dtd"
            with urllib.request.urlopen(callback_url, timeout=2.0) as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.headers.get("Content-Type"), "application/xml-dtd")
                body = resp.read().decode("utf-8")
                self.assertIn("oob_success", body)

            finding = self.collector.confirm_vulnerability(token)
            self.assertIsNotNone(finding)
            self.assertEqual(finding["category"], "injection")
            self.assertEqual(finding["cwe_id"], "CWE-611")
            self.assertEqual(finding["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
