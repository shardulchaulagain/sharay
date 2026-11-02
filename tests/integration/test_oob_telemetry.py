"""Hermetic unit tests for Out-of-Band (OOB) telemetry verification and callback correlation."""

from __future__ import annotations

import unittest

from packages.scanner_adapters.integrations.oob import (
    OOBCollector,
    OOBTokenGenerator,
)


class OOBTelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = OOBTokenGenerator(secret_key=b"test_secret_key_12345", domain="oob.test.invalid")
        self.collector = OOBCollector(token_generator=self.generator)

    def test_token_generation_and_cryptographic_validation(self) -> None:
        token = self.generator.generate_token(probe_id="finding-42", probe_type="ssrf")
        self.assertTrue(token.endswith(".oob.test.invalid"))
        self.assertIn("sharay-ssrf-finding4", token)

        # Valid token decodes correctly
        metadata = self.generator.validate_token(token)
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata["probe_type"], "ssrf")
        self.assertEqual(metadata["probe_id"], "finding4")

        # Tampered token fails validation
        tampered = token.replace("sharay-ssrf", "sharay-cmdi")
        self.assertIsNone(self.generator.validate_token(tampered))

        # Random garbage fails validation
        self.assertIsNone(self.generator.validate_token("evil.attacker.com"))

    def test_ssrf_callback_correlation_produces_confirmed_finding(self) -> None:
        token, oob_url = self.collector.register_probe(
            probe_id="probe-9988",
            probe_type="ssrf",
            target_endpoint="/api/fetch-url",
            parameter="target_url",
        )
        self.assertIn(token, oob_url)

        # Before callback, no vulnerability confirmed
        self.assertIsNone(self.collector.confirm_vulnerability(token))

        # Target triggers outbound HTTP interaction to OOB collector
        recorded = self.collector.record_interaction(
            token=token,
            protocol="http",
            source_ip="198.51.100.5",
            http_path="/callback",
            http_headers={"User-Agent": "Java/17.0.1"},
        )
        self.assertTrue(recorded)

        # Now vulnerability is 100% confirmed
        finding = self.collector.confirm_vulnerability(token)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["category"], "ssrf")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["cwe_id"], "CWE-918")
        self.assertEqual(finding["status"], "confirmed")
        self.assertEqual(finding["lifecycle_state"], "REPRODUCED")
        self.assertEqual(finding["poc"]["callback_protocol"], "http")
        self.assertEqual(finding["poc"]["callback_source_ip"], "198.51.100.5")

    def test_xxe_payload_builder_and_dns_callback_confirmation(self) -> None:
        token, _ = self.collector.register_probe(
            probe_id="probe-1122",
            probe_type="xxe",
            target_endpoint="/api/xml-import",
            parameter="xml_body",
        )
        xxe_payload = self.collector.build_xxe_payload(token)
        self.assertIn(token, xxe_payload)
        self.assertIn("<!ENTITY % oob SYSTEM", xxe_payload)

        # Target server DNS resolver issues query for the OOB domain
        recorded = self.collector.record_interaction(
            token=token,
            protocol="dns",
            source_ip="203.0.113.10",
            query_name=token,
        )
        self.assertTrue(recorded)

        finding = self.collector.confirm_vulnerability(token)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["category"], "injection")
        self.assertEqual(finding["cwe_id"], "CWE-611")
        self.assertIn("XML External Entity", finding["title"])
        self.assertEqual(finding["status"], "confirmed")

    def test_cmdi_payload_builder_and_callback(self) -> None:
        token, _ = self.collector.register_probe(
            probe_id="probe-3344",
            probe_type="cmdi",
            target_endpoint="/admin/ping",
            parameter="ip",
        )
        cmdi_payload = self.collector.build_cmdi_payload(token)
        self.assertIn(f"nslookup {token}", cmdi_payload)

        self.collector.record_interaction(
            token=token,
            protocol="dns",
            source_ip="198.51.100.25",
            query_name=token,
        )
        finding = self.collector.confirm_vulnerability(token)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["cwe_id"], "CWE-78")
        self.assertIn("OS Command Injection", finding["title"])


if __name__ == "__main__":
    unittest.main()
