"""TLS peer-certificate recon parser (L5): asset SANs, validity and derived facts, no probe."""

import unittest

from packages.scanner_adapters.integrations.tls import parse_peer_certificate

# A clock inside the cert's validity window below (2025-06-01 .. 2026-06-01).
NOW = 1767225600.0  # 2026-01-01 UTC


def cert(**over):
    base = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Some CA"), ("commonName", "Some CA Root")),),
        "notBefore": "Jun  1 00:00:00 2025 GMT",
        "notAfter": "Jun  1 00:00:00 2026 GMT",
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.Example.com"), ("IP Address", "203.0.113.5")),
    }
    base.update(over)
    return base


class TlsReconTests(unittest.TestCase):
    def test_sans_are_validated_lowercased_and_deduplicated(self):
        obs = parse_peer_certificate(cert(), now_epoch=NOW)
        self.assertEqual(obs["sans"], {"dns": ["example.com", "www.example.com"], "ip": ["203.0.113.5"]})
        self.assertEqual(obs["subject_cn"], "example.com")
        self.assertEqual(obs["issuer_cn"], "Some CA Root")

    def test_validity_window_and_expiry_are_derived_from_the_supplied_clock(self):
        valid = parse_peer_certificate(cert(), now_epoch=NOW)
        self.assertEqual((valid["expired"], valid["not_yet_valid"]), (False, False))
        self.assertTrue(0 < valid["days_until_expiry"] <= 366)
        expired = parse_peer_certificate(cert(), now_epoch=1798761600.0)  # 2027
        self.assertTrue(expired["expired"])
        early = parse_peer_certificate(cert(), now_epoch=1704067200.0)  # 2024
        self.assertTrue(early["not_yet_valid"])

    def test_self_signed_is_subject_equal_issuer(self):
        selfish = cert(issuer=((("commonName", "example.com"),),))
        self.assertTrue(parse_peer_certificate(selfish, now_epoch=NOW)["self_signed"])
        self.assertFalse(parse_peer_certificate(cert(), now_epoch=NOW)["self_signed"])

    def test_a_malformed_san_or_time_rejects_the_certificate(self):
        for bad in (
            cert(subjectAltName=(("DNS", "not a host name"),)),
            cert(subjectAltName=(("IP Address", "999.1.1.1"),)),
            cert(notAfter="whenever"),
            cert(notBefore="Jun 1 00:00:00 2027 GMT"),  # after notAfter
        ):
            with self.assertRaises(ValueError):
                parse_peer_certificate(bad, now_epoch=NOW)

    def test_a_certificate_with_no_sans_is_fine(self):
        obs = parse_peer_certificate(cert(subjectAltName=()), now_epoch=NOW)
        self.assertEqual(obs["sans"], {"dns": [], "ip": []})


if __name__ == "__main__":
    unittest.main()
