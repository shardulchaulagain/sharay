"""DNS recon record parser (L5): per-type validation and asset rollup, no lookup."""

import unittest

from packages.scanner_adapters.integrations.dns import parse_records


class DnsReconTests(unittest.TestCase):
    def test_records_validate_and_roll_up_into_assets(self):
        out = parse_records(
            [
                {"name": "Example.com.", "type": "A", "data": "203.0.113.5"},
                {"name": "example.com", "type": "AAAA", "data": "2001:db8::1"},
                {"name": "www.example.com", "type": "CNAME", "data": "example.com"},
                {"name": "example.com", "type": "MX", "data": "10 mail.example.com"},
                {"name": "example.com", "type": "TXT", "data": "v=spf1 include:_spf.example.com ~all"},
            ]
        )
        self.assertEqual(out["assets"]["ips"], ["2001:db8::1", "203.0.113.5"])
        self.assertIn("mail.example.com", out["assets"]["hostnames"])
        self.assertIn("www.example.com", out["assets"]["hostnames"])
        mx = next(r for r in out["records"] if r["type"] == "MX")
        self.assertEqual(mx["data"], "10 mail.example.com")

    def test_address_records_enforce_ip_version(self):
        with self.assertRaises(ValueError):
            parse_records([{"name": "x.test", "type": "A", "data": "2001:db8::1"}])
        with self.assertRaises(ValueError):
            parse_records([{"name": "x.test", "type": "AAAA", "data": "203.0.113.5"}])

    def test_unknown_type_or_malformed_data_rejects_the_batch(self):
        for bad in (
            [{"name": "x.test", "type": "WHAT", "data": "y"}],
            [{"name": "not a host", "type": "A", "data": "203.0.113.5"}],
            [{"name": "x.test", "type": "MX", "data": "mail.example.com"}],  # no preference
            [{"name": "x.test", "type": "CNAME", "data": "also not a host"}],
            ["not a dict"],
        ):
            with self.assertRaises(ValueError):
                parse_records(bad)

    def test_non_string_name_or_target_is_rejected_not_coerced(self):
        with self.assertRaises(ValueError):
            parse_records([{"name": None, "type": "A", "data": "203.0.113.5"}])
        with self.assertRaises(ValueError):
            parse_records([{"name": "example.com", "type": "CNAME", "data": None}])

    def test_names_are_lowercased_and_trailing_dot_stripped(self):
        out = parse_records([{"name": "WWW.Example.COM.", "type": "A", "data": "203.0.113.5"}])
        self.assertEqual(out["records"][0]["name"], "www.example.com")


if __name__ == "__main__":
    unittest.main()
