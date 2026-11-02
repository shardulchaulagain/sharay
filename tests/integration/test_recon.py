"""Recon asset inventory (L5): dedup across sources with provenance."""

import unittest

from packages.scanner_adapters.integrations.recon import collect_assets


class ReconAssetTests(unittest.TestCase):
    def test_assets_dedup_across_sources_and_keep_provenance(self):
        out = collect_assets(
            [
                {"source": "dns", "hostnames": ["example.com", "www.example.com"], "ips": ["203.0.113.5"]},
                {"source": "tls", "hostnames": ["Example.com"], "ips": []},
                {"source": "nmap", "hostnames": [], "ips": ["203.0.113.5"]},
            ]
        )
        by_value = {(a["kind"], a["value"]): a["sources"] for a in out["assets"]}
        self.assertEqual(by_value[("hostname", "example.com")], ["dns", "tls"])  # merged + lowercased
        self.assertEqual(by_value[("ip", "203.0.113.5")], ["dns", "nmap"])
        self.assertEqual(by_value[("hostname", "www.example.com")], ["dns"])

    def test_a_missing_or_bad_source_label_is_rejected(self):
        with self.assertRaises(ValueError):
            collect_assets([{"hostnames": ["x.test"], "ips": []}])
        with self.assertRaises(ValueError):
            collect_assets([{"source": "dns", "hostnames": "x.test", "ips": []}])

    def test_empty_input_is_an_empty_inventory(self):
        self.assertEqual(collect_assets([]), {"assets": [], "truncated": False})

    def test_ipv6_and_trailing_dot_hostnames_normalise_before_dedup(self):
        out = collect_assets(
            [
                {
                    "source": "tls",
                    "hostnames": ["App.Example.com."],
                    "ips": ["2001:0DB8:0000:0000:0000:0000:0000:0001"],
                },
                {"source": "dns", "hostnames": ["app.example.com"], "ips": ["2001:db8::1"]},
            ]
        )
        by = {(a["kind"], a["value"]): a["sources"] for a in out["assets"]}
        self.assertEqual(by[("hostname", "app.example.com")], ["dns", "tls"])
        self.assertEqual(by[("ip", "2001:db8::1")], ["dns", "tls"])

    def test_a_malformed_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            collect_assets([{"source": "nmap", "hostnames": [], "ips": ["999.1.1.1"]}])


if __name__ == "__main__":
    unittest.main()
