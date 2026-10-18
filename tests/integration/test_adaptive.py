"""Unit tests for adaptive target intelligence extraction and strategy synthesis."""

import unittest
from typing import Any

from packages.scanner_adapters.adaptive import (
    TargetIntelligence,
    extract_intelligence,
    synthesize_adaptive_strategy,
)


class AdaptiveIntelligenceTests(unittest.TestCase):
    def test_extract_intelligence_identifies_technologies_and_ports(self):
        observations: list[dict[str, Any]] = [
            {"kind": "network_service", "category": "network_inventory", "port": 443},
            {"kind": "network_service", "category": "network_inventory", "port": 8080},
            {"server": "Apache/2.4.49 (Unix)", "x_powered_by": "PHP/7.4.3"},
            {
                "kind": "crawler_summary",
                "endpoints": ["/api/v1/users", "/wp-content/themes/default"],
                "parameters": ["id", "nonce"],
            },
        ]
        intel = extract_intelligence(observations)

        self.assertIn("apache", intel.web_servers)
        self.assertIn("php", intel.runtimes)
        self.assertIn("wordpress", intel.frameworks)
        self.assertIn("api", intel.frameworks)
        self.assertIn(443, intel.open_ports)
        self.assertIn(8080, intel.open_ports)
        self.assertIn("/api/v1/users", intel.discovered_endpoints)

    def test_synthesize_adaptive_strategy_tailors_nuclei_tags(self):
        intel = TargetIntelligence()
        intel.web_servers.add("apache")
        intel.runtimes.add("php")
        intel.frameworks.add("wordpress")
        intel.open_ports.add(443)

        strategy = synthesize_adaptive_strategy(intel, base_tags=None, mode="adaptive")
        tags = strategy["tailored_tags"].split(",")

        self.assertIn("apache", tags)
        self.assertIn("php", tags)
        self.assertIn("wordpress", tags)
        self.assertIn("cve", tags)
        self.assertIn("misconfig", tags)

    def test_synthesize_strategy_honors_passive_mode(self):
        intel = TargetIntelligence()
        intel.web_servers.add("nginx")
        strategy = synthesize_adaptive_strategy(intel, base_tags="custom_tag", mode="passive")
        self.assertEqual(strategy["tailored_tags"], "custom_tag")


if __name__ == "__main__":
    unittest.main()
