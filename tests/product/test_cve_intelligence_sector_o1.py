"""Acceptance test suite for Sector O1: Complete KNOWN-Vuln Coverage & Coverage Ledger.

Verifies:
1. Version-to-CPE translation from HTTP headers, cookies, and tech metadata.
2. Anti-hallucination banner gate: rejection of versionless banners (never emit CVE on banner alone).
3. Accurate version-range matching against NVD/OSV/GHSA advisories.
4. Dynamic exploit module tree mapping (linking CVEs to Nuclei and Metasploit modules).
5. Comprehensive Assessment Coverage Ledger with quantifiable coverage metrics.
"""

from __future__ import annotations

import unittest

from packages.cve_intelligence import (
    AssessmentCoverageLedger,
    CPETranslator,
    CVEIntelligenceEngine,
    ObservedComponent,
    VersionRangeEvaluator,
)


class TestSectorO1CVEIntelligence(unittest.TestCase):
    def setUp(self):
        self.engine = CVEIntelligenceEngine()

    def test_cpe_translation_and_version_extraction(self):
        """O1.1: Translates server headers and asset signatures into valid CPE 2.3 strings."""
        headers = {
            "Server": "Apache/2.4.49 (Unix) OpenSSL/1.1.1l",
            "X-Powered-By": "PHP/8.1.2",
            "X-AspNet-Version": "4.0.30319",
        }
        components = CPETranslator.extract_from_headers(headers)
        self.assertGreaterEqual(len(components), 3)

        cpes = {c.cpe_23: c for c in components}
        self.assertIn("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", cpes)
        self.assertIn("cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*", cpes)
        self.assertIn("cpe:2.3:a:microsoft:asp.net:4.0.30319:*:*:*:*:*:*:*", cpes)

        apache = cpes["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"]
        self.assertEqual(apache.product, "http_server")
        self.assertEqual(apache.version, "2.4.49")
        self.assertEqual(apache.vendor, "apache")

    def test_versionless_banner_rejects_cve_emission(self):
        """O1.1: Guard against false positives: banner without version must NOT emit CVEs."""
        # Ambiguous banners commonly seen behind reverse proxies or stripped configs
        ambiguous_headers = [
            {"Server": "Apache"},
            {"Server": "nginx"},
            {"X-Powered-By": "PHP"},
            {"Server": "cloudflare"},
        ]
        for h in ambiguous_headers:
            components = CPETranslator.extract_from_headers(h)
            for c in components:
                matches = self.engine.match_cves(c)
                # Must be empty because version is unknown / unverified
                self.assertEqual(
                    len(matches),
                    0,
                    f"Component {c.product} without verified version emitted ungrounded CVEs",
                )

    def test_version_range_evaluation(self):
        """O1.1: Version ranges correctly match affected releases and pass fixed releases."""
        # Test Apache HTTP Server 2.4.49 vs CVE-2021-41773
        self.assertTrue(VersionRangeEvaluator.is_affected("2.4.49", ">=2.4.49,<=2.4.50"))
        self.assertTrue(VersionRangeEvaluator.is_affected("2.4.50", ">=2.4.49,<=2.4.50"))
        self.assertFalse(VersionRangeEvaluator.is_affected("2.4.48", ">=2.4.49,<=2.4.50"))
        self.assertFalse(VersionRangeEvaluator.is_affected("2.4.51", ">=2.4.49,<=2.4.50"))

        # Test Log4j 2.14.1 vs CVE-2021-44228
        self.assertTrue(VersionRangeEvaluator.is_affected("2.14.1", ">=2.0-beta9,<=2.14.1"))
        self.assertFalse(VersionRangeEvaluator.is_affected("2.17.1", ">=2.0-beta9,<=2.14.1"))

    def test_cve_matching_and_exploit_module_mapping(self):
        """O1.1 & O1.3: Maps detected CVEs to Metasploit and Nuclei modules."""
        comp = ObservedComponent(
            vendor="apache",
            product="http_server",
            version="2.4.49",
            cpe_23="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            source_fact="Server: Apache/2.4.49",
        )
        cve_findings = self.engine.match_cves(comp)
        self.assertGreaterEqual(len(cve_findings), 1)

        cve_ids = {f.cve_id: f for f in cve_findings}
        self.assertIn("CVE-2021-41773", cve_ids)

        cve_41773 = cve_ids["CVE-2021-41773"]
        self.assertEqual(cve_41773.severity, "critical")
        self.assertEqual(cve_41773.cvss_score, 7.5)
        self.assertIn("exploit/multi/http/apache_normalize_path", cve_41773.metasploit_modules)
        self.assertIn("http/cves/2021/CVE-2021-41773.yaml", cve_41773.nuclei_templates)
        self.assertTrue(cve_41773.safe_reproducer_available)

    def test_assessment_coverage_ledger(self):
        """O1.4: Assessment coverage ledger records tested vs applicable known classes and ratios."""
        ledger = AssessmentCoverageLedger(
            target_url="https://example.com/",
            detected_components=[
                ObservedComponent("apache", "http_server", "2.4.49", "cpe:2.3:a:apache:http_server:2.4.49", "Server"),
                ObservedComponent("php", "php", "8.1.2", "cpe:2.3:a:php:php:8.1.2", "X-Powered-By"),
            ],
        )

        ledger.record_applicable_cve("CVE-2021-41773", "apache:http_server", "cwe-22")
        ledger.record_applicable_cve("CVE-2021-42013", "apache:http_server", "cwe-22")
        ledger.record_applicable_cve("CVE-2022-31626", "php:php", "cwe-476")

        # Mark test execution results
        ledger.record_test_result("CVE-2021-41773", status="confirmed", tool="nuclei")
        ledger.record_test_result("CVE-2021-42013", status="negative_control_passed", tool="reproducer")
        ledger.record_test_result("CVE-2022-31626", status="not_evaluated", tool=None)

        summary = ledger.generate_summary()
        self.assertEqual(summary["total_applicable_cves"], 3)
        self.assertEqual(summary["tested_cves_count"], 2)
        self.assertEqual(summary["confirmed_cves_count"], 1)
        self.assertAlmostEqual(summary["coverage_percentage"], 66.67, places=1)
        self.assertIn("cwe-22", summary["tested_classes"])


if __name__ == "__main__":
    unittest.main()
