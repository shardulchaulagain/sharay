"""Hermetic unit and integration tests for the mathematical boolean-based blind SQLi differential oracle."""

from __future__ import annotations

import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from packages.scanner_adapters.integrations.vuln_scanner import (
    _compute_jaccard_similarity,
    _evaluate_boolean_blind_sqli,
    _extract_lexical_tokens,
)
from packages.security_policies import Destination


class BooleanBlindDifferentialSQLiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.destination = Destination(
            url="http://127.0.0.1:8080/search",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            path="/search",
            origin="http://127.0.0.1:8080",
            ip="127.0.0.1",
        )
        self.sql_regex = r"(?i)(SQL syntax.*(?:MySQL|MariaDB)|Warning.*mysql_|PostgreSQL.*ERROR|syntax error)"

    def test_extract_lexical_tokens(self) -> None:
        html = "<html><head><style>.hidden { display: none; }</style><script>var x = 1;</script></head><body><h1>Products Catalog</h1><p>Found 42 matching items in database.</p></body></html>"
        tokens = _extract_lexical_tokens(html)
        self.assertIn("Products", tokens)
        self.assertIn("Catalog", tokens)
        self.assertIn("Found", tokens)
        self.assertIn("database", tokens)
        self.assertNotIn("display", tokens)
        self.assertNotIn("script", tokens)

    def test_jaccard_similarity_calculation(self) -> None:
        set_a = {"alpha", "beta", "gamma", "delta"}
        set_b = {"alpha", "beta", "epsilon", "zeta"}
        # Intersection: {"alpha", "beta"} (2), Union: {"alpha", "beta", "gamma", "delta", "epsilon", "zeta"} (6)
        # J = 2/6 = 0.333...
        j = _compute_jaccard_similarity(set_a, set_b)
        self.assertAlmostEqual(j, 1.0 / 3.0, places=4)

        # Identical sets -> 1.0
        self.assertEqual(_compute_jaccard_similarity(set_a, set_a), 1.0)
        # Disjoint sets -> 0.0
        self.assertEqual(_compute_jaccard_similarity({"one"}, {"two"}), 0.0)

    def test_boolean_blind_sqli_differential_confirmed(self) -> None:
        """Verify that genuine boolean differential (with canary confirmation) detects SQLi."""

        def mock_request(dest, ip, method, path, headers=None, body=None, timeout=3.5):
            query = parse_qs(urlsplit(path).query)
            q = query.get("q", [""])[0]

            # Truthy condition returns rich data list
            if "1' OR '1'='1" in q or "1337=1337" in q:
                return (
                    200,
                    {},
                    (
                        "<html><body><h2>Results (15 items found)</h2>"
                        "<ul><li>Item 101 - Enterprise Server Pro</li>"
                        "<li>Item 102 - Advanced Threat Protection</li>"
                        "<li>Item 103 - Microsegmentation Gateway</li>"
                        "<li>Item 104 - Cryptographic Hardware Security Module</li></ul></body></html>"
                    ),
                    25.0,
                )
            # Falsy condition returns empty results
            return (
                200,
                {},
                "<html><body><h2>Results (0 items found)</h2><p>No matching records discovered.</p></body></html>",
                25.0,
            )

        with patch(
            "packages.scanner_adapters.integrations.vuln_scanner._request_endpoint", side_effect=mock_request
        ):
            finding = _evaluate_boolean_blind_sqli(
                destination=self.destination,
                allow_ip="127.0.0.1",
                ep="/search",
                param="q",
                is_lab_endpoint=False,
                timeout=3.5,
                sql_regex=self.sql_regex,
            )

            self.assertIsNotNone(finding)
            self.assertEqual(finding["category"], "injection")
            self.assertEqual(finding["cwe_id"], "CWE-89")
            self.assertEqual(finding["status"], "confirmed")
            self.assertEqual(finding["lifecycle_state"], "REPRODUCED")
            self.assertIn("Enterprise", finding["poc"]["differential_tokens"])
            self.assertLess(finding["poc"]["jaccard_similarity"], 0.88)
            self.assertGreater(finding["poc"]["length_delta"], 30)

    def test_boolean_blind_sqli_rejected_on_uniform_responses(self) -> None:
        """When responses for TRUE and FALSE are identical, no finding must be emitted."""

        def mock_request(dest, ip, method, path, headers=None, body=None, timeout=3.5):
            return 200, {}, "<html><body><h2>Search Page</h2><p>Input query above.</p></body></html>", 20.0

        with patch(
            "packages.scanner_adapters.integrations.vuln_scanner._request_endpoint", side_effect=mock_request
        ):
            finding = _evaluate_boolean_blind_sqli(
                destination=self.destination,
                allow_ip="127.0.0.1",
                ep="/search",
                param="q",
                is_lab_endpoint=False,
                timeout=3.5,
                sql_regex=self.sql_regex,
            )
            self.assertIsNone(finding)

    def test_boolean_blind_sqli_skipped_when_error_based_syntax_present(self) -> None:
        """When responses contain database error messages, blind differential skips so error-based probe handles it."""

        def mock_request(dest, ip, method, path, headers=None, body=None, timeout=3.5):
            query = parse_qs(urlsplit(path).query)
            q = query.get("q", [""])[0]
            if "1' OR '1'='1" in q:
                return (
                    500,
                    {},
                    "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given",
                    20.0,
                )
            return 200, {}, "<html><body>Search Page</body></html>", 20.0

        with patch(
            "packages.scanner_adapters.integrations.vuln_scanner._request_endpoint", side_effect=mock_request
        ):
            finding = _evaluate_boolean_blind_sqli(
                destination=self.destination,
                allow_ip="127.0.0.1",
                ep="/search",
                param="q",
                is_lab_endpoint=False,
                timeout=3.5,
                sql_regex=self.sql_regex,
            )
            self.assertIsNone(finding)


if __name__ == "__main__":
    unittest.main()
