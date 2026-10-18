"""Hermetic unit tests for specialized scanner integrations (Wordlist discovery & SQLMap auxiliary)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from packages.scanner_adapters.integrations.sqlmap import (
    build_safe_sqlmap_command,
    parse_sqlmap_output,
    run_sqlmap_auxiliary_check,
    validate_sqlmap_command,
)
from packages.scanner_adapters.integrations.wordlist_scanner import scan_wordlist_directories
from packages.security_policies import Destination


class SpecializedScannersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.destination = Destination(
            url="http://127.0.0.1:8080/",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            path="/",
            origin="http://127.0.0.1:8080",
            ip="127.0.0.1",
        )

    def test_wordlist_scanner_discovers_sensitive_endpoints(self) -> None:
        def mock_probe(dest, allow_ip, path, timeout=3.0):
            if path in ("/.env", "/admin"):
                return 200, {"content-type": "text/plain"}, 120, 10.0
            return 404, {}, 0, 10.0

        with patch(
            "packages.scanner_adapters.integrations.wordlist_scanner._probe_path", side_effect=mock_probe
        ):
            res = scan_wordlist_directories(self.destination, "127.0.0.1", max_workers=2)
            discovered = res["discovered_endpoints"]
            findings = res["findings"]

            self.assertIn("/.env", discovered)
            self.assertIn("/admin", discovered)

            env_finding = next(f for f in findings if "/.env" in f["target_url"])
            self.assertEqual(env_finding["severity"], "critical")
            self.assertEqual(env_finding["cwe_id"], "CWE-526")
            self.assertEqual(env_finding["status"], "confirmed")

    def test_wordlist_scanner_filters_wildcard_catchall_routes(self) -> None:
        # Catchall server returns 200 OK with identical 85-byte page for everything
        def mock_probe(dest, allow_ip, path, timeout=3.0):
            return 200, {}, 85, 10.0

        with patch(
            "packages.scanner_adapters.integrations.wordlist_scanner._probe_path", side_effect=mock_probe
        ):
            res = scan_wordlist_directories(self.destination, "127.0.0.1", max_workers=2)
            self.assertEqual(len(res["findings"]), 0)

    def test_sqlmap_safe_command_builder_and_forbidden_flags(self) -> None:
        cmd = build_safe_sqlmap_command("http://127.0.0.1:8080/vulnerabilities/sqli/?id=1", parameter="id")
        self.assertIn("--batch", cmd)
        self.assertIn("--dbs", cmd)
        self.assertIn("--risk=1", cmd)
        self.assertNotIn("--os-shell", cmd)

        # Safety validation succeeds on safe command
        validate_sqlmap_command(cmd)

        # Destructive flag raises ValueError
        with self.assertRaises(ValueError):
            validate_sqlmap_command(cmd + ["--os-shell"])
        with self.assertRaises(ValueError):
            validate_sqlmap_command(cmd + ["--file-write=/tmp/pwn"])

    def test_sqlmap_output_parsing_and_auxiliary_check(self) -> None:
        sample_output = """
        [INFO] testing connection to the target URL
        sqlmap identified the following injection point with a total of 73 HTTP(s) requests:
        ---
        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
        ---
        [INFO] the back-end DBMS is MySQL
        web application technology: Apache 2.4.41, PHP 7.4.3
        back-end DBMS: MySQL >= 5.0.0
        [INFO] fetching database names
        available databases [2]:
        [*] information_schema
        [*] dvwa
        """
        parsed = parse_sqlmap_output(sample_output)
        self.assertTrue(parsed["is_vulnerable"])
        self.assertIn("MySQL", parsed["dbms"])
        self.assertIn("dvwa", parsed["available_databases"])
        self.assertIn("information_schema", parsed["available_databases"])

        def mock_runner(cmd):
            return sample_output, 0

        res = run_sqlmap_auxiliary_check(
            self.destination,
            "127.0.0.1",
            "http://127.0.0.1:8080/vulnerabilities/sqli/?id=1",
            parameter="id",
            runner_fn=mock_runner,
        )
        self.assertEqual(len(res["findings"]), 1)
        finding = res["findings"][0]
        self.assertEqual(finding["category"], "injection")
        self.assertEqual(finding["cwe_id"], "CWE-89")
        self.assertEqual(finding["status"], "confirmed")
        self.assertEqual(finding["lifecycle_state"], "REPRODUCED")
        self.assertIn("dvwa", finding["poc"]["available_databases"])


if __name__ == "__main__":
    unittest.main()
