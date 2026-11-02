"""Authenticated deep audit: the login session is carried into injection probes so login-gated
vulnerabilities are actually detected (regression for the DVWA miss)."""

import unittest
from unittest import mock

from packages.scanner_adapters.integrations import vuln_scanner
from packages.security_policies import Destination


class AuthenticatedInjectionTests(unittest.TestCase):
    def setUp(self):
        self.dest = Destination(
            url="http://127.0.0.1:8080/vulnerabilities/sqli/", scheme="http", host="127.0.0.1",
            port=8080, origin="http://127.0.0.1:8080", ip="127.0.0.1", path="/vulnerabilities/sqli/",
        )

    def test_session_carried_and_sqli_detected_only_when_authenticated(self):
        seen_cookies = []

        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            # A login-gated app only serves the vulnerable page (and its SQL error) with the session.
            cookies = dict((auth or {}).get("cookies") or {})
            seen_cookies.append(cookies)
            if "PHPSESSID" not in cookies:
                return 302, {}, "", 1.0  # redirect to login
            if "id=1'" in path or "%271" in path or "id=1%27" in path or path.count("'"):
                return 200, {}, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL", 1.0
            return 200, {}, "<html>First name: admin</html>", 1.0

        with mock.patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res_auth = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/vulnerabilities/sqli/"],
                discovered_parameters=["id"], timeout=3,
                auth={"cookies": {"PHPSESSID": "sess123", "security": "low"}, "headers": {}},
            )
        sqli = [f for f in res_auth["findings"] if "sql" in f.get("category", "").lower() or "SQL Injection" in f.get("title", "")]
        self.assertTrue(sqli, "authenticated audit must detect the login-gated SQLi")
        self.assertTrue(any("PHPSESSID" in c for c in seen_cookies), "the session must reach the probes")

        # Without auth, the same app redirects to login and nothing is found.
        with mock.patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res_anon = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/vulnerabilities/sqli/"],
                discovered_parameters=["id"], timeout=3,
            )
        self.assertFalse(
            [f for f in res_anon["findings"] if "SQL Injection" in f.get("title", "")],
            "unauthenticated audit cannot reach the login-gated SQLi",
        )


    def test_stored_xss_detected_without_false_reflected_cascade(self):
        # A guestbook that persists input and shows it back: the stored canary must be reported as
        # Stored XSS, and must NOT make every other param's reflected check fire (per-param canary).
        import urllib.parse as _up

        stored = {"value": ""}

        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            if method == "POST" and body:
                stored["value"] = _up.unquote_plus(body)  # persist the full submitted payload
                return 200, {}, "saved", 1.0
            # GET returns whatever was stored (the guestbook), reflecting nothing from the query.
            return 200, {}, f"<div>{stored['value']}</div>", 1.0

        with mock.patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/vulnerabilities/xss_s/"],
                discovered_parameters=["txtName", "mtxMessage"], timeout=2,
                auth={"cookies": {"PHPSESSID": "x"}, "headers": {}},
            )
        xss = [f for f in res["findings"] if "XSS" in f.get("title", "")]
        self.assertTrue(any("Stored" in f["title"] for f in xss), "stored XSS must be detected")
        self.assertFalse(any("Reflected" in f["title"] for f in xss), "no reflected false positives")

    def test_destructive_endpoints_are_not_fuzzed(self):
        probed = []

        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            probed.append(path.split("?")[0])
            return 200, {}, "<html>ok</html>", 1.0

        with mock.patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1",
                discovered_endpoints=["/setup.php", "/logout.php", "/vulnerabilities/sqli/"],
                discovered_parameters=["id"], timeout=2,
            )
        # setup/logout are destructive (reset DB / end session); they must never be actively fuzzed.
        self.assertFalse(any("/setup.php" in p for p in probed), "setup.php must not be fuzzed")
        self.assertFalse(any("/logout.php" in p for p in probed), "logout.php must not be fuzzed")
        self.assertTrue(any("/vulnerabilities/sqli/" in p for p in probed), "the real endpoint is fuzzed")


if __name__ == "__main__":
    unittest.main()
