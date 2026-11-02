"""Brute-force protection: a login with no lockout after repeated failures is flagged; one that locks is not."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from packages.scanner_adapters import scan_comprehensive
from packages.security_policies import Destination


class BruteForceDetectionTests(unittest.TestCase):
    def setUp(self):
        self.dest = Destination(
            url="http://127.0.0.1:9/", scheme="http", host="127.0.0.1", port=9,
            origin="http://127.0.0.1:9", ip="127.0.0.1", path="/",
        )
        self.login = {
            "action": "http://127.0.0.1:9/login", "method": "POST",
            "inputs": [
                {"name": "username", "type": "text", "value": ""},
                {"name": "password", "type": "password", "value": ""},
                {"name": "Login", "type": "submit", "value": "Login"},
            ],
        }

    def _run(self, login_responder):
        def fake_crawl(dest, allow_ip, **kwargs):
            return {"endpoints": ["/login"], "parameters": [], "urls": [], "forms": [self.login]}

        calls = {"n": 0}

        def fake_probe(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            if "/login" in path or (body and "username" in str(body)):
                calls["n"] += 1
                return (200, {}, login_responder(calls["n"]), 1.0)
            return (200, {}, "", 1.0)

        def runner(image, argv, **kwargs):
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=b"", output_truncated=False)

        with patch("packages.scanner_adapters.integrations.crawler.crawl", side_effect=fake_crawl), \
             patch("packages.scanner_adapters.integrations.vuln_scanner._request_endpoint", side_effect=fake_probe):
            return scan_comprehensive(self.dest, "127.0.0.1", run=runner, tools=["crawler"], mode="aggressive")

    def test_no_lockout_flagged(self):
        res = self._run(lambda n: "Login failed. Incorrect username or password.")
        bf = [f for f in res["findings"] if f.get("category") == "broken_authentication"]
        self.assertEqual(len(bf), 1)
        self.assertEqual(bf[0]["cwe_id"], "CWE-307")

    def test_lockout_not_flagged(self):
        res = self._run(lambda n: "Account locked: too many failed attempts." if n >= 3 else "Login failed.")
        self.assertFalse([f for f in res["findings"] if f.get("category") == "broken_authentication"])


if __name__ == "__main__":
    unittest.main()
