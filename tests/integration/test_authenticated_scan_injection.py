"""P1-4 wiring: an authenticated scan injects stored credentials into the crawler, values redacted."""

import unittest
from unittest.mock import patch

from packages.scanner_adapters import scan_comprehensive
from packages.security_policies import Destination


class AuthenticatedScanInjectionTests(unittest.TestCase):
    def setUp(self):
        self.destination = Destination(
            url="http://127.0.0.1:9",
            scheme="http",
            host="127.0.0.1",
            port=9,
            path="/",
            origin="http://127.0.0.1:9",
            ip="127.0.0.1",
        )

    def test_crawler_receives_cookies_and_headers(self):
        captured = {}

        def fake_crawl(dest, allow_ip, **kwargs):
            captured.update(kwargs)
            return {"endpoints": [], "parameters": [], "urls": []}

        auth = {
            "cookies": {"sid": "cookie-secret"},
            "headers": {"Authorization": "Bearer tok-secret"},
            "identity_names": ["session"],
        }
        with patch("packages.scanner_adapters.integrations.crawler.crawl", side_effect=fake_crawl):
            res = scan_comprehensive(
                self.destination, "127.0.0.1", tools=["crawler"], mode="standard", auth=auth
            )

        self.assertEqual(captured.get("cookies"), {"sid": "cookie-secret"})
        self.assertEqual(captured.get("auth_headers"), {"Authorization": "Bearer tok-secret"})

        # The identity is recorded as evidence; the secret values never appear in any check text.
        auth_checks = [c for c in res["checks"] if c.get("category") == "authenticated_session"]
        self.assertEqual(len(auth_checks), 1)
        self.assertIn("session", auth_checks[0]["detail"])
        self.assertNotIn("cookie-secret", auth_checks[0]["detail"])
        self.assertNotIn("tok-secret", auth_checks[0]["detail"])


if __name__ == "__main__":
    unittest.main()
