"""CSRF detector: a state-changing POST form with no anti-CSRF token is flagged; a tokened one isn't."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from packages.scanner_adapters import scan_comprehensive
from packages.security_policies import Destination


class CsrfDetectionTests(unittest.TestCase):
    def setUp(self):
        self.dest = Destination(
            url="http://127.0.0.1:9/", scheme="http", host="127.0.0.1", port=9,
            origin="http://127.0.0.1:9", ip="127.0.0.1", path="/",
        )

    def _run(self, forms):
        def fake_crawl(dest, allow_ip, **kwargs):
            return {"endpoints": ["/account"], "parameters": [], "urls": [], "forms": forms}

        def runner(image, argv, **kwargs):
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=b"", output_truncated=False)

        with patch("packages.scanner_adapters.integrations.crawler.crawl", side_effect=fake_crawl):
            return scan_comprehensive(
                self.dest, "127.0.0.1", run=runner, tools=["crawler"], mode="standard"
            )

    def test_tokenless_post_form_flagged(self):
        res = self._run([
            {"action": "http://127.0.0.1:9/account", "method": "POST",
             "inputs": [{"name": "email", "type": "text", "value": ""}]},
        ])
        csrf = [f for f in res["findings"] if f.get("category") == "cross_site_request_forgery"]
        self.assertEqual(len(csrf), 1)
        self.assertEqual(csrf[0]["cwe_id"], "CWE-352")

    def test_form_with_token_and_get_form_not_flagged(self):
        res = self._run([
            {"action": "http://127.0.0.1:9/account", "method": "POST",
             "inputs": [{"name": "email", "type": "text", "value": ""},
                        {"name": "csrf_token", "type": "hidden", "value": "abc"}]},
            {"action": "http://127.0.0.1:9/search", "method": "GET",
             "inputs": [{"name": "q", "type": "text", "value": ""}]},
            {"action": "http://127.0.0.1:9/login", "method": "POST",
             "inputs": [{"name": "user", "type": "text", "value": ""},
                        {"name": "pass", "type": "password", "value": ""}]},
        ])
        self.assertFalse([f for f in res["findings"] if f.get("category") == "cross_site_request_forgery"])


if __name__ == "__main__":
    unittest.main()
