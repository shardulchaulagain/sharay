"""Header audit follows one same-origin redirect before judging posture."""

import unittest
from unittest import mock

from packages.scanner_adapters.integrations import vuln_scanner
from packages.security_policies import Destination


class HeaderRedirectFollowTests(unittest.TestCase):
    _dest = Destination(
        "https://example.com/", "https", "example.com", 443, "/", "https://example.com", "93.184.216.34"
    )

    def _run(self, responses):
        """responses: dict path -> (status, headers)."""

        def fake_request(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5):
            status, hdrs = responses.get(path, (404, {}))
            return status, hdrs, "", 1.0

        with mock.patch.object(vuln_scanner, "_request_endpoint", side_effect=fake_request):
            res = vuln_scanner.audit_deep_vulnerabilities(self._dest, "93.184.216.34", [], [])
        return {f["title"] for f in res["findings"]}

    def test_follows_redirect_and_audits_final_headers(self):
        secure = {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
        }
        titles = self._run(
            {
                "/": (301, {"location": "https://example.com/home"}),
                "/home": (200, secure),
            }
        )
        self.assertFalse(any("Missing" in t for t in titles))

    def test_does_not_follow_cross_origin_redirect(self):
        # Off-site redirect must not be followed; posture stays unknown -> missing-header findings fire.
        titles = self._run({"/": (302, {"location": "https://evil.example.net/"})})
        self.assertTrue(any("Missing Content-Security-Policy" in t for t in titles))


if __name__ == "__main__":
    unittest.main()
