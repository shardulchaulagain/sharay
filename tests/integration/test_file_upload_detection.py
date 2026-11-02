"""Unrestricted file upload: a form that accepts a .php canary is flagged; a rejecting one is not."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from packages.scanner_adapters import scan_comprehensive
from packages.security_policies import Destination


class FileUploadDetectionTests(unittest.TestCase):
    def setUp(self):
        self.dest = Destination(
            url="http://127.0.0.1:9/", scheme="http", host="127.0.0.1", port=9,
            origin="http://127.0.0.1:9", ip="127.0.0.1", path="/",
        )
        self.form = {
            "action": "http://127.0.0.1:9/upload", "method": "POST",
            "inputs": [
                {"name": "MAX_FILE_SIZE", "type": "hidden", "value": "100000"},
                {"name": "uploaded", "type": "file", "value": ""},
                {"name": "Upload", "type": "submit", "value": "Upload"},
            ],
        }

    def _run(self, upload_response):
        def fake_crawl(dest, allow_ip, **kwargs):
            return {"endpoints": ["/upload"], "parameters": [], "urls": [], "forms": [self.form]}

        def fake_probe(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            if method == "POST" and "multipart" in str((headers or {}).get("Content-Type", "")):
                return (200, {}, upload_response, 1.0)
            return (200, {}, "", 1.0)

        def runner(image, argv, **kwargs):
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=b"", output_truncated=False)

        with patch("packages.scanner_adapters.integrations.crawler.crawl", side_effect=fake_crawl), \
             patch("packages.scanner_adapters.integrations.vuln_scanner._request_endpoint", side_effect=fake_probe):
            return scan_comprehensive(self.dest, "127.0.0.1", run=runner, tools=["crawler"], mode="standard")

    def test_accepted_php_upload_flagged(self):
        res = self._run("File succesfully uploaded to ../../hackable/uploads/sharay.php")
        up = [f for f in res["findings"] if f.get("category") == "unrestricted_file_upload"]
        self.assertEqual(len(up), 1)
        self.assertEqual(up[0]["cwe_id"], "CWE-434")

    def test_rejected_upload_not_flagged(self):
        res = self._run("Your image was not uploaded. Only JPG/PNG allowed — file type not allowed / invalid.")
        self.assertFalse([f for f in res["findings"] if f.get("category") == "unrestricted_file_upload"])


if __name__ == "__main__":
    unittest.main()
