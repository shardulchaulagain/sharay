"""Tests for Nuclei parser with comprehensive negative, rejection, and credential stripping suites."""

import json
import unittest

from drafts.gemini.parsers.nuclei import parse_nuclei_jsonl

# Hand-written sample adapted from Nuclei JSONL specification:
# URL: https://docs.projectdiscovery.io/tools/nuclei/running#jsonl-output
SAMPLE_NUCLEI_OUTPUT = (
    json.dumps(
        {
            "template-id": "cve-2023-1234-exposure",
            "info": {
                "name": "Synthetic Exposure Check",
                "author": ["projectdiscovery"],
                "tags": ["cve", "misconfig"],
                "severity": "high",
                "description": "Exposed administrative endpoint.",
            },
            "type": "http",
            "host": "127.0.0.1:8080",
            "matched-at": "http://127.0.0.1:8080/admin/debug",
            "matcher-name": "status-200",
            "request": "GET /admin/debug HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Secret 12345\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nINTERNAL DEBUG DATA",
            "curl-command": "curl -X GET 'http://127.0.0.1:8080/admin/debug' -H 'Authorization: Secret 12345'",
            "ip": "127.0.0.1",
            "timestamp": "2026-10-12T00:00:00Z",
        }
    )
    + "\n"
).encode("utf-8")


class NucleiParserTests(unittest.TestCase):
    def test_parser_extracts_finding_and_strips_http_traffic(self):
        results = parse_nuclei_jsonl(SAMPLE_NUCLEI_OUTPUT)
        self.assertEqual(len(results), 1)
        finding = results[0]

        self.assertEqual(finding["template_id"], "cve-2023-1234-exposure")
        self.assertEqual(finding["name"], "Synthetic Exposure Check")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["matched_at"], "http://127.0.0.1:8080/admin/debug")
        self.assertEqual(finding["matcher_name"], "status-200")

        # Requests, responses, curl commands, and tokens must NEVER be retained
        serialized = json.dumps(finding)
        self.assertNotIn("Authorization", serialized)
        self.assertNotIn("Secret 12345", serialized)
        self.assertNotIn("INTERNAL DEBUG DATA", serialized)
        self.assertNotIn("curl", serialized)

    def test_url_credentials_and_queries_are_strictly_stripped(self):
        secret_user = "admin_user"
        secret_pass = "SUPER_SECRET_PASSWORD_123"
        secret_token = "TOKEN_IN_QUERY"
        raw_url = f"https://{secret_user}:{secret_pass}@api.example.local:8443/v1/auth?token={secret_token}#fragment"

        payload = (
            json.dumps(
                {
                    "template-id": "t-1",
                    "matched-at": raw_url,
                    "info": {"severity": "medium"},
                }
            )
            + "\n"
        ).encode("utf-8")

        results = parse_nuclei_jsonl(payload)
        self.assertEqual(len(results), 1)
        cleaned_url = results[0]["matched_at"]

        self.assertEqual(cleaned_url, "https://api.example.local:8443/v1/auth")
        serialized = json.dumps(results)
        self.assertNotIn(secret_user, serialized)
        self.assertNotIn(secret_pass, serialized)
        self.assertNotIn(secret_token, serialized)

    def test_rejection_malformed_json_line_fails_closed(self):
        with self.assertRaises(ValueError) as ctx:
            parse_nuclei_jsonl(b"not json line\n")
        self.assertIn("malformed", str(ctx.exception).lower())

    def test_rejection_non_object_line_fails_closed(self):
        with self.assertRaises(ValueError) as ctx:
            parse_nuclei_jsonl(b'["array", "not", "object"]\n')
        self.assertIn("must be a json object", str(ctx.exception).lower())

    def test_rejection_deeply_nested_line_recursion(self):
        with self.assertRaises(ValueError) as ctx:
            parse_nuclei_jsonl(b"[" * 200000 + b"\n")
        self.assertIn("nested", str(ctx.exception).lower())

    def test_rejection_missing_template_id(self):
        payload = json.dumps({"matched-at": "http://127.0.0.1:8080/test"}).encode("utf-8") + b"\n"
        with self.assertRaises(ValueError):
            parse_nuclei_jsonl(payload)

    def test_rejection_missing_or_invalid_matched_at(self):
        payload = json.dumps({"template-id": "t-1", "matched-at": 12345}).encode("utf-8") + b"\n"
        with self.assertRaises(ValueError):
            parse_nuclei_jsonl(payload)


if __name__ == "__main__":
    unittest.main()
