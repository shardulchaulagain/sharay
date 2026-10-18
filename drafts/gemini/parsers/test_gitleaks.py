"""Tests for Gitleaks parser with comprehensive negative and rejection suites."""

import json
import unittest

from drafts.gemini.parsers.gitleaks import parse_gitleaks_json

# Hand-written sample adapted from Gitleaks official report schema documentation:
# URL: https://github.com/gitleaks/gitleaks#report-format
SAMPLE_GITLEAKS_REPORT = json.dumps(
    [
        {
            "Description": "AWS Access Key",
            "StartLine": 42,
            "EndLine": 42,
            "StartColumn": 1,
            "EndColumn": 20,
            "Match": "AKIAIOSFODNN7EXAMPLE",  # Raw secret in tool output
            "Secret": "AKIAIOSFODNN7EXAMPLE",  # Raw secret in tool output
            "File": "config/aws.py",
            "SymlinkFile": "",
            "Commit": "a1b2c3d4e5f67890",
            "Entropy": 3.82,
            "Author": "developer",
            "Email": "dev@example.local",
            "Date": "2026-10-12T00:00:00Z",
            "Message": "Add production AWS credentials with token SECRET_TOKEN_PLANTED_HERE",
            "Tags": [],
            "RuleID": "aws-access-key-id",
            "Fingerprint": "aws-key-fp-12345",
        }
    ]
).encode("utf-8")


class GitleaksParserTests(unittest.TestCase):
    def test_parser_extracts_metadata_and_strips_secret(self):
        results = parse_gitleaks_json(SAMPLE_GITLEAKS_REPORT)
        self.assertEqual(len(results), 1)
        finding = results[0]

        self.assertEqual(finding["rule_id"], "aws-access-key-id")
        self.assertEqual(finding["file"], "config/aws.py")
        self.assertEqual(finding["line"], 42)
        self.assertTrue(len(finding["fingerprint"]) >= 16)

        # Assert no secret or commit message is leaked
        serialized = json.dumps(finding)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", serialized)
        self.assertNotIn("SECRET_TOKEN_PLANTED_HERE", serialized)

    def test_rejection_malformed_json(self):
        with self.assertRaises(ValueError):
            parse_gitleaks_json(b"{not valid json")

    def test_rejection_wrong_top_level_type(self):
        with self.assertRaises(ValueError):
            parse_gitleaks_json(json.dumps({"results": []}).encode("utf-8"))

    def test_rejection_non_object_element(self):
        with self.assertRaises(ValueError):
            parse_gitleaks_json(
                json.dumps([{"RuleID": "r", "File": "f.txt", "StartLine": 1}, "string_item"]).encode("utf-8")
            )

    def test_rejection_wrong_field_types(self):
        with self.assertRaises(ValueError):
            parse_gitleaks_json(
                json.dumps([{"RuleID": "r", "File": 12345, "StartLine": "not_an_int"}]).encode("utf-8")
            )

    def test_rejection_deeply_nested_json_recursion(self):
        with self.assertRaises(ValueError) as ctx:
            parse_gitleaks_json(b"[" * 200000)
        self.assertIn("nesting", str(ctx.exception).lower())

    def test_rejection_oversized_input(self):
        with self.assertRaises(ValueError):
            parse_gitleaks_json(b"[" + b" " * (6 * 1024 * 1024) + b"]")

    def test_rejection_path_traversal(self):
        payload = json.dumps([{"RuleID": "r", "File": "../../../etc/passwd", "StartLine": 10}]).encode(
            "utf-8"
        )
        with self.assertRaises(ValueError) as ctx:
            parse_gitleaks_json(payload)
        self.assertIn("traversal", str(ctx.exception))

    def test_secrets_planted_in_all_dropped_fields_never_echoed(self):
        planted_secret = "SUPER_SECRET_VALUE_PLANTED_IN_DROPPED_FIELDS"
        item = {
            "Description": "r",
            "File": "valid.py",
            "StartLine": 5,
            "Match": planted_secret,
            "Secret": planted_secret,
            "Commit": planted_secret,
            "Author": planted_secret,
            "Email": planted_secret,
            "Message": planted_secret,
            "RuleID": "rule-1",
        }
        res = parse_gitleaks_json(json.dumps([item]).encode("utf-8"))
        self.assertNotIn(planted_secret, json.dumps(res))


if __name__ == "__main__":
    unittest.main()
