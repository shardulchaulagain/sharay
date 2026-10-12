"""Tests for Semgrep parser with comprehensive negative and rejection suites."""

import json
import unittest

from drafts.gemini.parsers.semgrep import parse_semgrep_json

# Hand-written sample adapted from Semgrep CLI JSON specification:
# URL: https://semgrep.dev/docs/cli-reference#json-output
SAMPLE_SEMGREP_OUTPUT = json.dumps(
    {
        "errors": [],
        "results": [
            {
                "check_id": "python.lang.security.deserialization.pickle.avoid-pickle",
                "path": "app/worker.py",
                "start": {"line": 15, "col": 12, "offset": 320},
                "end": {"line": 15, "col": 35, "offset": 343},
                "extra": {
                    "engine_kind": "OSS",
                    "fingerprint": "semgrep-fp-9876",
                    "is_ignored": False,
                    "lines": "    data = pickle.loads(payload)  # SENSITIVE SOURCE SNIPPET WITH SECRET_TOKEN_123",
                    "message": "Avoid using pickle for deserializing untrusted input.",
                    "metadata": {
                        "cwe": "CWE-502: Deserialization of Untrusted Data",
                        "owasp": "A08:2021 - Software and Data Integrity Failures",
                    },
                    "severity": "ERROR",
                },
            }
        ],
        "version": "1.108.0",
    }
).encode("utf-8")


class SemgrepParserTests(unittest.TestCase):
    def test_parser_extracts_finding_and_strips_code_lines(self):
        results = parse_semgrep_json(SAMPLE_SEMGREP_OUTPUT)
        self.assertEqual(len(results), 1)
        finding = results[0]

        self.assertEqual(finding["rule_id"], "python.lang.security.deserialization.pickle.avoid-pickle")
        self.assertEqual(finding["file"], "app/worker.py")
        self.assertEqual(finding["line"], 15)
        self.assertEqual(finding["severity"], "error")
        self.assertIn("CWE-502", finding["cwe"])

        # Code snippet and tokens must NEVER be retained
        serialized = json.dumps(finding)
        self.assertNotIn("pickle.loads", serialized)
        self.assertNotIn("SENSITIVE SOURCE SNIPPET", serialized)
        self.assertNotIn("SECRET_TOKEN_123", serialized)

    def test_rejection_malformed_json(self):
        with self.assertRaises(ValueError):
            parse_semgrep_json(b"invalid json")

    def test_rejection_wrong_top_level_type(self):
        with self.assertRaises(ValueError):
            parse_semgrep_json(json.dumps(["not", "an", "object"]).encode("utf-8"))

    def test_rejection_missing_results_key(self):
        with self.assertRaises(ValueError):
            parse_semgrep_json(json.dumps({"errors": []}).encode("utf-8"))

    def test_rejection_non_object_result_item(self):
        with self.assertRaises(ValueError):
            parse_semgrep_json(json.dumps({"results": ["not_a_dict"]}).encode("utf-8"))

    def test_rejection_path_traversal(self):
        payload = json.dumps({"results": [{"check_id": "r", "path": "../../etc/shadow"}]}).encode("utf-8")
        with self.assertRaises(ValueError) as ctx:
            parse_semgrep_json(payload)
        self.assertIn("traversal", str(ctx.exception))

    def test_rejection_deeply_nested_json_recursion(self):
        with self.assertRaises(ValueError) as ctx:
            parse_semgrep_json(b"[" * 200000)
        self.assertIn("nesting", str(ctx.exception).lower())

    def test_rejection_oversized_input(self):
        with self.assertRaises(ValueError):
            parse_semgrep_json(b"{" + b" " * (11 * 1024 * 1024) + b"}")


if __name__ == "__main__":
    unittest.main()
