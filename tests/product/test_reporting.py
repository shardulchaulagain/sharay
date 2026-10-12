"""Regression checks for exports of untrusted assessment content."""

import json
import unittest
from copy import deepcopy
from html.parser import HTMLParser

from packages.reporting import redact, render_report


def assessment_data():
    return {
        "assessment": {
            "id": "assessment-1",
            "status": "completed_with_errors",
            "profile": "safe-http",
            "created_at": "2026-10-11T10:00:00Z",
            "started_at": "2026-10-11T10:01:00Z",
            "finished_at": "2026-10-11T10:02:00Z",
        },
        "project": {"id": "project-1", "name": "Synthetic local test"},
        "target": {"url": "http://127.0.0.1:8765/"},
        "scope": {"version": 2, "verification_status": "approved_lab", "excluded_paths": ["/excluded"]},
        "checks": [
            {"name": "headers", "status": "completed"},
            {"name": "redirect", "status": "failed", "error": "Out-of-scope redirect"},
        ],
        "observations": [
            {
                "id": "obs-1",
                "evidence_id": "evidence-1",
                "evidence_hash": "abc123",
                "value": {"Authorization": "Bearer hidden-value"},
            }
        ],
        "findings": [
            {
                "id": "finding-1",
                "title": "Missing content type protection",
                "severity": "low",
                "confidence": "high",
                "status": "confirmed",
                "description": "Observed on the approved synthetic fixture",
                "affected_url": "http://127.0.0.1:8765/",
                "remediation": "Set X-Content-Type-Options: nosniff",
                "evidence": [{"observation_id": "obs-1", "evidence_hash": "abc123"}],
            }
        ],
        "events": [{"event": "scanner_failed", "message": "Out-of-scope redirect"}],
        "generated_at": "2026-10-11T10:03:00Z",
        "synthetic": True,
    }


class ParsedHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


class ReportingTests(unittest.TestCase):
    def test_recursive_redaction_preserves_evidence_and_original(self):
        original = {
            "nested": [
                {
                    "apiKey": "api-secret",
                    "session_token": "session-secret",
                    "Set-Cookie": "session=cookie-secret",
                    "password": "password-secret",
                }
            ],
            "evidence_hash": "sha256-preserved",
            "message": "Authorization: Bearer bearer-secret\npassword=assignment-secret\n"
            "-----BEGIN RSA PRIVATE KEY-----\nprivate-material\n-----END RSA PRIVATE KEY-----",
            "url": "https://user:user-secret@example.test/path?token=query-secret&normal=value",
        }
        before = deepcopy(original)
        result = redact(original)
        serialized = json.dumps(result)
        for secret in (
            "api-secret",
            "session-secret",
            "cookie-secret",
            "password-secret",
            "bearer-secret",
            "assignment-secret",
            "private-material",
            "user-secret",
            "query-secret",
        ):
            self.assertNotIn(secret, serialized)
        self.assertIn("sha256-preserved", serialized)
        self.assertIn("normal=value", result["url"])
        self.assertEqual(original, before)

    def test_json_stable_metadata_and_separate_confidence(self):
        data = assessment_data()
        data["scope"] = {
            "version": 2,
            "verification_method": "explicit_controlled_lab",
            "approved_at": "2026-10-11T10:00:00Z",
            "authorized_by": "owner-1",
        }
        data["events"].append({"detail": {"adapter": "safe_http", "version": "test-version"}})
        raw, mime = render_report(data, "json")
        self.assertEqual((raw, mime), render_report(data, "json"))
        self.assertEqual(mime, "application/json")
        result = json.loads(raw)
        self.assertEqual(result["report_metadata"]["scope_version"], 2)
        self.assertEqual(result["tools"], [{"name": "safe_http", "version": "test-version"}])
        self.assertEqual(result["report_metadata"]["evidence_hashes"], ["abc123"])
        self.assertEqual(result["findings"][0]["severity"], "low")
        self.assertEqual(result["findings"][0]["confidence"], "high")
        self.assertNotIn("hidden-value", raw.decode())
        self.assertNotIn("report_metadata", data)

    def test_mapping_key_redaction_preserves_colliding_nested_records(self):
        self.assertEqual(redact({1: "integer key", "1": "text key"}), {"1": "integer key", "1#2": "text key"})
        first = "ghp_" + "A" * 36
        second = "ghp_" + "B" * 36
        entries = [
            (first, {"fact": "first observation"}),
            (second, {"fact": "second observation"}),
            ("[REDACTED]", {"fact": "ordinary placeholder"}),
            ("[REDACTED]#2", {"fact": "ordinary suffix"}),
        ]
        for order in (entries, list(reversed(entries))):
            with self.subTest(ordinary_labels_first=order[0][0] == "[REDACTED]#2"):
                original = {"id": "obs-1", "nested": [dict(order)], "evidence_hash": "preserved"}
                before = deepcopy(original)
                clean = redact(original)
                records = clean["nested"][0]
                self.assertEqual(len(records), len(order))
                self.assertCountEqual(list(records.values()), [item for _, item in order])
                self.assertEqual((clean["id"], clean["evidence_hash"]), ("obs-1", "preserved"))
                self.assertEqual(clean, redact(clean))
                self.assertEqual(clean, redact(original))
                self.assertEqual(original, before)
                for token in (first, second):
                    self.assertNotIn(token, json.dumps(clean))

                data = assessment_data()
                data["observations"][0]["value"] = original
                for format in ("json", "html", "markdown"):
                    with self.subTest(format=format):
                        raw, _ = render_report(data, format)
                        rendered = raw.decode()
                        for token in (first, second):
                            self.assertNotIn(token, rendered)
                        for _, item in order:
                            self.assertIn(item["fact"], rendered)
                exported = json.loads(render_report(data, "json")[0])
                self.assertEqual(exported["observations"][0]["value"], clean)

    def test_control_split_sensitive_keys_are_masked_before_export(self):
        markers = {"Authorization\x00": "SYNTHETIC_AUTH_MARKER", "pass\x00word": "SYNTHETIC_PASS_MARKER"}
        facts = {
            "cookie_flags": [{"secure": True, "httponly": True, "samesite": "lax"}],
            "cors_credentials": True,
        }
        malformed = markers | {
            "coo\x00kie_flags": facts["cookie_flags"],
            "cors_credentials\x00": facts["cors_credentials"],
        }
        original = {"nested": [malformed], "typed_facts": facts}
        before = deepcopy(original)
        clean = redact(original)
        self.assertEqual(
            clean["nested"][0],
            {
                name: "[REDACTED]"
                for name in ("Authorization", "password", "cookie_flags", "cors_credentials")
            },
        )
        self.assertEqual(clean["typed_facts"], facts)
        self.assertEqual(clean, redact(clean))
        self.assertEqual(original, before)
        data = assessment_data()
        data["observations"][0]["value"] = original
        for format in ("json", "html", "markdown"):
            with self.subTest(format=format):
                raw, _ = render_report(data, format)
                for marker in markers.values():
                    self.assertNotIn(marker, raw.decode())
        exported = json.loads(render_report(data, "json")[0])
        self.assertEqual(exported["observations"][0]["value"], clean)

    def test_html_escapes_untrusted_markup_and_exposes_failures(self):
        data = assessment_data()
        data["findings"][0]["title"] = '<script>alert("test")</script><img src=x onerror=alert(1)>'
        data["observations"][0]["value"]["body"] = "</pre><iframe src='https://example.test'></iframe>"
        raw, mime = render_report(data, "html")
        html = raw.decode()
        parser = ParsedHTML()
        parser.feed(html)
        self.assertNotIn("script", parser.tags)
        self.assertNotIn("img", parser.tags)
        self.assertNotIn("iframe", parser.tags)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Out-of-scope redirect", html)
        self.assertIn("not an OS sandbox", html)
        self.assertIn("literal loopback", html)
        self.assertNotIn("hidden-value", html)
        self.assertEqual(mime, "text/html; charset=utf-8")

    def test_empty_reports_have_honest_coverage(self):
        data = assessment_data()
        data["findings"] = []
        for format in ("html", "markdown"):
            raw, _ = render_report(data, format)
            self.assertIn(b"No confirmed vulnerabilities are recorded", raw)
            self.assertIn(b"Out-of-scope redirect", raw)
            self.assertIn(b"not establish", raw)
        self.assertEqual(json.loads(render_report(data, "json")[0])["findings"], [])

    def test_markdown_does_not_promote_target_content_to_markup(self):
        data = assessment_data()
        data["findings"][0]["title"] = "Malicious\n# injected heading <script>code</script>"
        data["observations"][0]["value"]["body"] = "```\n<script>code</script>\n```"
        raw, mime = render_report(data, "markdown")
        text = raw.decode()
        self.assertNotIn("\n# injected heading", text)
        self.assertTrue(all(line.startswith("    ") for line in text.splitlines() if "<script>" in line))
        self.assertEqual(mime, "text/markdown; charset=utf-8")

    def test_pdf_generates_local_pages_with_untrusted_long_content(self):
        data = assessment_data()
        data["findings"][0]["title"] = "<script>inert</script>"
        data["findings"][0]["description"] = "Long evidence " * 1200 + "\x00 Unicode: \u2603"
        raw, mime = render_report(data, "pdf")
        self.assertTrue(raw.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", raw)
        self.assertGreater(len(raw), 2000)
        self.assertEqual(mime, "application/pdf")

    def test_invalid_format_is_explicit(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            render_report(assessment_data(), "sarif")
        with self.assertRaisesRegex(ValueError, "dictionary"):
            render_report([], "json")

    def test_redaction_preserves_only_typed_cookie_configuration_facts(self):
        facts = {
            "cookie_flags": [{"secure": False, "httponly": True, "samesite": "lax"}],
            "cors_credentials": True,
        }
        self.assertEqual(redact(facts), facts)
        for value in ("raw-secret", [{"value": "raw-secret"}], [{"httponly": "raw-secret"}]):
            self.assertEqual(redact({"cookie_flags": value}), {"cookie_flags": "[REDACTED]"})
        self.assertEqual(redact({"cors_credentials": "raw-secret"}), {"cors_credentials": "[REDACTED]"})


if __name__ == "__main__":
    unittest.main()
