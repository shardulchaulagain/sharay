"""Safe browser-workflow validator (L3): only observe-only verbs survive; no execution."""

import unittest

from packages.scanner_adapters.integrations.browser import BrowserWorkflowError, validate_workflow


class BrowserWorkflowTests(unittest.TestCase):
    def test_a_safe_observe_only_workflow_is_normalised(self):
        plan = validate_workflow(
            [
                {"verb": "goto", "url": "https://example.com/login"},
                {"verb": "wait", "ms": 500},
                {"verb": "read_text", "label": "Welcome"},
                {"verb": "read_text"},
                {"verb": "click_text", "text": "Dashboard"},
                {"verb": "screenshot"},
                {"verb": "back"},
            ]
        )
        self.assertEqual(
            [s["verb"] for s in plan],
            ["goto", "wait", "read_text", "read_text", "click_text", "screenshot", "back"],
        )
        self.assertIsNone(plan[3]["label"])

    def test_loopback_http_is_allowed_but_other_schemes_and_credentials_are_not(self):
        self.assertTrue(validate_workflow([{"verb": "goto", "url": "http://127.0.0.1:8905/app"}]))
        for bad in ("file:///etc/passwd", "http://example.com/notloopback", "https://u:p@example.com/"):
            with self.assertRaises(BrowserWorkflowError):
                validate_workflow([{"verb": "goto", "url": bad}])

    def test_unsafe_verbs_are_rejected_not_ignored(self):
        for bad in (
            {"verb": "evaluate", "script": "fetch('/x')"},
            {"verb": "fill", "selector": "#password", "value": "hunter2"},
            {"verb": "upload", "path": "/etc/passwd"},
            {"verb": "download", "url": "https://example.com/x"},
            {"verb": "type", "text": "secret"},
        ):
            with self.assertRaises(BrowserWorkflowError):
                validate_workflow([{"verb": "goto", "url": "https://example.com/"}, bad])

    def test_a_recognized_credential_in_a_url_or_label_is_rejected(self):
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        with self.assertRaises(BrowserWorkflowError):
            validate_workflow([{"verb": "goto", "url": f"https://example.com/cb?token={token}"}])
        with self.assertRaises(BrowserWorkflowError):
            validate_workflow([{"verb": "click_text", "text": f"Bearer {token}"}])

    def test_limits_and_shapes(self):
        with self.assertRaises(BrowserWorkflowError):
            validate_workflow([])
        with self.assertRaises(BrowserWorkflowError):
            validate_workflow([{"verb": "goto", "url": "https://x.test/"}] * 51)
        with self.assertRaises(BrowserWorkflowError):
            validate_workflow([{"verb": "wait", "ms": 999999}])
        with self.assertRaises(BrowserWorkflowError):
            validate_workflow([{"verb": "click_text", "text": "x" * 300}])


if __name__ == "__main__":
    unittest.main()
