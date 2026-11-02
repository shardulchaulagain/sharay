"""Hermetic tests for the adopted multi-method BodyFuzzer and its FP-control fixes."""

import json
import unittest
from urllib.parse import unquote

from packages.scanner_adapters.integrations.body_fuzzer import BodyFuzzer, FuzzTarget
from packages.security_policies import Destination


class BodyFuzzerTests(unittest.TestCase):
    _dest = Destination(
        "http://127.0.0.1:8080/api", "http", "127.0.0.1", 8080, "/api", "http://127.0.0.1:8080", "127.0.0.1"
    )

    def _fuzzer(self, mock_req):
        return BodyFuzzer(self._dest, "127.0.0.1", request_fn=mock_req)

    def test_build_form_targets_one_per_named_input(self):
        forms = [
            {
                "action": "/login",
                "method": "POST",
                "inputs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}],
            }
        ]
        targets = BodyFuzzer.build_form_targets(forms)
        self.assertEqual([t.parameter for t in targets], ["username", "password"])
        self.assertEqual(targets[0].endpoint, "/login")
        self.assertEqual(targets[0].method, "POST")

    def test_mutate_json_payload_is_immutable_and_nested(self):
        template = {"user": {"profile": {"name": "alice"}}, "tags": ["admin", "editor"]}
        mutated = BodyFuzzer.mutate_json_payload(template, ["user", "profile", "name"], "x")
        self.assertEqual(mutated["user"]["profile"]["name"], "x")
        self.assertEqual(template["user"]["profile"]["name"], "alice")
        self.assertEqual(BodyFuzzer.mutate_json_payload(template, ["tags", "0"], "root")["tags"][0], "root")

    def test_time_based_sqli_confirmed_across_three_trials(self):
        def mock_req(method, path, headers=None, body=None, timeout=None):
            if body and "pg_sleep" in body:
                return 200, {}, "ok", 5100.0
            return 200, {}, "ok", 30.0

        target = FuzzTarget(endpoint="/search", parameter="query", raw_body_template={"query": "test"})
        finding = self._fuzzer(mock_req).audit_time_based_sqli(target)
        self.assertIsNotNone(finding)
        self.assertIn("Time-Based Blind SQL Injection (PostgreSQL)", finding["title"])
        self.assertEqual(finding["status"], "confirmed")
        self.assertEqual(finding["poc"]["trials"], 3)

    def test_time_based_sqli_rejected_when_a_trial_is_fast(self):
        calls = {"n": 0}

        def mock_req(method, path, headers=None, body=None, timeout=None):
            if body and "pg_sleep" in body:
                calls["n"] += 1
                return 200, {}, "ok", (5100.0 if calls["n"] < 3 else 40.0)  # 3rd trial is fast -> jitter
            return 200, {}, "ok", 30.0

        target = FuzzTarget(endpoint="/search", parameter="query", raw_body_template={"query": "test"})
        # Only PostgreSQL flaps; the other DBMS payloads never delay, so no finding at all.
        self.assertIsNone(self._fuzzer(mock_req).audit_time_based_sqli(target))

    def test_ssti_detected_on_evaluated_canary(self):
        def mock_req(method, path, headers=None, body=None, timeout=None):
            if method == "GET":
                return 200, {}, "<html>Hello Guest</html>", 20.0
            if body and "1337*1337" in unquote(body):
                return 200, {}, "<html>Result 1787569 ready</html>", 25.0
            return 200, {}, "<html>Hello Guest</html>", 20.0

        target = FuzzTarget(endpoint="/render", parameter="tpl")
        finding = self._fuzzer(mock_req).audit_ssti(target)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["poc"]["evaluated_result"], "1787569")
        self.assertEqual(finding["cwe_id"], "CWE-1336")

    def test_ssti_not_confirmed_on_literal_reflection(self):
        # Response echoes the literal payload (reflection/XSS), not an evaluated result -> no SSTI.
        def mock_req(method, path, headers=None, body=None, timeout=None):
            if method == "POST" and body:
                return 200, {}, "You sent: " + unquote(body), 20.0
            return 200, {}, "baseline", 20.0

        target = FuzzTarget(endpoint="/render", parameter="tpl")
        self.assertIsNone(self._fuzzer(mock_req).audit_ssti(target))

    def test_nosql_confirmed_differentially(self):
        def mock_req(method, path, headers=None, body=None, timeout=None):
            if body and '"$ne": null' in body:
                return 200, {}, json.dumps({"token": "eyJ...", "status": "authenticated"}), 35.0
            return 401, {}, json.dumps({"error": "invalid"}), 20.0

        target = FuzzTarget(
            endpoint="/auth",
            method="POST",
            is_json=True,
            parameter="password",
            json_path=["password"],
            raw_body_template={"username": "admin", "password": "secret"},
        )
        finding = self._fuzzer(mock_req).audit_nosql_injection(target)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["status"], "suspected")
        self.assertEqual(finding["cwe_id"], "CWE-943")

    def test_nosql_not_confirmed_when_control_also_authenticates(self):
        # Page always returns an auth-looking 200; the differential control fires too -> no finding.
        def mock_req(method, path, headers=None, body=None, timeout=None):
            return 200, {}, json.dumps({"status": "success", "welcome": True}), 20.0

        target = FuzzTarget(
            endpoint="/auth",
            method="POST",
            is_json=True,
            parameter="password",
            json_path=["password"],
            raw_body_template={"username": "admin", "password": "secret"},
        )
        self.assertIsNone(self._fuzzer(mock_req).audit_nosql_injection(target))

    def test_ssti_fingerprints_jinja2(self):
        def mock_req(method, path, headers=None, body=None, timeout=None):
            if method == "GET":
                return 200, {}, "<html>Hello Guest</html>", 20.0
            if body and "1337*1337" in unquote(body):
                return 200, {}, "<html>Result 1787569 ready</html>", 25.0
            if body and "7*'7'" in unquote(body):
                return 200, {}, "<html>Multiplication result: 7777777</html>", 25.0
            return 200, {}, "<html>Hello Guest</html>", 20.0

        target = FuzzTarget(endpoint="/render", parameter="tpl")
        finding = self._fuzzer(mock_req).audit_ssti(target)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["poc"]["fingerprinted_engine"], "Jinja2")
        self.assertIn("Jinja2", finding["description"])

    def test_ssti_fingerprints_twig(self):
        def mock_req(method, path, headers=None, body=None, timeout=None):
            if method == "GET":
                return 200, {}, "<html>Hello Guest</html>", 20.0
            if body and "1337*1337" in unquote(body):
                return 200, {}, "<html>Result 1787569 ready</html>", 25.0
            if body and "7*'7'" in unquote(body):
                return 200, {}, "<html>Multiplication result: 49</html>", 25.0
            return 200, {}, "<html>Hello Guest</html>", 20.0

        target = FuzzTarget(endpoint="/render", parameter="tpl")
        finding = self._fuzzer(mock_req).audit_ssti(target)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["poc"]["fingerprinted_engine"], "Twig")
        self.assertIn("Twig", finding["description"])

    def test_ssti_fingerprints_freemarker(self):
        def mock_req(method, path, headers=None, body=None, timeout=None):
            if method == "GET":
                return 200, {}, "<html>Hello Guest</html>", 20.0
            # Polyglot 1 (Jinja) not supported, Polyglot 2 (Spring/Freemarker) triggers
            if body and "${1337*1337}" in unquote(body):
                return 200, {}, "<html>Result 1787569 ready</html>", 25.0
            if body and "upper_case" in unquote(body):
                return 200, {}, "<html>Result FREEMARKER ready</html>", 25.0
            return 200, {}, "<html>Hello Guest</html>", 20.0

        target = FuzzTarget(endpoint="/render", parameter="tpl")
        finding = self._fuzzer(mock_req).audit_ssti(target)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["poc"]["fingerprinted_engine"], "Freemarker")
        self.assertIn("Freemarker", finding["description"])


if __name__ == "__main__":
    unittest.main()
