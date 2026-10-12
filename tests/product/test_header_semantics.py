"""Header interpretation regressions beyond the finite evaluation corpus."""

import json
import unittest
from http.client import parse_headers
from io import BytesIO

from packages.scanner_adapters import _findings, _header_facts


class HeaderSemanticsTests(unittest.TestCase):
    def facts(self, *headers):
        return _header_facts(
            [("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), *headers]
        )

    def checks(self, facts):
        observation = {"facts": facts, "url": "http://127.0.0.1/example", "status_code": 200}
        return {finding["evidence"]["check"] for finding in _findings(observation)}

    def test_nonempty_unknown_or_reporting_directive_never_claims_csp_effectiveness(self):
        for policy in ["not-a-real-directive", "report-uri /reports", "default-src *"]:
            with self.subTest(policy=policy):
                facts = self.facts(("Content-Security-Policy", policy))
                self.assertTrue(facts["csp_nonempty"])
                self.assertNotIn("csp_effective", facts)
                self.assertIn("not policy validity", facts["header_analysis_limits"])
        for policy in ["", " ; ; \t"]:
            with self.subTest(policy=policy):
                self.assertIn("missing_csp", self.checks(self.facts(("Content-Security-Policy", policy))))

    def test_only_first_ancestor_directive_in_each_policy_controls_framing(self):
        for policy, expected in [
            ("frame-ancestors *; frame-ancestors 'none'", False),
            ("frame-ancestors 'none'; frame-ancestors *", True),
            ("FrAmE-AnCeStOrS 'self'; frame-ancestors *", True),
        ]:
            with self.subTest(policy=policy):
                facts = self.facts(("Content-Security-Policy", policy))
                self.assertEqual(facts["framing_host_restriction_identified"], expected)
                self.assertEqual("missing_frame_policy" in self.checks(facts), not expected)

    def test_http_accepted_vt_and_fs_do_not_become_csp_whitespace(self):
        for separator in ["\x0b", "\x1c"]:
            for policy in ["frame-ancestors" + separator + "'none'", separator + "frame-ancestors 'none'"]:
                with self.subTest(separator=repr(separator), policy=repr(policy)):
                    parsed = parse_headers(
                        BytesIO(("Content-Security-Policy: " + policy + "\r\n\r\n").encode("ascii"))
                    )
                    self.assertEqual(parsed.defects, [])
                    facts = self.facts(*list(parsed.items()))
                    self.assertFalse(facts["csp_has_frame_ancestors"])
                    self.assertFalse(facts["framing_host_restriction_identified"])
                    self.assertIn("missing_frame_policy", self.checks(facts))

    def test_vt_and_fs_malformed_names_do_not_shadow_the_first_valid_directive(self):
        for separator in ["\x0b", "\x1c"]:
            for policy, expected in [
                ("frame-ancestors" + separator + "'none'; frame-ancestors *", False),
                ("frame-ancestors" + separator + "*; frame-ancestors 'none'", True),
                ("frame-ancestors *; frame-ancestors" + separator + "'none'", False),
                ("frame-ancestors 'none'; frame-ancestors" + separator + "*", True),
            ]:
                with self.subTest(separator=repr(separator), policy=repr(policy)):
                    parsed = parse_headers(
                        BytesIO(("Content-Security-Policy: " + policy + "\r\n\r\n").encode("ascii"))
                    )
                    self.assertEqual(parsed.defects, [])
                    facts = self.facts(*list(parsed.items()))
                    self.assertTrue(facts["csp_has_frame_ancestors"])
                    self.assertEqual(facts["framing_host_restriction_identified"], expected)

    def test_csp_permitted_ascii_whitespace_still_splits_names_and_values(self):
        for separator in [" ", "\t", "\n", "\f", "\r"]:
            with self.subTest(separator=repr(separator)):
                policy = separator + "frame-ancestors" + separator + "'none'" + separator
                facts = self.facts(("Content-Security-Policy", policy))
                self.assertTrue(facts["framing_host_restriction_identified"])

    def test_empty_ancestor_directive_has_an_empty_allowlist(self):
        facts = self.facts(("Content-Security-Policy", "frame-ancestors; frame-ancestors *"))
        self.assertTrue(facts["csp_has_frame_ancestors"])
        self.assertTrue(facts["framing_host_restriction_identified"])
        self.assertNotIn("missing_frame_policy", self.checks(facts))

    def test_bare_and_all_host_web_wildcards_are_distinct_from_narrow_domain_wildcards(self):
        for source in [
            "*",
            "http:",
            "https:",
            "http: https:",
            "https://*",
            "http://*:*",
            "'none' https://*",
            "'self' *",
        ]:
            with self.subTest(source=source):
                facts = self.facts(("Content-Security-Policy", "frame-ancestors " + source))
                self.assertFalse(facts["framing_host_restriction_identified"])
                self.assertIn("missing_frame_policy", self.checks(facts))
        for source in [
            "'self'",
            "'none'",
            "*.example.com",
            "https://*.example.com",
            "https://example.com:*",
            "https://example.com",
        ]:
            with self.subTest(source=source):
                facts = self.facts(("Content-Security-Policy", "frame-ancestors " + source))
                self.assertTrue(facts["framing_host_restriction_identified"])
                self.assertNotIn("missing_frame_policy", self.checks(facts))

    def test_repeated_csp_fields_preserve_a_restrictive_policy_in_either_order(self):
        for values in [
            ("frame-ancestors 'none'", "frame-ancestors *"),
            ("frame-ancestors *", "frame-ancestors 'self'"),
            ("frame-ancestors 'none'", "default-src *"),
        ]:
            for ordered in [values, values[::-1]]:
                with self.subTest(values=ordered):
                    facts = self.facts(*[("Content-Security-Policy", value) for value in ordered])
                    self.assertTrue(facts["framing_host_restriction_identified"])

    def test_comma_delimited_csp_policies_are_not_collapsed_into_one_directive_list(self):
        for value in [
            "default-src *, frame-ancestors 'none'",
            "frame-ancestors 'none', default-src *",
            "frame-ancestors *, frame-ancestors 'self'",
        ]:
            with self.subTest(value=value):
                self.assertTrue(
                    self.facts(("Content-Security-Policy", value))["framing_host_restriction_identified"]
                )

    def test_enforced_ancestor_directive_overrides_even_valid_xfo(self):
        facts = self.facts(("X-Frame-Options", "DENY"), ("Content-Security-Policy", "frame-ancestors *"))
        self.assertTrue(facts["frame_options_valid"])
        self.assertFalse(facts["framing_host_restriction_identified"])
        self.assertIn("missing_frame_policy", self.checks(facts))
        report_only = self.facts(
            ("X-Frame-Options", "DENY"), ("Content-Security-Policy-Report-Only", "frame-ancestors *")
        )
        self.assertFalse(report_only["csp_has_frame_ancestors"])
        self.assertTrue(report_only["framing_host_restriction_identified"])

    def test_xfo_multi_value_html_processing_rules_and_invalid_tokens(self):
        for values, restricted in [
            (["DENY", "deny"], True),
            (["DENY\r\n\t"], True),
            (["SAMEORIGIN, SAMEORIGIN"], True),
            (["DENY", "SAMEORIGIN"], True),
            (["SAMEORIGIN,"], True),
            (["ALLOWALL", "INVALID"], True),
            (["INVALID", "OTHER"], False),
            (["ALLOWALL"], False),
        ]:
            with self.subTest(values=values):
                facts = self.facts(*[("X-Frame-Options", value) for value in values])
                self.assertEqual(facts["framing_host_restriction_identified"], restricted)
        self.assertFalse(self.facts(("X-Frame-Options", "DENY, INVALID"))["frame_options_valid"])

    def test_referrer_fields_combine_recognized_tokens_instead_of_discarding_earlier_fields(self):
        for values, recognized in [
            (["no-referrer", "bogus"], True),
            (["bogus", "NO-REFERRER"], True),
            (["NO-REFERRER\r\n\t"], True),
            (["no-referrer, unsafe-url"], True),
            (["bogus", "unknown"], False),
            (["no-referrer\xa0"], False),
        ]:
            with self.subTest(values=values):
                facts = _header_facts([("Referrer-Policy", value) for value in values])
                self.assertEqual(facts["referrer_policy_valid"], recognized)
                self.assertIn("not a privacy-strength", facts["header_analysis_limits"])

    def test_observations_retain_only_facts_and_stable_finding_keys(self):
        facts = self.facts(
            ("Content-Security-Policy", "default-src 'none'; report-uri /private-token-123"),
            ("Set-Cookie", "secret=private-cookie-123; HttpOnly"),
            ("X-Demo", "private-header-123"),
        )
        serialized = json.dumps(facts)
        for secret in ["private-token-123", "private-cookie-123", "private-header-123"]:
            self.assertNotIn(secret, serialized)
        self.assertEqual(self.checks(facts), {"missing_frame_policy"})

    def test_historical_facts_remain_readable_without_rewriting_observations(self):
        facts = self.facts(("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"))
        facts["csp_effective"] = facts.pop("csp_nonempty")
        facts.pop("framing_host_restriction_identified")
        before = json.dumps(facts, sort_keys=True)
        self.assertEqual(self.checks(facts), set())
        self.assertEqual(json.dumps(facts, sort_keys=True), before)
        # Version 1.0 stored presence facts before recognized-value checks existed.
        facts.pop("frame_options_valid")
        facts.pop("referrer_policy_valid")
        facts.pop("csp_effective")
        self.assertEqual(self.checks(facts), set())


if __name__ == "__main__":
    unittest.main()
