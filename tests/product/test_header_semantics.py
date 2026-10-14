"""Header interpretation regressions beyond the finite evaluation corpus."""

import json
import unittest
from http.client import HTTPException, parse_headers
from io import BytesIO

from packages.scanner_adapters import MAX_HEADER_BYTES, _findings, _header_facts, _HeaderReader


class HeaderSemanticsTests(unittest.TestCase):
    def test_cors_credentials_is_case_sensitive_and_duplicate_fields_are_not_collapsed(self):
        for values, expected in [
            (["true"], True),
            ([" \ttrue\t "], True),
            (["True"], False),
            (["TRUE"], False),
            (["true", "true"], False),
            (["false", "true"], False),
            (["true\xa0"], False),
        ]:
            with self.subTest(values=values):
                facts = self.facts(*[("Access-Control-Allow-Credentials", value) for value in values])
                self.assertEqual(facts["cors_credentials"], expected)
        facts = self.facts(
            ("Access-Control-Allow-Origin", "https://private-origin.invalid"),
            ("Access-Control-Allow-Credentials", "true"),
        )
        self.assertFalse(facts["cors_wildcard"])
        self.assertFalse(any("reflection" in check for check in self.checks(facts)))
        self.assertNotIn("private-origin", json.dumps(facts))
        repeated = self.facts(("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Origin", "*"))
        self.assertFalse(repeated["cors_wildcard"])

    def test_browser_isolation_retains_only_known_tokens_without_claiming_effectiveness(self):
        facts = self.facts(
            ("Cross-Origin-Opener-Policy", 'same-origin; report-to="private-endpoint"'),
            ("Cross-Origin-Embedder-Policy", "credentialless"),
            ("Cross-Origin-Resource-Policy", "same-site"),
        )
        self.assertEqual(
            facts["browser_isolation_tokens"],
            {"coop": "same-origin", "coep": "credentialless", "corp": "same-site"},
        )
        self.assertNotIn("private-endpoint", json.dumps(facts))
        invalid = self.facts(
            ("Cross-Origin-Opener-Policy", "SAME-ORIGIN"),
            ("Cross-Origin-Embedder-Policy", "require-corp"),
            ("Cross-Origin-Embedder-Policy", "require-corp"),
        )
        self.assertEqual(
            invalid["browser_isolation_tokens"],
            {"coop": "unrecognized", "coep": "unrecognized", "corp": "absent"},
        )
        self.assertFalse(any("isolation" in check for check in self.checks(self.facts())))

    def test_prefixed_cookie_facts_follow_attribute_whitespace_and_last_path(self):
        for cookie, expected in [
            ("__Host-private=private-value; Secure=false; Path = /", (False, False, False)),
            ("__hOsT-private=private-value; Secure; Path=/; Path=/child", (False, True, False)),
            ("__Host-private=private-value; Secure; Path=/child; Path=/", (False, False, False)),
            ("__Host-private=private-value; Secure; Path=/; Domain = private.invalid", (False, False, True)),
            ("__Host-private=private-value; Secure; Path=/; Domain=", (False, False, False)),
            (
                "__Host-private=private-value; Secure; Path=/; Domain=; Domain=private.invalid",
                (False, False, True),
            ),
            (
                "__Host-private=private-value; Secure; Path=/; Domain=private.invalid; Domain=",
                (False, False, False),
            ),
            (
                "__Host-private=private-value; Secure; Path=/; Domain=private.invalid; Domain=.",
                (False, False, False),
            ),
            ("__Host-private=private-value; Path=/", (True, False, False)),
            ("__Host-private=private-value; Secure", (False, True, False)),
        ]:
            with self.subTest(cookie=cookie):
                facts = self.facts(("Set-Cookie", cookie))
                flags = facts["cookie_flags"][0]
                self.assertEqual(flags["prefix"], "host")
                self.assertEqual(
                    tuple(
                        flags[key]
                        for key in ("prefix_missing_secure", "prefix_nonroot_path", "prefix_domain_present")
                    ),
                    expected,
                )
                self.assertEqual("cookie_prefix" in self.checks(facts), any(expected))
                for secret in ("private", "private-value", "child", "invalid"):
                    self.assertNotIn(secret, json.dumps(flags))

    def test_prefixed_cookie_limits_and_secure_prefix_keep_response_facts_bounded(self):
        for cookie, missing in [
            ("__Secure-private=value", True),
            ("__sEcUrE-private=value; Secure=false", False),
        ]:
            flags = self.facts(("Set-Cookie", cookie))["cookie_flags"][0]
            self.assertEqual(flags["prefix"], "secure")
            self.assertEqual(flags["prefix_missing_secure"], missing)
        oversized_path = self.facts(("Set-Cookie", "__Host-x=v; Secure; Path=/; Path=/" + "x" * 1024))
        self.assertFalse(oversized_path["cookie_flags"][0]["prefix_nonroot_path"])
        oversized_domain = self.facts(("Set-Cookie", "__Host-x=v; Secure; Path=/; Domain=" + "x" * 1025))
        self.assertFalse(oversized_domain["cookie_flags"][0]["prefix_domain_present"])
        malformed = self.facts(("Set-Cookie", "__Host-x=v; Secure\x00; Path=/"))
        self.assertEqual(malformed["cookie_flags"], [{"parse_error": True}])
        self.assertNotIn("cookie_prefix", self.checks(malformed))

    def test_software_indicators_never_retain_banners_or_claim_a_known_vulnerability(self):
        facts = self.facts(
            ("Server", "Apache/2.4.49 synthetic-private-banner"),
            ("X-Powered-By", "synthetic-private-runtime"),
        )
        self.assertEqual(facts["software_indicators"]["server"], {"present": True, "version_pattern": True})
        self.assertEqual(
            facts["software_indicators"]["x-powered-by"], {"present": True, "version_pattern": False}
        )
        self.assertNotIn("synthetic-private", json.dumps(facts))
        observation = {"facts": facts, "url": "https://127.0.0.1/example", "status_code": 200}
        finding = next(f for f in _findings(observation) if f["evidence"]["check"] == "software_indicators")
        self.assertEqual(finding["severity"], "info")
        self.assertNotIn("CVE", finding["description"])
        # The standard Server field is observed, not an automatic vulnerability.
        self.assertNotIn("software_indicators", self.checks(self.facts(("Server", "Apache/2.4.49"))))

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

    def test_nosniff_uses_the_first_value_and_preserves_duplicate_field_order(self):
        for values, expected in [
            (["nosniff, nosniff"], True),
            (["nosniff, other"], True),
            (["other, nosniff"], False),
            (["nosniff", "other"], True),
            (["other", "nosniff"], False),
            (["", "nosniff"], False),
            ([", nosniff"], False),
            ([" \tNoSnIfF\t , other"], True),
            (["nosniff;"], False),
            (['"nosniff, other"', "nosniff"], False),
            (['"nosniff"'], False),
            (["nosniff\xa0"], False),
            (["\x0bnosniff"], False),
            (["nosniff\r\n\t"], False),
        ]:
            with self.subTest(values=values):
                facts = _header_facts([("x-CoNtEnT-TyPe-OpTiOnS", value) for value in values])
                self.assertEqual(facts["nosniff"], expected)
                self.assertEqual("missing_nosniff" in self.checks(facts), not expected)

    def test_permissive_cookie_pairs_and_unknown_attributes_do_not_hide_httponly_absence(self):
        for cookie in [
            "no-equals-private-cookie",
            "=empty-name-private-cookie",
            "user[id]=private-cookie",
            'prefs={"private-cookie":1}',
            "sid=private-cookie; Unrecognised",
            "sid=private-cookie; Partitioned; Secure",
            "sid=private-cookie; Extra=private-attribute",
            "HttpOnly=private-cookie",
            "sid=HttpOnly",
        ]:
            for suffix, expected in [("", False), ("; hTtPoNlY", True)]:
                with self.subTest(cookie=cookie, suffix=suffix):
                    facts = self.facts(("Set-Cookie", cookie + suffix))
                    self.assertEqual(len(facts["cookie_flags"]), 1)
                    self.assertEqual(facts["cookie_flags"][0]["httponly"], expected)
                    self.assertEqual("cookie_httponly" in self.checks(facts), not expected)
                    self.assertNotIn("private-cookie", json.dumps(facts))
                    self.assertNotIn("private-attribute", json.dumps(facts))
                    self.assertIn("not browser storage acceptance", facts["header_analysis_limits"])

    def test_cookie_flags_parse_separate_attributes_and_last_samesite_without_retaining_values(self):
        for attributes, expected in [
            ("HttpOnly=false; Secure=false; SameSite=lAx", (True, True, "lax")),
            ("SameSite=Strict; SameSite=unknown", (False, False, "unset")),
            ("SameSite=unknown; SameSite=None", (False, False, "none")),
            ('Unknown=HttpOnly; Path=/HttpOnly; SameSite="Lax"', (False, False, "unset")),
            ("Unrecognised; Partitioned; HttpOnly; Other=private-attribute", (True, False, "unset")),
        ]:
            with self.subTest(attributes=attributes):
                facts = self.facts(("Set-Cookie", "private-name=private-value; " + attributes))
                flags = facts["cookie_flags"]
                self.assertEqual(
                    flags, [{"httponly": expected[0], "secure": expected[1], "samesite": expected[2]}]
                )
                serialized = json.dumps(facts)
                for secret in ["private-name", "private-value", "Other", "private-attribute"]:
                    self.assertNotIn(secret, serialized)

    def test_cookie_rejects_controls_anywhere_but_allows_horizontal_tab_whitespace(self):
        for code in [*range(9), *range(10, 32), 127, 256]:
            for cookie in [
                "name" + chr(code) + "=private",
                "name=private" + chr(code),
                "name=private; Unrecognised=" + chr(code),
            ]:
                with self.subTest(code=code, position=cookie.index(chr(code))):
                    facts = self.facts(("Set-Cookie", cookie))
                    self.assertEqual(facts["cookie_flags"], [{"parse_error": True}])
                    self.assertNotIn("cookie_httponly", self.checks(facts))
        facts = self.facts(("Set-Cookie", "\t name \t=\t private \t;\t HttpOnly \t; SameSite= Lax \t"))
        self.assertEqual(facts["cookie_flags"], [{"secure": False, "httponly": True, "samesite": "lax"}])

    def test_cookie_pair_and_attribute_octet_limits_do_not_make_false_cookie_facts(self):
        for value in ["", "=", " \t = \t", " ; HttpOnly", "n=" + "x" * 4096]:
            with self.subTest(length=len(value)):
                facts = self.facts(("Set-Cookie", value))
                self.assertEqual(facts["cookie_flags"], [{"parse_error": True}])
                self.assertNotIn("cookie_httponly", self.checks(facts))
        accepted = self.facts(("Set-Cookie", "n=" + "\xff" * 4095))
        self.assertIn("cookie_httponly", self.checks(accepted))
        for size, expected in [(1024, True), (1025, False)]:
            with self.subTest(attribute_size=size):
                facts = self.facts(("Set-Cookie", "n=v; HttpOnly=" + "x" * size))
                self.assertEqual(facts["cookie_flags"][0]["httponly"], expected)
                self.assertEqual("cookie_httponly" in self.checks(facts), not expected)

    def test_response_header_reader_still_enforces_the_total_wire_budget(self):
        reader = _HeaderReader(BytesIO(b"x" * MAX_HEADER_BYTES))
        self.assertEqual(len(reader.readline()), MAX_HEADER_BYTES)
        self.assertEqual(reader.readline(), b"")
        reader = _HeaderReader(BytesIO(b"x" * (MAX_HEADER_BYTES + 1)))
        with self.assertRaisesRegex(HTTPException, "Response header budget exceeded"):
            reader.readline()

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
