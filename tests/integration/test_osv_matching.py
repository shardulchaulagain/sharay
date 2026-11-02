"""OSV advisory matching: range evaluation as the schema defines it, honest about what it cannot do.

Most of this file was written as acceptance tests before any implementation existed; the
expected results follow the OSV schema's evaluation algorithm, PEP 440 and SemVer 2.0.0.
"""

import json
import unittest

from packages.scanner_adapters.integrations import osv

SECRET = "synthetic-secret-value"


def record(events=None, *, name="demo", ecosystem="PyPI", kind=None, versions=None, **extra):
    affected = {"package": {"ecosystem": ecosystem, "name": name}}
    if events is not None:
        kind = kind or ("ECOSYSTEM" if ecosystem == "PyPI" else "SEMVER")
        affected["ranges"] = [{"type": kind, "events": [{key: value} for key, value in events]}]
    if versions is not None:
        affected["versions"] = versions
    return {"id": "OSV-TEST-1", "summary": "Synthetic advisory", "affected": [affected]} | extra


def package(version, name="demo", ecosystem="PyPI"):
    return {"ecosystem": ecosystem, "name": name, "version": version, "manifest": "requirements.txt"}


def hit(advisory, *packages) -> bool:
    return bool(osv.match(json.dumps(advisory).encode(), list(packages))["findings"])


class RangeEvaluationTests(unittest.TestCase):
    def test_events_are_evaluated_in_order_as_the_schema_defines(self):
        two_windows = [("introduced", "0"), ("fixed", "1.2.3"), ("introduced", "2.0.0"), ("fixed", "2.1.5")]
        cases = [
            (
                [("introduced", "0"), ("fixed", "1.2.3")],
                {"0.0.1": True, "1.2.2": True, "1.2.3": False, "9.0": False},
            ),
            ([("introduced", "1.0.0"), ("fixed", "1.2.3")], {"0.9": False, "1.0.0": True, "1.2.3": False}),
            # Several introduced/fixed pairs in ONE range: each window counts, not only the last pair.
            (two_windows, {"1.0.0": True, "1.5.0": False, "2.0.0": True, "2.1.0": True, "2.1.5": False}),
            # Events may arrive unsorted; the schema says to sort them.
            (two_windows[::-1], {"1.0.0": True, "1.5.0": False, "2.1.0": True, "2.1.5": False}),
            ([("introduced", "0"), ("last_affected", "1.4.0")], {"1.4.0": True, "1.4.1": False}),
            ([("introduced", "0")], {"99.0": True}),
            ([("introduced", "1.0"), ("limit", "2.0"), ("fixed", "3.0")], {"1.5": True, "2.5": False}),
        ]
        for events, expectations in cases:
            for version, expected in expectations.items():
                with self.subTest(events=events, version=version):
                    self.assertEqual(hit(record(events), package(version)), expected)

    def test_pypi_versions_order_by_pep_440(self):
        cases = [
            (
                "1.0",
                {
                    "1.0rc1": True,
                    "1.0.dev1": True,
                    "1.0a1": True,
                    "1.0": False,
                    "1.0.post1": False,
                    "1.0.0": False,
                },
            ),
            ("1.10", {"1.9": True, "1.10": False, "1.9.9": True}),
            ("2.0", {"1!0.5": False, "2.0+local": False, "1.9+local": True}),
        ]
        for fixed, expectations in cases:
            for version, expected in expectations.items():
                with self.subTest(fixed=fixed, version=version):
                    self.assertEqual(
                        hit(record([("introduced", "0"), ("fixed", fixed)]), package(version)), expected
                    )

    def test_npm_versions_order_by_semver_2(self):
        cases = [
            ("2.0.0", {"2.0.0-beta.1": True, "2.0.0": False, "1.99.99": True, "2.0.0+build.5": False}),
            (
                "1.0.0-beta.11",
                {"1.0.0-beta.2": True, "1.0.0-beta.11": False, "1.0.0-alpha": True, "1.0.0": False},
            ),
            ("1.0.0-rc.1", {"1.0.0-beta": True, "1.0.0-rc.1": False, "1.0.0-1": True}),
        ]
        for fixed, expectations in cases:
            for version, expected in expectations.items():
                with self.subTest(fixed=fixed, version=version):
                    advisory = record([("introduced", "0"), ("fixed", fixed)], ecosystem="npm")
                    self.assertEqual(hit(advisory, package(version, ecosystem="npm")), expected)

    def test_an_explicit_versions_list_matches_exactly(self):
        advisory = record(versions=["1.0.0", "1.0.1"])
        self.assertTrue(hit(advisory, package("1.0.1")))
        self.assertFalse(hit(advisory, package("1.0.2")))


class MatchingTests(unittest.TestCase):
    def test_names_follow_each_ecosystem_and_ecosystems_never_cross(self):
        always = [("introduced", "0")]
        self.assertTrue(hit(record(always, name="Flask-Cors"), package("1.0", name="flask_cors")))
        self.assertTrue(hit(record(always, name="zope.interface"), package("1.0", name="Zope-Interface")))
        self.assertTrue(
            hit(record(always, name="@scope/pkg", ecosystem="npm"), package("1.0.0", "@scope/pkg", "npm"))
        )
        self.assertFalse(
            hit(record(always, name="Lodash", ecosystem="npm"), package("1.0.0", "lodash", "npm"))
        )
        self.assertFalse(hit(record(always, name="demo"), package("1.0.0", "demo", "npm")))
        self.assertFalse(hit(record(always, name="demo", ecosystem="npm"), package("1.0")))
        self.assertFalse(hit(record(always, name="demo2"), package("1.0")))

    def test_a_finding_states_what_matched_and_never_guesses_severity(self):
        advisory = record(
            [("introduced", "0"), ("fixed", "1.2.3")],
            aliases=["CVE-2099-0001", "GHSA-xxxx-yyyy-zzzz"],
            database_specific={"severity": "HIGH"},
        )
        result = osv.match(json.dumps([advisory]).encode(), [package("1.0")])
        (finding,) = result["findings"]
        self.assertEqual(
            {key: value for key, value in finding.items() if key != "fingerprint"},
            {
                "advisory": "OSV-TEST-1",
                "aliases": ["CVE-2099-0001", "GHSA-xxxx-yyyy-zzzz"],
                "summary": "Synthetic advisory",
                "severity": "high",
                "ecosystem": "PyPI",
                "package": "demo",
                "version": "1.0",
                "fixed": "1.2.3",
                "manifest": "requirements.txt",
            },
        )
        self.assertRegex(finding["fingerprint"], r"^[0-9a-f]{16}$")
        self.assertEqual((result["not_evaluated"], result["truncated"]), ([], False))
        # A CVSS vector is not a severity word; without database_specific.severity it is unknown.
        scored = record([("introduced", "0")], severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}])
        (unknown,) = osv.match(json.dumps(scored).encode(), [package("1.0")])["findings"]
        self.assertEqual(unknown["severity"], "unknown")
        self.assertIsNone(unknown["fixed"])

    def test_identity_is_stable_and_separates_advisory_package_and_version(self):
        always = record([("introduced", "0")])
        prints = {
            osv.match(json.dumps(advisory).encode(), [pkg])["findings"][0]["fingerprint"]
            for advisory, pkg in (
                (always, package("1.0")),
                (always, package("1.1")),
                (always | {"id": "OSV-TEST-2"}, package("1.0")),
                (record([("introduced", "0")], name="other"), package("1.0", name="other")),
            )
        }
        self.assertEqual(len(prints), 4)
        again = osv.match(json.dumps(always | {"summary": "Reworded"}).encode(), [package("1.0")])
        self.assertIn(again["findings"][0]["fingerprint"], prints)

    def test_withdrawn_advisories_report_nothing(self):
        advisory = record([("introduced", "0")], withdrawn="2026-01-01T00:00:00Z")
        result = osv.match(json.dumps(advisory).encode(), [package("1.0")])
        self.assertEqual((result["findings"], result["not_evaluated"]), ([], []))


class HonestyTests(unittest.TestCase):
    def test_what_cannot_be_evaluated_is_listed_not_guessed_and_not_dropped(self):
        cases = {
            "git range": record([("introduced", "0"), ("fixed", "a" * 40)], kind="GIT"),
            "unparseable bound": record([("introduced", "0"), ("fixed", "not a version")]),
            "bound is not text": record([("introduced", "0"), ("fixed", 2)]),
            "events not a list": record()
            | {
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "demo"},
                        "ranges": [{"type": "ECOSYSTEM", "events": "x"}],
                    }
                ]
            },
            "affected not a list": {"id": "OSV-TEST-1", "affected": "x"},
            "no introduced event": record([("fixed", "1.0")]),
        }
        for label, advisory in cases.items():
            with self.subTest(label):
                result = osv.match(json.dumps([advisory]).encode(), [package("0.5")])
                self.assertEqual(result["findings"], [])
                self.assertEqual([item["advisory"] for item in result["not_evaluated"]], ["OSV-TEST-1"])
                self.assertNotIn("not a version", json.dumps(result))
        # An advisory for a package that is not installed is simply irrelevant, however odd its ranges.
        other = record([("introduced", "0"), ("fixed", "not a version")], name="absent")
        self.assertEqual(osv.match(json.dumps(other).encode(), [package("0.5")])["not_evaluated"], [])
        # One bad advisory does not hide a good one beside it.
        good = record([("introduced", "0")]) | {"id": "OSV-TEST-2"}
        both = osv.match(json.dumps([cases["git range"], good]).encode(), [package("0.5")])
        self.assertEqual([f["advisory"] for f in both["findings"]], ["OSV-TEST-2"])
        self.assertEqual(len(both["not_evaluated"]), 1)

    def test_a_feed_that_is_not_osv_is_rejected_with_fixed_text(self):
        hostile = [
            b"not json",
            b"7",
            b"[" * 200000,
            json.dumps([SECRET]).encode(),
            json.dumps({"summary": SECRET}).encode(),  # no id
            json.dumps({"id": [SECRET]}).encode(),
            json.dumps({"id": "OSV-\u0000" + SECRET}).encode(),
            b'{"id": "OSV-TEST-1", "affected": [], "x": NaN}',
        ]
        for index, data in enumerate(hostile):
            with self.subTest(index), self.assertRaises(ValueError) as caught:
                osv.match(data, [package("1.0")])
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
        for wrong in ("text", None, bytearray(b"[]")):
            with self.assertRaises(ValueError):
                osv.match(wrong, [])
        with self.assertRaises(ValueError):
            osv.match(b" " * (10 * 1024 * 1024 + 1), [])

    def test_text_from_an_advisory_is_redacted_and_bounded(self):
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"
        advisory = record([("introduced", "0")], summary=f"Leaked {token} " + "x" * 5000, details=SECRET)
        result = osv.match(json.dumps(advisory).encode(), [package("1.0")])
        dumped = json.dumps(result)
        self.assertNotIn(token, dumped)
        self.assertNotIn(SECRET, dumped)  # details is never kept
        self.assertLessEqual(len(result["findings"][0]["summary"]), 300)

    def test_truncation_is_reported_only_when_findings_were_left_out(self):
        always = record([("introduced", "0")])
        exactly = [package(f"1.{n}") for n in range(5000)]
        self.assertFalse(osv.match(json.dumps(always).encode(), exactly)["truncated"])
        result = osv.match(json.dumps(always).encode(), exactly + [package("9.9")])
        self.assertEqual((len(result["findings"]), result["truncated"]), (5000, True))


class ReviewFindingsTests(unittest.TestCase):
    """Defects found by reading the first implementation; each was reproduced before the fix."""

    ALWAYS = [("introduced", "0")]

    def run_match(self, advisory, *packages):
        return osv.match(json.dumps(advisory).encode(), list(packages))

    def test_one_declared_version_that_cannot_be_ordered_does_not_stop_the_others(self):
        result = self.run_match(record(self.ALWAYS), package("not-a-version"), package("1.0"))
        self.assertEqual([finding["version"] for finding in result["findings"]], ["1.0"])
        self.assertEqual(
            result["not_evaluated"], [{"package": "demo", "reason": "declared version cannot be ordered"}]
        )
        for broken in (
            {"ecosystem": "PyPI", "name": "demo", "version": None},
            {"ecosystem": "npm", "name": 7, "version": "1.0.0"},
        ):
            with self.assertRaises(ValueError):
                self.run_match(record(self.ALWAYS), broken)
        with self.assertRaises(ValueError):
            osv.match(json.dumps(record(self.ALWAYS)).encode(), ["demo==1.0"])
        other = {"ecosystem": "Go", "name": "demo", "version": "v1.0.0"}
        self.assertEqual(
            self.run_match(record(self.ALWAYS), other),
            {"findings": [], "not_evaluated": [], "truncated": False},
        )

    def test_a_listed_version_is_compared_as_the_ecosystem_orders_it_and_an_odd_one_is_harmless(self):
        self.assertTrue(hit(record(versions=["1.0.0"]), package("1.0")))
        self.assertTrue(
            hit(record(versions=["1.0.0"], ecosystem="npm"), package("1.0.0+build", ecosystem="npm"))
        )
        # A legacy string in the list cannot equal a declared version; the range still decides.
        legacy = record(self.ALWAYS, versions=["0.1dev-r1234", "1.0"])
        result = self.run_match(legacy, package("2.0"))
        self.assertEqual((len(result["findings"]), result["not_evaluated"]), (1, []))
        self.assertEqual(self.run_match(record(versions=["0.1dev-r1234"]), package("2.0"))["findings"], [])
        not_text = self.run_match(record(self.ALWAYS, versions=[["1.0"]]), package("2.0"))
        self.assertEqual((not_text["findings"], len(not_text["not_evaluated"])), ([], 1))

    def test_a_commit_range_beside_a_version_range_does_not_hide_the_version_range(self):
        advisory = record([("introduced", "0"), ("fixed", "2.0")])
        advisory["affected"][0]["ranges"].insert(
            0,
            {
                "type": "GIT",
                "repo": "https://example.invalid/x",
                "events": [{"introduced": "0"}, {"fixed": "a" * 40}],
            },
        )
        result = self.run_match(advisory, package("1.0"))
        self.assertEqual(
            ([finding["fixed"] for finding in result["findings"]], result["not_evaluated"]), (["2.0"], [])
        )
        self.assertEqual(self.run_match(advisory, package("2.0"))["findings"], [])

    def test_an_entry_that_cannot_be_evaluated_does_not_hide_the_next_package(self):
        advisory = record(self.ALWAYS, name="other")
        advisory["affected"].insert(
            0, record([("introduced", "0"), ("fixed", "a" * 40)], kind="GIT")["affected"][0]
        )
        advisory["affected"].insert(1, "not an object")
        result = self.run_match(advisory, package("1.0"), package("1.0", name="other"))
        self.assertEqual([finding["package"] for finding in result["findings"]], ["other"])
        self.assertEqual([item["advisory"] for item in result["not_evaluated"]], ["OSV-TEST-1"])  # once

    def test_a_bound_that_is_not_text_is_not_evaluated_in_either_ecosystem(self):
        for ecosystem, version in (("PyPI", "0.5"), ("npm", "0.5.0")):
            for bound in (2, None, ["1.0.0"], "1.0.0\x00"):
                advisory = record([("introduced", "0"), ("fixed", bound)], ecosystem=ecosystem)
                result = self.run_match(advisory, package(version, ecosystem=ecosystem))
                self.assertEqual(
                    (result["findings"], len(result["not_evaluated"])), ([], 1), (ecosystem, bound)
                )

    def test_two_entries_for_one_package_give_one_finding(self):
        advisory = record([("introduced", "0"), ("fixed", "2.0")])
        advisory["affected"].append(record([("introduced", "0"), ("fixed", "3.0")])["affected"][0])
        self.assertEqual(len(self.run_match(advisory, package("1.0"))["findings"]), 1)

    def test_malformed_aliases_matter_only_for_an_advisory_about_a_declared_package(self):
        irrelevant = record(self.ALWAYS, name="absent", aliases=[7])
        self.assertEqual(self.run_match(irrelevant, package("1.0"))["not_evaluated"], [])
        for aliases in ([7], "CVE-2099-0001", [SECRET + "\x00"]):
            result = self.run_match(record(self.ALWAYS, aliases=aliases), package("1.0"))
            self.assertEqual(
                (result["findings"], [item["reason"] for item in result["not_evaluated"]]),
                ([], ["aliases are malformed"]),
            )
            self.assertNotIn(SECRET, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
