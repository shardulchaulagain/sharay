"""Gitleaks, Semgrep and Nuclei report parsers: strict, bounded, and nothing secret retained.

No tool is installed here. Samples are hand-written from each tool's documented format and
have never been compared with real output.
"""

import json
import unittest

from packages.scanner_adapters.integrations import gitleaks, nuclei, semgrep
from packages.scanner_adapters.integrations._parsing import MAX_FINDINGS, MAX_REPORT_BYTES

SECRET = "synthetic-secret-value"
GITLEAKS = {
    "Description": "AWS access key",
    "RuleID": "aws-access-token",
    "File": "config/settings.py",
    "StartLine": 12,
    "EndLine": 12,
    "Match": f"key = {SECRET}",
    "Secret": SECRET,
    "Commit": "0123abcd",
    "Author": SECRET,
    "Email": f"{SECRET}@example.invalid",
    "Message": f"add key {SECRET}",
    "Fingerprint": "0123abcd:config/settings.py:aws-access-token:12",
}
SEMGREP = {
    "check_id": "python.lang.security.audit.exec-detected",
    "path": "src/app.py",
    "start": {"line": 7, "col": 1},
    "end": {"line": 7, "col": 20},
    "extra": {
        "severity": "ERROR",
        "message": f"Detected exec of {SECRET}",
        "lines": f"exec({SECRET!r})",
        "metadata": {"cwe": ["CWE-95: Eval Injection"], "owasp": "A03"},
    },
}
NUCLEI = {
    "template-id": "exposed-debug-page",
    "info": {"name": "Exposed debug page", "severity": "medium", "description": SECRET},
    "type": "http",
    "host": "127.0.0.1:8080",
    "matched-at": f"http://user:{SECRET}@127.0.0.1:8080/admin/debug?token={SECRET}#{SECRET}",
    "matcher-name": "debug-banner",
    "extracted-results": [SECRET],
    "request": f"GET /admin/debug HTTP/1.1\r\nAuthorization: {SECRET}",
    "response": SECRET,
    "curl-command": f"curl -H 'Authorization: {SECRET}' http://127.0.0.1:8080/admin/debug",
}


def encode(value) -> bytes:
    return json.dumps(value).encode()


def lines(*items) -> bytes:
    return b"\n".join(encode(item) for item in items) + b"\n"


class ToolReportParserTests(unittest.TestCase):
    def test_documented_samples_become_findings_without_any_secret_text(self):
        leaks = gitleaks.parse(encode([GITLEAKS]))
        code = semgrep.parse(encode({"results": [SEMGREP], "errors": []}))
        web = nuclei.parse(
            lines(NUCLEI, NUCLEI | {"matched-at": "db.example.invalid:5432", "matcher-name": None})
        )
        self.assertEqual(
            {k: v for k, v in leaks["findings"][0].items() if k != "fingerprint"},
            {"rule": "aws-access-token", "file": "config/settings.py", "line": 12},
        )
        self.assertEqual(
            {k: v for k, v in code["findings"][0].items() if k != "fingerprint"},
            {
                "rule": "python.lang.security.audit.exec-detected",
                "file": "src/app.py",
                "line": 7,
                "severity": "error",
                "cwe": ["CWE-95: Eval Injection"],
            },
        )
        first, second = web["findings"]
        self.assertEqual(
            (first["template"], first["name"], first["severity"], first["matched_at"], first["matcher"]),
            (
                "exposed-debug-page",
                "Exposed debug page",
                "medium",
                "http://127.0.0.1:8080/admin/debug",
                "debug-banner",
            ),
        )
        self.assertEqual((second["matched_at"], second["matcher"]), ("db.example.invalid:5432", None))
        for result in (leaks, code, web):
            self.assertFalse(result["truncated"])
            self.assertNotIn(SECRET, json.dumps(result))
            self.assertRegex(result["findings"][0]["fingerprint"], r"^[0-9a-f]{16}$")
        # Identity is stable and changes with location.
        self.assertEqual(leaks, gitleaks.parse(encode([GITLEAKS])))
        moved = gitleaks.parse(encode([GITLEAKS | {"StartLine": 13}]))
        self.assertNotEqual(moved["findings"][0]["fingerprint"], leaks["findings"][0]["fingerprint"])

    def test_malformed_or_hostile_reports_are_rejected_whole_with_fixed_text(self):
        deep = b"[" * 200000
        cases = {
            gitleaks.parse: [
                b"not json",
                b"{}",
                b"[1]",
                deep,
                "text".encode("utf-16"),
                encode([GITLEAKS, "x"]),
                encode([GITLEAKS | {"RuleID": [SECRET]}]),
                encode([GITLEAKS | {"RuleID": ""}]),
                encode([GITLEAKS | {"File": f"../../{SECRET}"}]),
                encode([GITLEAKS | {"File": 7}]),
                encode([GITLEAKS | {"StartLine": True}]),
                encode([GITLEAKS | {"StartLine": "12"}]),
                encode([GITLEAKS | {"StartLine": 0}]),
                encode([{k: v for k, v in GITLEAKS.items() if k != "File"}]),
            ],
            semgrep.parse: [
                b"not json",
                b"[]",
                deep,
                encode({"results": "x"}),
                encode({"results": [1]}),
                encode({"results": [SEMGREP | {"check_id": {"x": SECRET}}]}),
                encode({"results": [SEMGREP | {"path": f"/etc/../../{SECRET}"}]}),
                encode({"results": [SEMGREP | {"start": {"line": "7"}}]}),
                encode({"results": [SEMGREP | {"start": None}]}),
                encode({"results": [SEMGREP | {"extra": {"metadata": {"cwe": [{"x": SECRET}]}}}]}),
            ],
            nuclei.parse: [
                b"not json\n",
                b"[]\n",
                deep,
                lines(NUCLEI) + b"garbage\n",
                lines(NUCLEI | {"template-id": 5}),
                lines(NUCLEI | {"matched-at": f"not a url {SECRET}"}),
                lines(NUCLEI | {"matched-at": "http://"}),
                lines(NUCLEI | {"matched-at": None}),
                lines(NUCLEI | {"matcher-name": [SECRET]}),
                lines(NUCLEI | {"info": {"name": {"x": SECRET}}}),
            ],
        }
        for parse, reports in cases.items():
            for index, report in enumerate(reports):
                with self.subTest(parser=parse.__module__.rsplit(".", 1)[1], case=index):
                    with self.assertRaises(ValueError) as caught:
                        parse(report)
                    self.assertNotIn(SECRET, str(caught.exception))
            for wrong in ("a string", None, bytearray(b"[]")):
                with self.assertRaises(ValueError):
                    parse(wrong)
            with self.assertRaises(ValueError):
                parse(b" " * (MAX_REPORT_BYTES + 1))

    def test_locations_are_validated_as_written_and_never_repaired_into_another_identity(self):
        for path in (
            "/etc/passwd",
            "C:\\Windows\\system.ini",
            "\\\\server\\share\\x",
            "a//b",
            "a/../b",
            "bad\x07name.py",
            "x" * 501,
            "ok/" * 170 + "../escape",
        ):
            with self.subTest(path=path[:30]):
                with self.assertRaises(ValueError):
                    gitleaks.parse(encode([GITLEAKS | {"File": path}]))
                with self.assertRaises(ValueError):
                    semgrep.parse(encode({"results": [SEMGREP | {"path": path}]}))
        # An absolute path is accepted only beneath a root the caller vouches for.
        inside = gitleaks.parse(
            encode([GITLEAKS | {"File": "/work/repo/src/a.py"}]), source_root="/work/repo"
        )
        self.assertEqual(inside["findings"][0]["file"], "src/a.py")
        with self.assertRaises(ValueError):
            gitleaks.parse(encode([GITLEAKS | {"File": "/work/other/a.py"}]), source_root="/work/repo")
        windows = gitleaks.parse(encode([GITLEAKS | {"File": "C:\\app\\src\\a.py"}]), source_root="C:\\app")
        self.assertEqual(windows["findings"][0]["file"], "src/a.py")
        with self.assertRaises(ValueError):
            gitleaks.parse(encode([GITLEAKS | {"RuleID": "r" * 151}]))
        # Two long paths that differ only at the end keep distinct identities.
        first, second = (
            gitleaks.parse(encode([GITLEAKS | {"File": "d/" * 200 + name}]))["findings"][0]
            for name in ("one.py", "two.py")
        )
        self.assertNotEqual((first["file"], first["fingerprint"]), (second["file"], second["fingerprint"]))

    def test_nuclei_locations_keep_their_identity_or_are_rejected(self):
        def where(value):
            return nuclei.parse(lines(NUCLEI | {"matched-at": value}))["findings"][0]["matched_at"]

        self.assertEqual(where("http://[::1]:8080/path"), "http://[::1]:8080/path")
        self.assertEqual(where("https://h.example.invalid/caf\u00e9"), "https://h.example.invalid/caf\u00e9")
        self.assertEqual(where("h.example.invalid"), "h.example.invalid")
        self.assertEqual(where("h.example.invalid:8443"), "h.example.invalid:8443")
        # IPv6 in the bare host form used by network and DNS templates.
        self.assertEqual(where("[::1]:22"), "[::1]:22")
        self.assertEqual(where("[2001:db8::1]:53"), "[2001:db8::1]:53")
        self.assertEqual(where("::1"), "::1")
        self.assertEqual(where("[::1]"), "::1")
        for bad in (
            "http://h.example.invalid:0/",
            "http://h.example.invalid:99999/",
            "h.example.invalid:99999",
            "h.example.invalid:0",
            "h.example.invalid:8a",
            "[::1]:0",
            "[::1]:99999",
            "[not-an-address]:22",
            "ftp://h.example.invalid/",
            "http://bad\x07host/",
            "http://h.example.invalid/" + "p" * 1000,
        ):
            with self.subTest(bad=bad[:30]), self.assertRaises(ValueError):
                where(bad)
        # Two different long paths are two findings, never merged by shortening.
        first, second = (
            nuclei.parse(lines(NUCLEI | {"matched-at": "http://h.example.invalid/" + "a/" * 300 + end}))[
                "findings"
            ][0]
            for end in ("one", "two")
        )
        self.assertNotEqual(
            (first["matched_at"], first["fingerprint"]), (second["matched_at"], second["fingerprint"])
        )

    def test_rejections_keep_no_report_text_in_the_traceback(self):
        import traceback

        for parse, report in (
            (gitleaks.parse, f'[{{"RuleID": "{SECRET}", broken'.encode()),
            (semgrep.parse, f'{{"results": "{SECRET}", broken'.encode()),
            (nuclei.parse, lines(NUCLEI | {"matched-at": f"http://h.example.invalid:{SECRET}/"})),
        ):
            with self.subTest(parse.__module__):
                try:
                    parse(report)
                except ValueError as error:
                    shown = "".join(traceback.format_exception(error))
                    self.assertIsNone(error.__cause__)
                else:
                    self.fail("the report was accepted")
                self.assertNotIn(SECRET, shown)

    def test_numbers_that_are_not_json_reject_the_report(self):
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(constant):
                with self.assertRaises(ValueError) as caught:
                    gitleaks.parse(
                        b'[{"RuleID": "r", "File": "f", "StartLine": 1, "Entropy": ' + constant + b"}]"
                    )
                self.assertEqual(str(caught.exception), "Gitleaks report is not valid JSON.")
                with self.assertRaises(ValueError):
                    semgrep.parse(b'{"results": [], "time": ' + constant + b"}")
                with self.assertRaises(ValueError):
                    nuclei.parse(
                        b'{"template-id": "t", "matched-at": "h.example.invalid", "x": ' + constant + b"}\n"
                    )

    def test_credentials_in_retained_fields_are_redacted_without_losing_identity(self):
        planted = f"token={SECRET}"
        leaks = gitleaks.parse(
            encode([GITLEAKS | {"RuleID": f"rule-{planted}", "File": f"conf/{planted}/a.py"}])
        )
        code = semgrep.parse(
            encode(
                {
                    "results": [
                        SEMGREP
                        | {
                            "check_id": f"rule.{planted}",
                            "path": f"src/{planted}.py",
                            "extra": {"metadata": {"cwe": [f"CWE {planted}"]}},
                        }
                    ]
                }
            )
        )
        web = nuclei.parse(
            lines(
                NUCLEI | {"template-id": f"t-{planted}", "matcher-name": planted, "info": {"name": planted}}
            )
        )
        for result in (leaks, code, web):
            self.assertNotIn(SECRET, json.dumps(result))
        # Identity comes from the original value, so two different secrets stay two findings.
        other = gitleaks.parse(
            encode([GITLEAKS | {"RuleID": f"rule-{planted}", "File": "conf/token=another-value/a.py"}])
        )
        self.assertNotEqual(other["findings"][0]["fingerprint"], leaks["findings"][0]["fingerprint"])
        plain = gitleaks.parse(encode([GITLEAKS]))["findings"][0]
        self.assertEqual((plain["rule"], plain["file"]), ("aws-access-token", "config/settings.py"))

    def test_a_credential_crossing_the_display_cap_leaves_no_fragment_behind(self):
        import string

        token = "ghp_" + (string.ascii_letters + string.digits)[5:41]
        for name in ("n" * 170 + " " + token, "n" * 150 + " " + token[:20] + "\x07" + token[20:]):
            with self.subTest(length=len(name)):
                stored = nuclei.parse(lines(NUCLEI | {"info": {"name": name}}))["findings"][0]["name"]
                self.assertLessEqual(len(stored), 200)
                self.assertNotIn(token, stored)
                # Not even a recognisable beginning of it.
                self.assertNotIn(token[:12], stored)

    def test_a_malformed_entry_beyond_the_retention_cap_still_rejects_the_report(self):
        valid_leak = {"RuleID": "r", "File": "f", "StartLine": 1}
        valid_code = {"check_id": "r", "path": "f", "start": {"line": 1}}
        valid_web = {"template-id": "t", "matched-at": "h.example.invalid:80"}
        for label, call in (
            ("gitleaks", lambda: gitleaks.parse(encode([valid_leak] * MAX_FINDINGS + [{"RuleID": 5}]))),
            (
                "semgrep",
                lambda: semgrep.parse(encode({"results": [valid_code] * MAX_FINDINGS + [{"path": 5}]})),
            ),
            ("nuclei", lambda: nuclei.parse(lines(*[valid_web] * MAX_FINDINGS) + b"garbage\n")),
        ):
            with self.subTest(label), self.assertRaises(ValueError):
                call()

    def test_a_failed_or_partial_semgrep_scan_never_looks_like_a_clean_one(self):
        clean = semgrep.parse(encode({"results": [], "errors": [], "paths": {"scanned": ["a.py", "b.py"]}}))
        failed = semgrep.parse(
            encode(
                {
                    "results": [],
                    "errors": [{"level": "error", "message": SECRET}],
                    "paths": {"scanned": ["a.py"], "skipped": [{"path": "b.py"}]},
                }
            )
        )
        self.assertEqual(
            (clean["complete"], clean["errors"], clean["paths_scanned"], clean["paths_skipped"]),
            (True, 0, 2, 0),
        )
        self.assertEqual(
            (failed["complete"], failed["errors"], failed["paths_scanned"], failed["paths_skipped"]),
            (False, 1, 1, 1),
        )
        self.assertNotIn(SECRET, json.dumps(failed))
        for malformed in (
            {"results": [], "errors": "x"},
            {"results": [], "paths": []},
            {"results": [], "paths": {"scanned": 5}},
        ):
            with self.assertRaises(ValueError):
                semgrep.parse(encode(malformed))

    def test_unknown_severity_is_reported_as_unknown_and_large_reports_say_truncated(self):
        code = semgrep.parse(
            encode({"results": [SEMGREP | {"extra": {"severity": "BANANA"}}, SEMGREP | {"extra": 5}]})
        )
        self.assertEqual([f["severity"] for f in code["findings"]], ["unknown", "unknown"])
        self.assertEqual(nuclei.parse(lines(NUCLEI | {"info": {}}))["findings"][0]["severity"], "unknown")
        self.assertEqual(
            nuclei.parse(lines(NUCLEI | {"info": {}}))["findings"][0]["name"], "exposed-debug-page"
        )
        many = [{"RuleID": "r", "File": "f", "StartLine": n + 1} for n in range(MAX_FINDINGS + 1)]
        result = gitleaks.parse(encode(many))
        self.assertEqual((len(result["findings"]), result["truncated"]), (MAX_FINDINGS, True))
        self.assertEqual(nuclei.parse(b"\n\n"), {"findings": [], "truncated": False})


if __name__ == "__main__":
    unittest.main()
