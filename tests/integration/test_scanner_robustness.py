"""Robustness/consistency regressions: HSQLDB/Spring SQLi signatures and the deadline-bounded audit.

Covers the two behaviours added so a self-signed/JDBC/large target is handled consistently:
  - error-based SQLi is detected on Spring/HSQLDB stacks (OWASP Benchmark's database), not only MySQL/PG;
  - the active-fuzzing loop stops cleanly at its time budget and reports the skipped endpoints.
"""

import unittest
from unittest.mock import patch

from packages.scanner_adapters.integrations import vuln_scanner
from packages.security_policies import Destination

HSQLDB_ERROR = (
    "org.springframework.jdbc.BadSqlGrammarException: StatementCallback; bad SQL grammar "
    "[SELECT * FROM users WHERE name=''']; nested exception is java.sql.SQLSyntaxErrorException: "
    "malformed string: '''"
)


class ScannerRobustnessTests(unittest.TestCase):
    def setUp(self):
        self.dest = Destination(
            url="http://127.0.0.1:9/", scheme="http", host="127.0.0.1", port=9,
            origin="http://127.0.0.1:9", ip="127.0.0.1", path="/",
        )

    def test_error_based_sqli_detected_on_hsqldb_spring_stack(self):
        """A Spring/HSQLDB SQL error (not MySQL/PG) must still be flagged as CWE-89."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = (path or "") + (body or "")
            if "%27" in blob or "'" in blob:  # a quote reached the query -> emit the DB error
                return (200, {}, HSQLDB_ERROR, 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/search"], discovered_parameters=["q"]
            )
        sqli = [f for f in res["findings"] if f.get("cwe_id") == "CWE-89"]
        self.assertTrue(sqli, "HSQLDB/Spring error-based SQLi should be detected")

    def test_benign_jdbc_wording_is_not_a_false_positive(self):
        """Ordinary error pages that merely mention 'exception' must not be flagged as SQLi."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            return (200, {}, "<html>An unexpected error occurred. Please contact support.</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/search"], discovered_parameters=["q"]
            )
        self.assertFalse([f for f in res["findings"] if f.get("cwe_id") == "CWE-89"])

    def test_active_fuzzing_stops_at_time_budget_and_reports_skipped(self):
        """With a tiny budget the loop fuzzes at least one endpoint then stops and records what it skipped."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            return (200, {}, "<html>ok</html>", 1.0)

        endpoints = [f"/e{i}" for i in range(40)]
        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=endpoints,
                discovered_parameters=["id"], max_seconds=0.0001,
            )
        limits = [o for o in res["observations"] if o.get("kind") == "coverage_limit"]
        self.assertTrue(limits, "A truncated audit must report a coverage_limit observation")
        self.assertIn("not fuzzed", limits[0]["detail"])

    def test_no_budget_keeps_conservative_window_and_no_coverage_limit(self):
        """Without a budget the audit uses the small fixed window and never reports a time truncation."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=[f"/e{i}" for i in range(5)],
                discovered_parameters=["id"],
            )
        self.assertFalse([o for o in res["observations"] if o.get("kind") == "coverage_limit"])


    def test_cookie_vectored_sqli_detected(self):
        """A quote delivered via a cookie that triggers a DB error is flagged, with the cookie vector noted."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            if "'" in (headers or {}).get("Cookie", ""):
                return (200, {}, HSQLDB_ERROR, 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/account"],
                discovered_parameters=["JSESSIONID"],
            )
        cookie_sqli = [
            f for f in res["findings"]
            if f.get("cwe_id") == "CWE-89" and str(f.get("poc", {}).get("parameter", "")).startswith("cookie:")
        ]
        self.assertTrue(cookie_sqli, "Cookie-delivered SQLi should be detected and attributed to the cookie")

    def test_header_vectored_xss_detected(self):
        """A canary reflected from the Referer header is flagged as XSS via that header."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            ref = (headers or {}).get("Referer", "")
            if "sharay_canary" in ref:
                return (200, {}, f"<html><div>{ref}</div></html>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/page"], discovered_parameters=[],
            )
        header_xss = [
            f for f in res["findings"]
            if f.get("cwe_id") == "CWE-79" and f.get("poc", {}).get("parameter") == "header:Referer"
        ]
        self.assertTrue(header_xss, "Referer-reflected XSS should be detected and attributed to the header")

    def test_benign_cookie_and_header_values_are_not_flagged(self):
        """Cookies/headers that are echoed safely or ignored produce no injection findings."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            return (200, {}, "<html>welcome back</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/page"], discovered_parameters=["sid"],
            )
        self.assertFalse(
            [f for f in res["findings"] if str(f.get("poc", {}).get("parameter", "")).startswith(("cookie:", "header:"))]
        )


    def test_per_form_sqli_uses_the_forms_own_unique_field(self):
        """A form whose injectable field is named per-page is fuzzed with its OWN field, not a global list."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = (path or "") + (body or "")
            if "BenchmarkTest00026" in blob and ("'" in blob or "%27" in blob):
                return (200, {}, HSQLDB_ERROR, 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        form = {
            "action": "http://127.0.0.1:9/sqli-00/BenchmarkTest00026", "method": "GET",
            "inputs": [{"name": "BenchmarkTest00026", "type": "text", "value": "bar"}],
        }
        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=[], discovered_parameters=[],
                discovered_forms=[form],
            )
        hit = [
            f for f in res["findings"]
            if f.get("cwe_id") == "CWE-89" and f.get("poc", {}).get("parameter") == "BenchmarkTest00026"
        ]
        self.assertTrue(hit, "Per-form SQLi should fuzz the form's own unique field and detect the error")

    def test_per_form_xss_reflected_in_forms_own_field(self):
        """A reflected canary submitted through a form's own field is flagged against that field."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            from urllib.parse import unquote_plus
            blob = (path or "") + (body or "")
            if "sharay_canary" in blob:  # a vulnerable server url-decodes and reflects the value
                return (200, {}, f"<html><div>{unquote_plus(blob)}</div></html>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        form = {
            "action": "http://127.0.0.1:9/xss/BenchmarkTest00100", "method": "POST",
            "inputs": [{"name": "answer", "value": "x"}, {"name": "BenchmarkTest00100", "value": "q"}],
        }
        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=[], discovered_parameters=[],
                discovered_forms=[form],
            )
        hit = [f for f in res["findings"] if f.get("cwe_id") == "CWE-79" and f.get("poc", {}).get("parameter") in ("answer", "BenchmarkTest00100")]
        self.assertTrue(hit, "Per-form reflected XSS should be detected on the form's own field")

    def test_per_form_pass_skips_destructive_actions(self):
        """Forms posting to reset/logout/install actions must not be fuzzed (non-destructive guarantee)."""
        calls = {"n": 0}

        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            if "reset" in (path or ""):
                calls["n"] += 1
            return (200, {}, "<html>ok</html>", 1.0)

        form = {"action": "http://127.0.0.1:9/setup/reset.php", "method": "POST",
                "inputs": [{"name": "confirm", "value": "1"}]}
        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=[], discovered_parameters=[],
                discovered_forms=[form],
            )
        self.assertEqual(calls["n"], 0, "Destructive form actions must never be fuzzed")


    def test_ssti_detected_via_math_eval(self):
        """Phase 1: a template engine that evaluates an injected math expression (product appears, not the
        literal 'a*b') is flagged CWE-1336 (SSTI)."""
        import re as _re
        from urllib.parse import unquote_plus

        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = unquote_plus((path or "") + (body or "") + "".join((headers or {}).values()))
            m = _re.search(r"(\d{4})\*(\d{4})", blob)
            if m:  # vulnerable template engine evaluates it
                return (200, {}, f"<html>Hello {int(m.group(1)) * int(m.group(2))}</html>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/tpl"], discovered_parameters=["name"],
            )
        self.assertTrue([f for f in res["findings"] if f.get("cwe_id") == "CWE-1336"], "SSTI should be detected")

    def test_ssti_reflection_is_not_false_positive(self):
        """A page that echoes the raw template expression (no evaluation) must NOT be flagged as SSTI."""
        from urllib.parse import unquote_plus

        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = unquote_plus((path or "") + (body or "") + "".join((headers or {}).values()))
            return (200, {}, f"<html>You searched for: {blob[:200]}</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/tpl"], discovered_parameters=["name"],
            )
        self.assertFalse([f for f in res["findings"] if f.get("cwe_id") == "CWE-1336"])

    def test_ldap_injection_detected_via_error(self):
        """W4: a JNDI/LDAP exception triggered by a syntax-breaking filter metacharacter is flagged CWE-90."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = (path or "") + (body or "") + "".join((headers or {}).values())
            if "(" in blob or ")(" in blob or "*)" in blob:
                return (200, {}, "<html>javax.naming.directory.InvalidSearchFilterException: bad filter</html>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/dir"], discovered_parameters=["user"],
            )
        self.assertTrue([f for f in res["findings"] if f.get("cwe_id") == "CWE-90"], "LDAP injection should be flagged")

    def test_xpath_injection_detected_via_error(self):
        """W4: an XPath parse error triggered by a broken expression is flagged CWE-643."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = (path or "") + (body or "") + "".join((headers or {}).values())
            if "']" in blob or "%27%5D" in blob or "'" in blob:
                return (200, {}, "<html>Error parsing XPath input: '']'</html>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/lookup"], discovered_parameters=["q"],
            )
        self.assertTrue([f for f in res["findings"] if f.get("cwe_id") == "CWE-643"], "XPath injection should be flagged")

    def test_benign_page_not_flagged_as_ldap_or_xpath(self):
        """A page that merely contains the word 'LDAP' in text must NOT be flagged (specific-string match)."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            return (200, {}, "<html><h1>LDAP Injection demo</h1><p>Search XPath users</p></html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/dir"], discovered_parameters=["user"],
            )
        self.assertFalse([f for f in res["findings"] if f.get("cwe_id") in ("CWE-90", "CWE-643")])

    def test_xxe_detected_via_inband_file_read(self):
        """Phase 1: an XML external-entity payload that returns /etc/passwd content is flagged CWE-611."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            if method == "POST" and "<!ENTITY xxe SYSTEM" in (body or ""):
                return (200, {}, "<r>root:*:0:0:System Administrator:/var/root:/bin/sh</r>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/xmlapi"], discovered_parameters=["data"],
            )
        self.assertTrue([f for f in res["findings"] if f.get("cwe_id") == "CWE-611"], "XXE should be flagged")

    def test_nosql_injection_detected_via_error(self):
        """Phase 1: a MongoDB/driver error triggered by an injection metacharacter is flagged CWE-943."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = (path or "") + (body or "") + "".join((headers or {}).values())
            if "'" in blob or "%27" in blob or "$gt" in blob or "%24gt" in blob:
                return (200, {}, "<html>MongoServerError: unexpected token at position 3</html>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/api"], discovered_parameters=["filter"],
            )
        self.assertTrue([f for f in res["findings"] if f.get("cwe_id") == "CWE-943"], "NoSQL injection should be flagged")

    def test_pathtraver_inband_file_read_on_any_param(self):
        """W2: a traversal that returns /etc/passwd content is flagged CWE-22, on an ARBITRARY param
        name (the old file/path/page name-gate is lifted)."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = (path or "") + (body or "") + "".join((headers or {}).values())
            if "etc/passwd" in blob and "_sharay_nx" not in blob:
                return (200, {}, "<pre>root:*:0:0:System Administrator:/var/root:/bin/sh</pre>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/render"], discovered_parameters=["widget"],
            )
        self.assertTrue([f for f in res["findings"] if f.get("cwe_id") == "CWE-22"], "LFI should be flagged on any param")

    def test_pathtraver_blind_existence_differential_detected(self):
        """W2: a blind sink that never echoes file content but branches on File.exists() is caught by the
        existence differential — existing target vs the same path + nonexistent suffix differ."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = (path or "") + (body or "") + "".join((headers or {}).values())
            if "etc/passwd" in blob:
                if "_sharay_nx" in blob:
                    return (200, {}, "<html>result: file doesn't exist yet.</html>", 1.0)
                return (200, {}, "<html>result: file already exists.</html>", 1.0)  # no root sig -> echo misses
            return (200, {}, "<html>idle</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/open"], discovered_parameters=["name"],
            )
        self.assertTrue([f for f in res["findings"] if f.get("cwe_id") == "CWE-22"], "blind LFI should be flagged")

    def test_pathtraver_stable_benign_page_not_flagged(self):
        """W2 no-FP: a sink that ignores the input (same response for every payload) must NOT be flagged —
        after stripping the nonexistent suffix the two differential probes are identical."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            return (200, {}, "<html>static content, input ignored</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/safe"], discovered_parameters=["name"],
            )
        self.assertFalse([f for f in res["findings"] if f.get("cwe_id") == "CWE-22"], "safe sink must not be flagged")

    def test_pathtraver_dynamic_page_not_flagged_by_differential(self):
        """W2 no-FP (real-site robustness): a page whose body changes every request (nonce/timestamp) must
        NOT false-positive — the stability gate (two identical probes) aborts the differential."""
        import itertools
        counter = itertools.count()
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            return (200, {}, f"<html>nonce={next(counter)} time={next(counter)}</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/dyn"], discovered_parameters=["name"],
            )
        self.assertFalse([f for f in res["findings"] if f.get("cwe_id") == "CWE-22"], "dynamic page must not FP")

    def test_parameter_mining_discovers_hidden_param_and_fuzzes_it(self):
        """P1.3: a hidden param ('debug', not in the default set and not in discovered_parameters) that the
        endpoint reacts to is mined, folded into the fuzz set, and then found vulnerable (reflected XSS)."""
        from urllib.parse import urlsplit, parse_qs
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            val = (parse_qs(urlsplit(path or "").query).get("debug") or [""])[0]
            if val:  # endpoint echoes whatever 'debug' carries -> both mining canary and XSS payload reflect
                return (200, {}, f"<html>debug={val}</html>", 1.0)
            return (200, {}, "<html>home</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/app"], discovered_parameters=["foo"],
            )
        xss = [f for f in res["findings"] if f.get("cwe_id") == "CWE-79" and "debug" in str(f.get("poc", {}).get("parameter", ""))]
        self.assertTrue(xss, "mined hidden param 'debug' should be fuzzed and flagged")

    def test_parameter_mining_inert_endpoint_mines_nothing(self):
        """P1.3 no-noise: an endpoint whose response never changes with input mines no params (and so the
        reflected-XSS probe on a hidden param produces nothing)."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            return (200, {}, "<html>static home page, input ignored</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/app"], discovered_parameters=["foo"],
            )
        self.assertFalse([f for f in res["findings"] if f.get("cwe_id") == "CWE-79"], "inert endpoint must not yield XSS")

    def test_per_endpoint_param_association_fuzzes_endpoint_own_param(self):
        """P1.1: a param observed only at one endpoint (not in the global discovered_parameters) is still
        fuzzed on THAT endpoint, and is not required to survive the global cap."""
        from urllib.parse import urlsplit, parse_qs
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            val = (parse_qs(urlsplit(path or "").query).get("report_id") or [""])[0]
            if val:
                return (200, {}, f"<html>report {val}</html>", 1.0)  # reflects the XSS payload
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1",
                discovered_endpoints=["/reports/view"], discovered_parameters=["unrelated"],
                endpoint_parameters={"/reports/view": ["report_id"]},
            )
        hits = [f for f in res["findings"] if f.get("cwe_id") == "CWE-79" and "report_id" in str(f.get("poc", {}).get("parameter", ""))]
        self.assertTrue(hits, "an endpoint's own param should be fuzzed on it")

    def test_json_body_sqli_detected_on_api_endpoint(self):
        """P1.2: an API endpoint that reads inputs from a JSON body (not query/form) is fuzzed — a SQL
        error triggered by a single quote in a JSON field is flagged CWE-89 with a json: vector."""
        import json as _json
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            if method == "POST" and (headers or {}).get("Content-Type") == "application/json":
                try:
                    vals = "".join(str(v) for v in _json.loads(body or "{}").values())
                except Exception:
                    vals = ""
                if "'" in vals:
                    return (200, {}, "<html>java.sql.SQLSyntaxErrorException: bad SQL near ''</html>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/api/v1/orders"], discovered_parameters=["q"],
            )
        hits = [f for f in res["findings"] if f.get("cwe_id") == "CWE-89" and "json:" in str(f.get("poc", {}).get("parameter", ""))]
        self.assertTrue(hits, "JSON-body SQLi should be flagged on an API endpoint")

    def test_json_body_pass_skipped_on_non_api_endpoint(self):
        """P1.2 scope: the JSON-body pass is gated to API-looking endpoints, so a plain HTML page that would
        error on a quoted JSON value is NOT probed that way (no spurious json: SQLi)."""
        import json as _json
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            if method == "POST" and (headers or {}).get("Content-Type") == "application/json":
                return (200, {}, "<html>java.sql.SQLSyntaxErrorException</html>", 1.0)  # would fire IF probed
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/about"], discovered_parameters=["q"],
            )
        self.assertFalse([f for f in res["findings"] if "json:" in str(f.get("poc", {}).get("parameter", ""))])

    def test_output_based_cmdi_detected_on_any_param_after_gate_lift(self):
        """W1: output-based cmdi — the echo marker appears as command OUTPUT (not a reflected
        'echo <marker>') — is detected on an arbitrary param name now that the name-gate is lifted."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = (path or "") + (body or "")
            if "sharay_canary_cmd" in blob and "echo" in blob:  # shell ran echo -> only output returns
                return (200, {}, "<html>PING 127.0.0.1:\nsharay_canary_cmd\n</html>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/run"], discovered_parameters=["widget"],
            )
        self.assertTrue(
            [f for f in res["findings"] if f.get("cwe_id") == "CWE-78"],
            "output-based cmdi must fire on a non-gated param name",
        )

    def test_reflected_echo_payload_is_not_a_cmdi_false_positive(self):
        """Pure reflection of the payload (response still contains 'echo <marker>') must NOT be flagged."""
        def fake(destination, allow_ip, method, path, headers=None, body=None, timeout=3.5, auth=None):
            blob = (path or "") + (body or "")
            if "sharay_canary_cmd" in blob:  # echoes the raw payload back -> still has 'echo <marker>'
                return (200, {}, "<html>results for: 127.0.0.1; echo sharay_canary_cmd</html>", 1.0)
            return (200, {}, "<html>ok</html>", 1.0)

        with patch.object(vuln_scanner, "_request_endpoint", side_effect=fake):
            res = vuln_scanner.audit_deep_vulnerabilities(
                self.dest, "127.0.0.1", discovered_endpoints=["/run"], discovered_parameters=["widget"],
            )
        self.assertFalse([f for f in res["findings"] if f.get("cwe_id") == "CWE-78"])


if __name__ == "__main__":
    unittest.main()
