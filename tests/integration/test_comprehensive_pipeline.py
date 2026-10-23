"""Comprehensive multi-stage assessment pipeline tests."""

import unittest
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from packages.scanner_adapters import scan_comprehensive
from packages.security_policies import Destination, ScopePolicy


def _scope(host, origin):
    return ScopePolicy.model_validate(
        {
            "hosts": [host],
            "allowed_origins": [origin],
            "allowed_paths": ["/"],
            "allowed_cidrs": [],
            "categories": ["http_headers", "templates"],
            "starts_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        }
    )


class ComprehensivePipelineTests(unittest.TestCase):
    _dest = Destination(
        "https://example.com/", "https", "example.com", 443, "/", "https://example.com", "example.com"
    )

    def setUp(self):
        # These cases verify aggregation; individual stage tests exercise their transports.
        fixtures = {
            "dns_scanner.scan_dns_records": {},
            "subdomain_scanner.scan_subdomains": {},
            "port_scanner.scan_network_ports": {
                "observations": [{"kind": "network_service", "category": "network_inventory", "port": 443}],
                "check": {"category": "network_inventory", "status": "completed"},
            },
            "crawler.crawl": {"endpoints": ["/"], "pages_visited": 1},
            "crawler._fetch_page": (404, {}, ""),
            "browser.HeadlessBrowserDriver.render_dom": {"dom": "<html></html>"},
            "differential.run_differential_tests": {},
            "vuln_scanner.audit_deep_vulnerabilities": {},
            "authorization.AuthorizationMatrixProber.sweep": {"findings": []},
        }
        for name, result in fixtures.items():
            mock = patch("packages.scanner_adapters.integrations." + name, return_value=result)
            mock.start()
            self.addCleanup(mock.stop)
        peer = MagicMock()
        peer.getpeercert.return_value = b"synthetic-certificate"
        peer.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        peer.version.return_value = "TLSv1.3"
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = peer
        for mock in (
            patch("packages.scanner_adapters.ssl.create_default_context", return_value=context),
            patch("packages.scanner_adapters.socket.create_connection", return_value=MagicMock()),
        ):
            mock.start()
            self.addCleanup(mock.stop)
        for mock in (
            patch(
                "socket.socket.connect",
                side_effect=AssertionError("Aggregation fixtures must not contact targets"),
            ),
            patch(
                "socket.getaddrinfo",
                side_effect=AssertionError("Aggregation fixtures must not resolve targets"),
            ),
        ):
            guard = mock.start()
            self.addCleanup(mock.stop)
            self.addCleanup(guard.assert_not_called)

    def test_pipeline_aggregates_recon_headers_ports_and_nuclei(self):
        curl_raw = b"HTTP/2 200 \r\ncontent-type: text/html\r\nserver: nginx\r\n\r\n"
        nuclei_raw = (
            b"[INF] Templates loaded: 14036\n"
            b'{"template-id":"CVE-2024-9999","info":{"name":"Critical RCE","severity":"critical"},"matched-at":"https://example.com/api"}\n'
        )

        calls = []

        def mock_runner(image, argv, **kwargs):
            calls.append((image, argv, kwargs))
            if "curl" in image:
                return SimpleNamespace(
                    outcome="completed", exit_code=0, stdout=curl_raw, output_truncated=False
                )
            return SimpleNamespace(
                outcome="completed", exit_code=0, stdout=nuclei_raw, output_truncated=False
            )

        res = scan_comprehensive(self._dest, "93.184.216.34", run=mock_runner)

        # completed_with_errors is honest when an auxiliary stage (e.g. reproducer_canary) cannot run.
        self.assertIn(res["outcome"], ("completed", "completed_with_errors"))
        self.assertGreaterEqual(len(res["checks"]), 4)  # tls, recon, port, headers, nuclei, pipeline
        self.assertTrue(any(c["category"] == "network_inventory" for c in res["checks"]))
        self.assertTrue(any(c["category"] == "pipeline" for c in res["checks"]))

        # Verify findings include both headers and nuclei
        findings = res["findings"]
        self.assertTrue(any("nuclei:" in f["fingerprint"] for f in findings))
        self.assertTrue(any(f["title"] == "Critical RCE" for f in findings))
        self.assertTrue(any("Strict-Transport-Security" in f["title"] for f in findings))

        # Verify observations include network service and recon assets
        observations = res["observations"]
        self.assertTrue(any(obs.get("category") == "network_inventory" for obs in observations))
        self.assertTrue(any(obs.get("category") == "recon" for obs in observations))

    def test_pipeline_executes_all_configured_tools_including_nmap_zap_metasploit(self):
        curl_raw = b"HTTP/2 200 \r\ncontent-type: text/html\r\nserver: nginx\r\n\r\n"
        nuclei_raw = (
            b"[INF] Templates loaded: 14036\n"
            b'{"template-id":"CVE-2024-9999","info":{"name":"Critical RCE","severity":"critical"},"matched-at":"https://example.com/api"}\n'
        )
        nmap_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b"<!DOCTYPE nmaprun>\n"
            b'<nmaprun scanner="nmap" args="synthetic sample" start="1760000000" version="7.95" xmloutputversion="1.05">\n'
            b'<host starttime="1760000000" endtime="1760000001"><status state="up" reason="user-set"/>\n'
            b'<address addr="93.184.216.34" addrtype="ipv4"/>\n'
            b"<ports>\n"
            b'<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>\n'
            b'<service name="https" method="probed" conf="10"/></port>\n'
            b"</ports></host>\n"
            b'<runstats><finished time="1760000001" exit="success"/></runstats>\n'
            b"</nmaprun>\n"
        )
        zap_json = (
            b'{"site": [{"alerts": [{"pluginid": "10020", "alertRef": "10020-1", "name": "X-Frame-Options Header Not Set", '
            b'"riskcode": "2", "confidence": "2", "cweid": "1021", "solution": "Ensure header is present.", '
            b'"instances": [{"uri": "https://example.com/", "method": "GET", "param": ""}]}]}]}'
        )
        msf_json = (
            b'{"results": [{"module": "auxiliary/scanner/http/title", "outcome": "confirmed_reproducible", '
            b'"target_url": "https://example.com/", "session_established": false, "summary": "Example Domain Title"}]}'
        )

        ran_images = []

        def mock_runner(image, argv, **kwargs):
            ran_images.append(image)
            if "curl" in image:
                return SimpleNamespace(
                    outcome="completed", exit_code=0, stdout=curl_raw, output_truncated=False
                )
            if "nmap" in image:
                return SimpleNamespace(
                    outcome="completed", exit_code=0, stdout=nmap_xml, output_truncated=False
                )
            if "zap" in image:
                return SimpleNamespace(
                    outcome="completed", exit_code=0, stdout=zap_json, output_truncated=False
                )
            if "metasploit" in image:
                return SimpleNamespace(
                    outcome="completed", exit_code=0, stdout=msf_json, output_truncated=False
                )
            return SimpleNamespace(
                outcome="completed", exit_code=0, stdout=nuclei_raw, output_truncated=False
            )

        res = scan_comprehensive(
            self._dest,
            "93.184.216.34",
            run=mock_runner,
            tools=["nmap", "crawler", "sensitive", "diff", "nuclei", "zap", "metasploit"],
        )

        # completed_with_errors is honest when an auxiliary stage (e.g. reproducer_canary) cannot run.
        self.assertIn(res["outcome"], ("completed", "completed_with_errors"))
        # Ensure all 4 images were executed
        self.assertTrue(any("nmap" in img for img in ran_images))
        self.assertTrue(any("zap" in img for img in ran_images))
        self.assertTrue(any("metasploit" in img for img in ran_images))
        self.assertTrue(any("nuclei" in img for img in ran_images))

        # Check findings from all integrated tools
        findings = res["findings"]
        self.assertTrue(any(f["fingerprint"].startswith("nuclei:") for f in findings))
        self.assertTrue(any(f["fingerprint"].startswith("zap:") for f in findings))
        self.assertTrue(any(f["fingerprint"].startswith("metasploit:") for f in findings))

        # Check checks
        categories = {c["category"] for c in res["checks"]}
        self.assertIn("network_inventory", categories)
        self.assertIn("zap", categories)
        self.assertIn("metasploit", categories)
        self.assertIn("nuclei", categories)
        self.assertIn("pipeline", categories)

    def test_pipeline_handles_metasploit_and_zap_timeout_124(self):
        def timeout_runner(image, argv, **kwargs):
            if "metasploit" in image:
                return SimpleNamespace(
                    outcome="failed",
                    exit_code=124,
                    stdout=b"",
                    stderr=b"Command timed out before completion",
                    output_truncated=False,
                )
            if "zap" in image:
                return SimpleNamespace(
                    outcome="failed",
                    exit_code=124,
                    stdout=b"",
                    stderr=b"Command timed out before completion",
                    output_truncated=False,
                )
            return SimpleNamespace(
                outcome="completed",
                exit_code=0,
                stdout=b"[]",
                output_truncated=False,
            )

        res = scan_comprehensive(
            self._dest,
            "93.184.216.34",
            run=timeout_runner,
            tools=["metasploit", "zap"],
            max_seconds=60,
        )
        # A stage that only hit its budget is honest (amber), never a green "completed".
        self.assertEqual(res["outcome"], "completed_with_errors")
        checks = {c["category"]: c for c in res["checks"]}
        self.assertIn("metasploit", checks)
        self.assertEqual(checks["metasploit"]["status"], "completed_with_errors")
        self.assertIn("execution budget", checks["metasploit"]["detail"])
        self.assertIn("zap", checks)
        self.assertEqual(checks["zap"]["status"], "completed_with_errors")
        self.assertIn("execution budget", checks["zap"]["detail"])
        # The budget adapts upward so each enabled asset gets its floor (zap 150 + metasploit 120
        # + base 60 = 330), even though 60s was requested; capped at 1800s.
        budget = next(o for o in res["observations"] if o.get("kind") == "adaptive_budget")
        self.assertGreaterEqual(budget["allocated_seconds"], 330)
        self.assertLessEqual(budget["allocated_seconds"], 1800)

    def test_optin_protocol_audits_run_only_when_selected(self):
        def benign_runner(image, argv, **kwargs):
            raw = b"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=raw, output_truncated=False)

        base = "packages.scanner_adapters.integrations."
        sentinels = {
            "graphql_scanner.audit_graphql_endpoint": {
                "findings": [{"fingerprint": "gql1", "title": "GraphQL introspection", "severity": "medium"}],
                "checks": [{"category": "graphql", "status": "completed", "detail": "audited"}],
            },
            "websocket_scanner.audit_websocket_endpoint": {
                "findings": [],
                "checks": [{"category": "websocket", "status": "completed", "detail": "audited"}],
            },
            "wordlist_scanner.scan_wordlist_directories": {
                "findings": [],
                "checks": [{"category": "wordlist", "status": "completed", "detail": "audited"}],
            },
        }
        mocks = {name: patch(base + name, return_value=result) for name, result in sentinels.items()}
        started = {name: m.start() for name, m in mocks.items()}
        for m in mocks.values():
            self.addCleanup(m.stop)

        # Not selected -> the audits never run and emit no checks.
        default_res = scan_comprehensive(self._dest, "93.184.216.34", run=benign_runner)
        for stub in started.values():
            stub.assert_not_called()
        self.assertFalse(
            any(c["category"] in {"graphql", "websocket", "wordlist"} for c in default_res["checks"])
        )

        # Selected -> each audit runs and its checks/findings are merged.
        res = scan_comprehensive(
            self._dest, "93.184.216.34", run=benign_runner, tools=["graphql", "websocket", "wordlist"]
        )
        for stub in started.values():
            stub.assert_called()
        categories = {c["category"] for c in res["checks"]}
        self.assertEqual(
            {"graphql", "websocket", "wordlist"} & categories, {"graphql", "websocket", "wordlist"}
        )
        self.assertTrue(any(f.get("fingerprint") == "gql1" for f in res["findings"]))

    def test_cve_intelligence_runs_only_when_selected(self):
        vulnerable_headers = b"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\nserver: Apache/2.4.49\r\n\r\n"

        def runner(image, argv, **kwargs):
            raw = vulnerable_headers if "curl" in image else b"[]"
            return SimpleNamespace(outcome="completed", exit_code=0, stdout=raw, output_truncated=False)

        default_res = scan_comprehensive(self._dest, "93.184.216.34", run=runner)
        self.assertFalse(any(c["category"] == "cve_intelligence" for c in default_res["checks"]))
        self.assertFalse(
            any(str(f.get("fingerprint", "")).startswith("cve:") for f in default_res["findings"])
        )

        res = scan_comprehensive(self._dest, "93.184.216.34", run=runner, tools=["cve"])
        self.assertTrue(any(c["category"] == "cve_intelligence" for c in res["checks"]))
        cve_titles = [f["title"] for f in res["findings"] if str(f.get("fingerprint", "")).startswith("cve:")]
        self.assertTrue(any("CVE-2021-41773" in t for t in cve_titles), cve_titles)
        for finding in res["findings"]:
            if str(finding.get("fingerprint", "")).startswith("cve:"):
                self.assertEqual(finding["status"], "suspected")
                self.assertEqual(finding["confidence"], "low")

    @staticmethod
    def _basic_runner(image, argv, **kwargs):
        stdout = b"HTTP/2 200 \r\ncontent-type: text/html\r\n\r\n" if "curl" in image else b""
        return SimpleNamespace(outcome="completed", exit_code=0, stdout=stdout, output_truncated=False)

    def test_port_stage_does_not_fabricate_open_service_when_none_found(self):
        # E06/F07: when the port scan ran and saw no open services, the stage must NOT invent an
        # "open" network_service -- a closed/filtered port is not reported open.
        with patch(
            "packages.scanner_adapters.integrations.port_scanner.scan_network_ports",
            return_value={"observations": [], "findings": []},
        ):
            res = scan_comprehensive(self._dest, "93.184.216.34", run=self._basic_runner)
        self.assertFalse(
            any(o.get("tool") == "sharay_port_verifier" for o in res["observations"]),
            "port stage must not fabricate an open service",
        )
        net_checks = [c for c in res["checks"] if c["category"] == "network_inventory"]
        self.assertTrue(
            any(c["status"] == "completed" and "no open" in c["detail"].lower() for c in net_checks)
        )

    def test_port_stage_reports_failed_on_exception_without_fabrication(self):
        # E06/F07: a stage that threw must be recorded failed, never "completed", and must not
        # fabricate an open service to paper over the error.
        with patch(
            "packages.scanner_adapters.integrations.port_scanner.scan_network_ports",
            side_effect=RuntimeError("boom"),
        ):
            res = scan_comprehensive(self._dest, "93.184.216.34", run=self._basic_runner)
        self.assertFalse(any(o.get("tool") == "sharay_port_verifier" for o in res["observations"]))
        net_checks = [c for c in res["checks"] if c["category"] == "network_inventory"]
        self.assertTrue(
            any(c["status"] == "failed" and "did not complete" in c["detail"] for c in net_checks)
        )
        self.assertFalse(any(c["status"] == "completed" for c in net_checks if "boom" in c.get("detail", "")))


if __name__ == "__main__":
    unittest.main()
