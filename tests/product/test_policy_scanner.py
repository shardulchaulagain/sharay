import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from fixtures.safe_targets.server import create_server
from packages.scanner_adapters import preflight, scan
from packages.security_policies import (
    PolicyError,
    ScopePolicy,
    check_url,
    normalize_url,
    validate_scope,
)
from packages.shared_schemas import adapter_roadmap


def scope_for(url):
    now = datetime.now(UTC)
    return {
        "hosts": ["127.0.0.1"],
        "allowed_origins": [url.rstrip("/")],
        "allowed_paths": ["/"],
        "excluded_paths": ["/excluded"],
        "allowed_cidrs": ["127.0.0.1/32"],
        "categories": ["http_headers", "tls", "dns"],
        "request_rate": 5,
        "starts_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.origin = "http://127.0.0.1:8766"
        self.scope = scope_for(self.origin)

    def test_url_normalization_and_ipv6(self):
        self.assertEqual(normalize_url("http://127.0.0.1:80"), "http://127.0.0.1/")
        self.assertEqual(normalize_url("https://[::1]:443/app"), "https://[::1]/app")
        self.assertEqual(
            normalize_url(self.origin + "/hello%20world"),
            self.origin + "/hello%20world",
        )

    def test_non_literal_private_public_metadata_and_ambiguous_authorities_denied(self):
        bad = [
            "http://localhost/",
            "http://example.com/",
            "http://10.0.0.1/",
            "http://169.254.169.254/",
            "http://2130706433/",
            "http://127.1/",
            "http://127.0.0.1./",
            "http://127.0.0.1:0/",
            "file:///etc/passwd",
            "http://user:password@127.0.0.1/",
            "http://127.0.0.1/?token=secret",
            "http://127.0.0.1/#fragment",
            "http://127.0.0.1:00080/",
            "http://127.0.0.1\\@example.com/",
        ]
        for url in bad:
            with self.subTest(url=url), self.assertRaises(PolicyError):
                normalize_url(url)

    def test_encoded_and_literal_traversal_denied(self):
        for path in [
            "/../secret",
            "/a/./b",
            "/%2e%2e/secret",
            "/a%2fb",
            "/%252e%252e/secret",
            "/a%5cb",
            "/a//b",
            "/bad%ZZ",
            "/%00",
        ]:
            with self.subTest(path=path), self.assertRaises(PolicyError):
                check_url(self.scope, self.origin + path)

    def test_scope_paths_have_segment_boundaries_and_exclusions_win(self):
        self.scope["allowed_paths"] = ["/app"]
        self.scope["excluded_paths"] = ["/app/private"]
        check_url(self.scope, self.origin + "/app")
        check_url(self.scope, self.origin + "/app/public")
        for path in ["/apple", "/app/private", "/app/private/x"]:
            with self.subTest(path=path), self.assertRaises(PolicyError):
                check_url(self.scope, self.origin + path)

    def test_semicolon_path_parameters_cannot_bypass_exclusions_or_traversal(self):
        for path in (
            "/excluded;jsessionid=1",
            "/excluded%3Bjsessionid=1",
            "/excluded%3bjsessionid=1",
            "/excluded;jsessionid=1/child",
            "/app/..;/excluded",
            "/app/..%3B/excluded",
            "/app/%2e%2e%3b/excluded",
            "/app/.;/public",
        ):
            scope = self.scope | {"allowed_paths": ["/app"]} if path.startswith("/app/") else self.scope
            with self.subTest(path=path), self.assertRaises(PolicyError):
                check_url(scope, self.origin + path)

    def test_scope_prefixes_reject_raw_and_encoded_semicolon_parameters(self):
        for field in ("allowed_paths", "excluded_paths"):
            for path in ("/app;version=1", "/app%3Bversion=1", "/app%3bversion=1"):
                with self.subTest(field=field, path=path), self.assertRaises(ValidationError):
                    ScopePolicy.model_validate(self.scope | {field: [path]})

    def test_permission_schema_rejects_intrusive_authenticated_credentials_and_unknown_fields(
        self,
    ):
        changes = [
            {"intrusive": True},
            {"authenticated": True},
            {"credential_refs": ["secret"]},
            {"request_rate": 6},
            {"max_concurrency": 2},
            {"approval_required": False},
            {"categories": ["exploit"]},
            {"unknown": True},
            {"allowed_cidrs": ["127.0.0.0/8"]},
            {"intrusive": 0},
            {"max_concurrency": True},
            {"emergency_stop_conditions": ["operator_cancel"]},
        ]
        for changeset in changes:
            with self.subTest(changes=changeset), self.assertRaises(ValidationError):
                ScopePolicy.model_validate(self.scope | changeset)

    def test_expiry_and_unstarted_scope_denied(self):
        now = datetime.now(UTC)
        expired = self.scope | {
            "starts_at": (now - timedelta(hours=1)).isoformat(),
            "expires_at": (now - timedelta(seconds=1)).isoformat(),
        }
        future = self.scope | {"starts_at": (now + timedelta(minutes=1)).isoformat()}
        for value in [expired, future]:
            with self.assertRaises(PolicyError):
                validate_scope(value, self.origin)
        with self.assertRaises(ValidationError):
            ScopePolicy.model_validate(self.scope | {"expires_at": "2026-10-11T20:00:00"})

    def test_origin_port_and_ip_require_explicit_authorization(self):
        with self.assertRaises(PolicyError):
            check_url(self.scope, "http://127.0.0.1:8767/")
        with self.assertRaises(ValidationError):
            ScopePolicy.model_validate(self.scope | {"allowed_cidrs": ["::1/128"]})


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.server = create_server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.scope = scope_for(self.origin)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def run_scan(self, path="/", cancelled=lambda: False):
        return scan(self.scope, self.origin + path, cancelled, lambda event: None)

    def test_real_fixture_seeded_issues_then_repaired_headers_clear_findings(self):
        result = self.run_scan()
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(result["requests_performed"], 1)
        self.assertEqual(len(result["findings"]), 5)
        self.assertTrue(
            all(f["confidence"] == "high" and f["status"] == "confirmed" for f in result["findings"])
        )
        self.assertTrue(
            all(f["severity"] in {"low", "info"} and f["cvss_score"] is None for f in result["findings"])
        )
        self.server.secure_headers = True
        repaired = self.run_scan()
        self.assertEqual(repaired["outcome"], "completed")
        self.assertEqual(repaired["findings"], [])
        self.assertTrue(
            any(c["category"] == "http_headers" and c["status"] == "completed" for c in repaired["checks"])
        )

    def test_evidence_redacts_cookie_arbitrary_header_and_body_values(self):
        result = self.run_scan()
        serialized = json.dumps(result)
        for secret in [
            "never-retain-this-cookie-value",
            "never-retain-this-header-value",
            "never-retain-this-body",
        ]:
            self.assertNotIn(secret, serialized)
        self.assertFalse(result["observations"][0]["body_retained"])
        self.assertEqual(
            result["observations"][0]["facts"]["cookie_flags"],
            [{"secure": False, "httponly": False, "samesite": "unset"}],
        )

    def test_redirects_are_revalidated_before_connection(self):
        for path in ["/redirect-outside", "/redirect-excluded", "/redirect-loop"]:
            with self.subTest(path=path):
                result = self.run_scan(path)
                self.assertEqual(result["outcome"], "completed_with_errors")
                self.assertEqual(result["requests_performed"], 1)
                self.assertEqual(result["findings"], [])
                self.assertFalse(
                    any(
                        c["category"] == "http_headers" and c["status"] == "completed"
                        for c in result["checks"]
                    )
                )
        allowed = self.run_scan("/redirect-inside")
        self.assertEqual(allowed["outcome"], "completed")
        self.assertEqual(allowed["requests_performed"], 2)
        covered_urls = {
            check["url"]
            for check in allowed["checks"]
            if check["category"] == "http_headers" and check["status"] == "completed"
        }
        self.assertEqual(covered_urls, {self.origin + "/app"})

    def test_numeric_connection_never_uses_dns(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS must not be used")):
            result = self.run_scan()
        self.assertEqual(result["outcome"], "completed")

    def test_connection_time_peer_mismatch_stops_before_http_request(self):
        with patch("packages.scanner_adapters._DeadlineSocket.getpeername", return_value=("10.0.0.1", 80)):
            result = self.run_scan()
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["requests_performed"], 0)
        self.assertEqual(result["observations"], [])
        self.assertIn("pinned destination", result["checks"][-1]["detail"])

    def test_expiry_between_redirect_hops_stops_before_second_connection(self):
        now = datetime.now(UTC)
        self.scope["expires_at"] = (now + timedelta(milliseconds=80)).isoformat()
        result = self.run_scan("/redirect-inside")
        self.assertEqual(result["outcome"], "completed_with_errors")
        self.assertEqual(result["requests_performed"], 1)

    def test_cancellation_before_and_between_requests(self):
        before = self.run_scan(cancelled=lambda: True)
        self.assertEqual(before["outcome"], "cancelled")
        self.assertEqual(before["requests_performed"], 0)
        events = []
        result = scan(
            self.scope,
            self.origin + "/redirect-inside",
            lambda: bool(events),
            events.append,
        )
        self.assertEqual(result["outcome"], "cancelled")

    def test_slow_drip_headers_have_a_total_deadline(self):
        started = time.monotonic()
        with patch("packages.scanner_adapters.REQUEST_TIMEOUT", 0.2):
            result = self.run_scan("/slow-header")
        self.assertEqual(result["outcome"], "failed")
        self.assertLess(time.monotonic() - started, 0.7)

    def test_scope_expiry_bounds_an_inflight_slow_response(self):
        self.scope["expires_at"] = (datetime.now(UTC) + timedelta(milliseconds=120)).isoformat()
        started = time.monotonic()
        result = self.run_scan("/slow-header")
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["observations"], [])
        self.assertLess(time.monotonic() - started, 0.7)

    def test_header_size_limit_reports_failure(self):
        result = self.run_scan("/large-headers")
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["observations"], [])

    def test_failed_connection_cannot_imply_a_successful_retest(self):
        self.server.shutdown()
        self.server.server_close()
        result = self.run_scan()
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["findings"], [])
        self.assertTrue(any(c["status"] == "failed" for c in result["checks"]))

    def test_missing_external_adapters_are_never_runnable(self):
        tools = preflight()
        self.assertEqual({tool["id"] for tool in tools}, {tool.adapter_id for tool in adapter_roadmap()})
        self.assertTrue(tools[0]["runnable"])
        self.assertTrue(all(not tool["runnable"] and tool["version"] is None for tool in tools[1:]))

    def test_real_tls_trust_and_literal_hostname_verification_without_insecure_fallback(self):
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("OpenSSL unavailable for ephemeral local test certificates.")
        original_context = ssl.create_default_context
        with tempfile.TemporaryDirectory() as directory:
            for certificate_ip in ["127.0.0.1", "127.0.0.2"]:
                certificate = Path(directory) / "certificate.pem"
                key = Path(directory) / "key.pem"
                subprocess.run(
                    [
                        openssl,
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-days",
                        "1",
                        "-keyout",
                        str(key),
                        "-out",
                        str(certificate),
                        "-subj",
                        "/CN=AEGIS synthetic test certificate",
                        "-addext",
                        f"subjectAltName=IP:{certificate_ip}",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certificate, key)
                server = create_server(secure_headers=True)
                server.socket = context.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                url = f"https://127.0.0.1:{server.server_port}/"
                scope = scope_for(url)
                try:
                    # With the real default trust store, the synthetic issuer is rejected.
                    untrusted = scan(scope, url, lambda: False, lambda event: None)
                    self.assertEqual(untrusted["outcome"], "failed")
                    self.assertEqual(untrusted["observations"], [])
                    self.assertIn("No insecure fallback", untrusted["checks"][-1]["detail"])

                    def trust_test_issuer():
                        client_context = original_context()
                        client_context.load_verify_locations(cafile=certificate)
                        return client_context

                    with patch("packages.scanner_adapters.ssl.create_default_context", trust_test_issuer):
                        checked = scan(scope, url, lambda: False, lambda event: None)
                    if certificate_ip == "127.0.0.1":
                        self.assertEqual(checked["outcome"], "completed")
                        tls_observation = next(
                            o for o in checked["observations"] if o["kind"] == "tls_handshake"
                        )
                        self.assertTrue(tls_observation["certificate_verified"])
                        self.assertTrue(tls_observation["hostname_verified"])
                        self.assertEqual(len(tls_observation["certificate_sha256"]), 64)
                        self.assertTrue(
                            any(
                                f["title"] == "Strict-Transport-Security header is absent"
                                for f in checked["findings"]
                            )
                        )
                    else:
                        self.assertEqual(checked["outcome"], "failed")
                        self.assertEqual(checked["observations"], [])
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
