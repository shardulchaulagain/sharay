"""Acceptance test suite for Sector O2: Metasploit at Full Capacity & Safe-Gated Sessions.

Verifies:
1. Programmatic MSF RPC client protocol formatting and session management.
2. Dynamic module tree search across exploit/auxiliary/post namespaces by CVE and product.
3. Safe-gated check -> exploit -> benign session lifecycle with clean teardown receipts.
4. Msfvenom benign payload generation for verification markers.
5. Read-only post-exploitation evidence collection within authorized scope boundaries.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from packages.scanner_adapters.integrations.msf_rpc import (
    BenignSessionExecutionResult,
    MetasploitModuleDescriptor,
    MetasploitRPCClient,
    MsfvenomPayloadGenerator,
    OperatorConsentReceipt,
)


class TestSectorO2MetasploitFullCapacity(unittest.TestCase):
    def setUp(self):
        self.mock_transport = MagicMock()
        self.client = MetasploitRPCClient(
            host="127.0.0.1",
            port=55553,
            username="msf",
            password="test_password",
            transport=self.mock_transport,
        )

    def test_rpc_authentication_and_handshake(self):
        """O2.1: MSF RPC client performs authentication and acquires session token."""
        self.mock_transport.send_rpc.return_value = {
            "result": "success",
            "token": "TEMP_MSF_RPC_AUTH_TOKEN_12345",
        }

        token = self.client.login()
        self.assertEqual(token, "TEMP_MSF_RPC_AUTH_TOKEN_12345")
        self.mock_transport.send_rpc.assert_called_with("auth.login", ["msf", "test_password"])

    def test_dynamic_module_tree_search(self):
        """O2.2: Searches dynamic Metasploit module tree by CVE and service keywords."""
        self.mock_transport.send_rpc.return_value = {
            "modules": [
                {
                    "type": "exploit",
                    "fullname": "exploit/multi/http/apache_normalize_path",
                    "name": "Apache 2.4.49/2.4.50 Path Traversal and RCE",
                    "rank": "excellent",
                    "references": ["CVE-2021-41773", "CVE-2021-42013"],
                    "description": "Exploits path traversal and CGI execution in Apache HTTP Server.",
                    "targets": ["Automatic", "Unix", "Windows"],
                },
                {
                    "type": "auxiliary",
                    "fullname": "auxiliary/scanner/http/apache_normalize_path_traversal",
                    "name": "Apache 2.4.49/2.4.50 Path Traversal Scanner",
                    "rank": "normal",
                    "references": ["CVE-2021-41773"],
                    "description": "Scans for path traversal vulnerability.",
                    "targets": [],
                },
            ]
        }

        # Search by CVE
        results = self.client.search_modules("CVE-2021-41773")
        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], MetasploitModuleDescriptor)
        self.assertEqual(results[0].fullname, "exploit/multi/http/apache_normalize_path")
        self.assertEqual(results[0].rank, "excellent")

    def test_safe_gated_exploit_and_benign_session_lifecycle(self):
        """O2.3: Safe-gate check -> exploit -> benign proof -> clean session teardown."""
        # Step 1: Precondition check
        self.mock_transport.send_rpc.side_effect = [
            # check call response
            {"code": "vulnerable", "reason": "Target vulnerable to path traversal"},
            # exploit execution call response
            {"job_id": 101, "uuid": "sess-uuid-99"},
            # session list polling
            {"1": {"type": "shell", "info": "sh", "target_host": "104.21.13.218"}},
            # command execution output
            {"data": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"},
            # session kill response
            {"result": "success"},
        ]

        consent = OperatorConsentReceipt(
            operator_id="operator_shardul",
            target_url="https://example.com/",
            approved_module="exploit/multi/http/apache_normalize_path",
            non_destructive_command="id",
            session_lifetime_limit_seconds=10.0,
        )

        res: BenignSessionExecutionResult = self.client.execute_benign_verification(
            module_name="exploit/multi/http/apache_normalize_path",
            options={"RHOSTS": "104.21.13.218", "RPORT": 443, "SSL": True},
            consent=consent,
        )

        self.assertTrue(res.check_passed)
        self.assertTrue(res.session_opened)
        self.assertIn("uid=33(www-data)", res.proof_evidence)
        self.assertTrue(res.clean_teardown)
        self.assertIsNotNone(res.receipt_hash)

    def test_unauthorized_action_rejected_without_operator_consent(self):
        """O2.3: Action without operator consent receipt raises PermissionError fail-closed."""
        with self.assertRaises(PermissionError):
            self.client.execute_benign_verification(
                module_name="exploit/multi/http/apache_normalize_path",
                options={"RHOSTS": "104.21.13.218"},
                consent=None,  # Missing consent
            )

    def test_msfvenom_benign_payload_generation(self):
        """O2.4: Msfvenom generator creates safe pingback/id payloads for verification."""
        gen = MsfvenomPayloadGenerator()
        payload = gen.generate_benign_command(
            platform="linux",
            marker="SHARAY_BENIGN_VERIFY_2026",
            command="id",
        )
        self.assertIn("echo SHARAY_BENIGN_VERIFY_2026", payload)
        self.assertIn("id", payload)

    def test_safe_post_exploitation_enumeration(self):
        """O2.5: Read-only post modules collect environment facts without modification."""
        self.mock_transport.send_rpc.side_effect = [
            # session write/read for read-only enum
            {"data": "Linux target-host 5.15.0-generic #1 SMP x86_64\n"},
            {"data": "/etc/os-release: Ubuntu 22.04 LTS\n"},
            {"result": "success"},  # close
        ]
        info = self.client.collect_read_only_post_evidence(session_id=1)
        self.assertIn("kernel", info)
        self.assertIn("5.15.0", info["kernel"])
        self.assertIn("Ubuntu", info["os_release"])


class TestSectorO2FailClosedAndRealTransport(unittest.TestCase):
    """Integrity: the client never fabricates a session, and the real JSON-RPC transport works."""

    def test_no_transport_fails_closed_never_fabricates(self):
        from packages.scanner_adapters.integrations.msf_rpc import MsfRpcUnavailable

        client = MetasploitRPCClient(password="x")  # no transport configured
        with self.assertRaises(MsfRpcUnavailable):
            client.login()
        with self.assertRaises(MsfRpcUnavailable):
            client.search_modules("apache")
        with self.assertRaises(MsfRpcUnavailable):
            client.collect_read_only_post_evidence(1)
        consent = OperatorConsentReceipt(operator_id="o", target_url="u", approved_module="exploit/x")
        # Consent is present and matches, so the only reason to refuse is the missing transport —
        # i.e. it fails closed instead of returning a fabricated uid=33(www-data) session.
        with self.assertRaises(MsfRpcUnavailable):
            client.execute_benign_verification("exploit/x", {}, consent)

    def test_real_http_jsonrpc_transport_full_flow(self):
        """O2.1-2.3 over a REAL HTTP JSON-RPC transport against a mock msfrpcd."""
        import http.server
        import json
        import socketserver
        import threading

        from packages.scanner_adapters.integrations.msf_rpc import connect

        responses = {
            "auth.login": {"token": "REAL_TOKEN_abc123"},
            "module.search": {
                "modules": [
                    {
                        "type": "exploit",
                        "fullname": "exploit/multi/http/apache_normalize_path",
                        "name": "Apache Path Traversal RCE",
                        "rank": "excellent",
                        "references": ["CVE-2021-41773"],
                        "description": "x",
                        "targets": ["Unix"],
                    }
                ]
            },
            "module.check": {"code": "vulnerable"},
            "module.execute": {"job_id": 42, "uuid": "u-1"},
            "session.list": {"1": {"type": "shell", "target_host": "127.0.0.1"}},
            "session.shell_write": {"data": "uid=0(root) gid=0(root)\n"},
            "session.stop": {"result": "success"},
        }
        seen_auth_header = {}

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n))
                seen_auth_header["value"] = self.headers.get("Authorization")
                out = json.dumps(
                    {"jsonrpc": "2.0", "result": responses.get(req["method"], {}), "id": req["id"]}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        srv.allow_reuse_address = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            client = connect(f"http://127.0.0.1:{port}/api/v1/json-rpc", "msf", "pw")
            self.assertEqual(client.token, "REAL_TOKEN_abc123")

            mods = client.search_modules("CVE-2021-41773")
            self.assertEqual(len(mods), 1)
            self.assertEqual(mods[0].fullname, "exploit/multi/http/apache_normalize_path")

            consent = OperatorConsentReceipt(
                operator_id="op",
                target_url="http://127.0.0.1/",
                approved_module="exploit/multi/http/apache_normalize_path",
            )
            res = client.execute_benign_verification(
                "exploit/multi/http/apache_normalize_path", {"RHOSTS": "127.0.0.1"}, consent
            )
            self.assertTrue(res.check_passed)
            self.assertTrue(res.session_opened)
            self.assertIn("uid=0(root)", res.proof_evidence)
            self.assertTrue(res.clean_teardown)
            # The bearer token from auth.login was carried on later authenticated calls.
            self.assertEqual(seen_auth_header["value"], "Bearer REAL_TOKEN_abc123")
        finally:
            srv.shutdown()
            srv.server_close()


class TestSectorO2ConsoleSearchWiring(unittest.TestCase):
    """The console's module search prefers the live RPC tree when msfrpcd is configured."""

    def test_search_uses_live_rpc_tree_when_configured_else_static(self):
        import http.server
        import json
        import os
        import socketserver
        import threading

        from packages.scanner_adapters.integrations.metasploit import search_metasploit_modules

        resp = {
            "auth.login": {"token": "T"},
            "module.search": {
                "modules": [
                    {
                        "type": "auxiliary",
                        "fullname": "auxiliary/scanner/http/live_only_mod",
                        "name": "Live only module",
                        "rank": "normal",
                        "references": ["CVE-2024-0001"],
                        "description": "d",
                        "targets": [],
                    }
                ]
            },
        }

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n))
                out = json.dumps(
                    {"jsonrpc": "2.0", "result": resp.get(req["method"], {}), "id": req["id"]}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        # Without configuration: the static offensive catalog (no RPC call).
        static = search_metasploit_modules("log4j")
        self.assertTrue(static)
        self.assertNotEqual(static[0].get("source"), "msfrpc")

        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        srv.allow_reuse_address = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        os.environ["SHARAY_MSFRPC_URL"] = f"http://127.0.0.1:{port}/api/v1/json-rpc"
        try:
            live = search_metasploit_modules("cve-2024-0001")
            self.assertEqual(live[0]["source"], "msfrpc")
            self.assertEqual(live[0]["fullname"], "auxiliary/scanner/http/live_only_mod")
            self.assertEqual(live[0]["cve"], "CVE-2024-0001")
        finally:
            os.environ.pop("SHARAY_MSFRPC_URL", None)
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
