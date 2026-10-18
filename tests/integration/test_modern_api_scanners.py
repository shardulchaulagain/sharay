"""Hermetic unit tests for GraphQL and WebSocket API security analyzers."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from packages.scanner_adapters.integrations.graphql_scanner import audit_graphql_endpoint
from packages.scanner_adapters.integrations.websocket_scanner import audit_websocket_endpoint
from packages.security_policies import Destination


class ModernAPIScannersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.destination = Destination(
            url="http://127.0.0.1:8080/",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            path="/",
            origin="http://127.0.0.1:8080",
            ip="127.0.0.1",
        )

    def test_graphql_introspection_and_batch_amplification_detected(self) -> None:
        def mock_request(dest, allow_ip, method, path, headers=None, body=None, timeout=3.5):
            if path == "/graphql":
                if body and "__schema" in body:
                    schema_data = {
                        "data": {
                            "__schema": {
                                "queryType": {"name": "Query"},
                                "mutationType": {"name": "Mutation"},
                                "types": [
                                    {"name": "Query", "kind": "OBJECT"},
                                    {"name": "User", "kind": "OBJECT"},
                                    {"name": "Order", "kind": "OBJECT"},
                                    {"name": "AdminSecret", "kind": "OBJECT"},
                                ],
                            }
                        }
                    }
                    return 200, {"content-type": "application/json"}, json.dumps(schema_data), 15.0
                elif body and isinstance(json.loads(body), list):
                    # 15 batched queries
                    batch_resp = [{"data": {"__typename": "Query"}} for _ in range(15)]
                    return 200, {"content-type": "application/json"}, json.dumps(batch_resp), 20.0
                elif body and "__sharay_canary" in body:
                    return (
                        200,
                        {},
                        '{"errors": [{"message": "Cannot query field. Did you mean __schema?"}]}',
                        15.0,
                    )
            return 404, {}, "", 10.0

        with patch(
            "packages.scanner_adapters.integrations.graphql_scanner._request_graphql",
            side_effect=mock_request,
        ):
            res = audit_graphql_endpoint(self.destination, "127.0.0.1", discovered_endpoints=["/graphql"])
            findings = res["findings"]

            # Introspection + Batch + Field suggestions
            self.assertGreaterEqual(len(findings), 2)
            cwe_ids = [f["cwe_id"] for f in findings]
            self.assertIn("CWE-200", cwe_ids)
            self.assertIn("CWE-776", cwe_ids)

            intro_finding = next(f for f in findings if f["cwe_id"] == "CWE-200")
            self.assertIn("Introspection Enabled", intro_finding["title"])
            self.assertEqual(intro_finding["poc"]["type_count"], 4)
            self.assertEqual(intro_finding["poc"]["mutation_root"], "Mutation")

    def test_graphql_hardened_endpoint_clean(self) -> None:
        def mock_request(dest, allow_ip, method, path, headers=None, body=None, timeout=3.5):
            return 400, {}, '{"errors": [{"message": "GraphQL introspection is strictly forbidden."}]}', 10.0

        with patch(
            "packages.scanner_adapters.integrations.graphql_scanner._request_graphql",
            side_effect=mock_request,
        ):
            res = audit_graphql_endpoint(self.destination, "127.0.0.1", discovered_endpoints=["/graphql"])
            self.assertEqual(len(res["findings"]), 0)

    def test_websocket_cswsh_detected_when_arbitrary_origin_accepted(self) -> None:
        def mock_probe(dest, allow_ip, path, origin_header, timeout=3.5):
            if path == "/ws":
                # Server blindly accepts evil origin and completes handshake
                return (
                    101,
                    {"upgrade": "websocket", "sec-websocket-accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
                    15.0,
                )
            return 404, {}, 10.0

        with patch(
            "packages.scanner_adapters.integrations.websocket_scanner._probe_websocket_upgrade",
            side_effect=mock_probe,
        ):
            res = audit_websocket_endpoint(self.destination, "127.0.0.1", discovered_endpoints=["/ws"])
            findings = res["findings"]
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding["category"], "broken_access_control")
            self.assertEqual(finding["cwe_id"], "CWE-1385")
            self.assertIn("Cross-Site WebSocket Hijacking", finding["title"])
            self.assertEqual(finding["status"], "confirmed")
            self.assertEqual(finding["lifecycle_state"], "REPRODUCED")

    def test_websocket_origin_enforced_produces_no_finding(self) -> None:
        def mock_probe(dest, allow_ip, path, origin_header, timeout=3.5):
            if "evil" in origin_header:
                return 403, {}, 10.0
            return 101, {"upgrade": "websocket"}, 15.0

        with patch(
            "packages.scanner_adapters.integrations.websocket_scanner._probe_websocket_upgrade",
            side_effect=mock_probe,
        ):
            res = audit_websocket_endpoint(self.destination, "127.0.0.1", discovered_endpoints=["/ws"])
            self.assertEqual(len(res["findings"]), 0)


if __name__ == "__main__":
    unittest.main()
