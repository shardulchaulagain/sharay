"""Dual-identity authorization matrix runs when two real operator identities are supplied (not skipped)."""

import unittest
from unittest.mock import patch

from packages.scanner_adapters import scan_comprehensive
from packages.security_policies import Destination


class AuthorizationMatrixWiringTests(unittest.TestCase):
    def setUp(self):
        # Loopback http so the pipeline's real network probes (TLS, port scan) fast-fail; the matrix
        # prober itself is stubbed, so no real requests are made.
        self.dest = Destination(
            url="http://127.0.0.1:9/",
            scheme="http",
            host="127.0.0.1",
            port=9,
            origin="http://127.0.0.1:9",
            ip="127.0.0.1",
            path="/",
        )

    def _run(self, auth):
        # A no-op container runner; the matrix stage uses its own HTTP prober, which we stub below.
        def runner(image, argv, **kwargs):
            from types import SimpleNamespace

            return SimpleNamespace(outcome="completed", exit_code=0, stdout=b"", output_truncated=False)

        return scan_comprehensive(
            self.dest, "127.0.0.1", run=runner, tools=["auth_matrix"], mode="standard", auth=auth
        )

    def test_matrix_skipped_with_fewer_than_two_identities(self):
        res = self._run({"identity_names": ["solo"], "identities": {"solo": {"cookies": {}, "headers": {}}}})
        matrix = next(c for c in res["checks"] if c["category"] == "authorization_matrix")
        self.assertEqual(matrix["status"], "skipped")
        self.assertIn("two provisioned operator identities", matrix["detail"])

    def test_matrix_runs_with_two_identities(self):
        captured = {}

        class StubProber:
            def __init__(self, destination, allow_ip, identities):
                captured["identities"] = set(identities)

            def sweep(self, targets):
                captured["targets"] = len(targets)
                return {"findings": [{"endpoint": "/api/user/101", "resource_id": "101", "detail": "bob read alice"}]}

        auth = {
            "identity_names": ["alice", "bob"],
            "identities": {
                "alice": {"cookies": {}, "headers": {"Authorization": "Bearer a"}, "user_id": "101", "role": "alice"},
                "bob": {"cookies": {"sid": "b"}, "headers": {}, "user_id": "102", "role": "bob"},
            },
        }
        with patch("packages.scanner_adapters.integrations.authorization.AuthorizationMatrixProber", StubProber):
            res = self._run(auth)

        self.assertEqual(captured["identities"], {"alice", "bob"})
        matrix = next(c for c in res["checks"] if c["category"] == "authorization_matrix")
        self.assertEqual(matrix["status"], "completed")
        self.assertTrue(any(f["category"] == "broken_object_level_authorization" for f in res["findings"]))


if __name__ == "__main__":
    unittest.main()
