"""Acceptance tests for AutoPyVerifier, Consensus Best-of-N, and Entropy Gate (G2–G7)."""

import threading
import unittest

from services.ai_analysis_worker.autopyverifier import (
    AutoPyVerifier,
    ConsensusSearchEngine,
    FlightLogDatasetIngester,
)


class AutoPyVerifierAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.verifier = AutoPyVerifier()
        self.consensus = ConsensusSearchEngine()

    def test_autopyverifier_synthesizes_and_executes_script(self):
        script = self.verifier.synthesize_script(
            target_url="http://127.0.0.1:8000/api",
            vuln_type="sqli",
            canary="sharay_canary_test_123",
            mock_mode=True,
        )
        self.assertIn("sharay_canary_test_123", script)
        self.assertIn("def verify():", script)

        # Execute in sandbox
        result = self.verifier.execute_in_sandbox(script, timeout_seconds=4)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["returncode"], 0)

    def test_autopyverifier_handles_failed_assertion(self):
        failing_script = """
def verify():
    assert "token_expected" in "wrong_token", "Canary not reflected"

if __name__ == "__main__":
    verify()
"""
        result = self.verifier.execute_in_sandbox(failing_script, timeout_seconds=4)
        self.assertEqual(result["status"], "failed")
        self.assertNotEqual(result["returncode"], 0)
        self.assertIn("Canary not reflected", result["error"])

    def test_consensus_voting_selects_best_candidate(self):
        candidates = [
            {"id": "cand_1", "hypothesis": "SQLi in id parameter", "verdict": True},
            {"id": "cand_2", "hypothesis": "SQLi in id parameter", "verdict": True},
            {"id": "cand_3", "hypothesis": "SQLi in id parameter", "verdict": True},
            {"id": "cand_4", "hypothesis": "SQLi in id parameter", "verdict": True},
            {"id": "cand_5", "hypothesis": "False positive header glitch", "verdict": False},
        ]
        result = self.consensus.evaluate_candidates(candidates)

        self.assertEqual(result["consensus_decision"], "SQLi in id parameter")
        self.assertEqual(result["agreement_ratio"], 0.8)
        self.assertFalse(result["escalated"])

    def test_entropy_gate_escalates_on_high_variance(self):
        # 50/50 split among candidates causes high Shannon entropy (1.0)
        split_candidates = [
            {"id": "c1", "hypothesis": "Exploit Successful", "verdict": True},
            {"id": "c2", "hypothesis": "Exploit Successful", "verdict": True},
            {"id": "c3", "hypothesis": "Target Immune", "verdict": False},
            {"id": "c4", "hypothesis": "Target Immune", "verdict": False},
        ]
        result = self.consensus.evaluate_candidates(split_candidates, entropy_threshold=0.8)

        self.assertTrue(result["escalated"])
        self.assertGreaterEqual(result["entropy"], 0.8)
        self.assertIn("Gemini", result["escalation_target"])

    def test_flight_log_ingestion_into_dataset(self):
        ingester = FlightLogDatasetIngester()
        flight_log = [
            {"direction": "stdin", "sender": "human", "preview": "sqlmap -u target --batch"},
            {"direction": "system", "action": "ownership_preempted_by_human"},
            {"direction": "stdin", "sender": "human", "preview": "curl -v target/api"},
        ]
        dataset_entries = ingester.ingest(flight_log, session_id="test_sess_001")

        self.assertGreaterEqual(len(dataset_entries), 2)
        self.assertEqual(dataset_entries[0]["session_id"], "test_sess_001")
        self.assertIn("sqlmap", dataset_entries[0]["command"])

    def test_autopyverifier_non_mock_execution_against_live_fixtures(self):
        """Verifies non-mock AutoPyVerifier scripts execute against real live endpoints with no NameError."""
        import http.server

        canary = "sharay_canary_verified_9942"
        vulnerable_mode = True

        class MockVulnHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                if vulnerable_mode:
                    self.wfile.write(
                        f"<html><body>Welcome user! ID: 1, Canary: {canary}</body></html>".encode("utf-8")
                    )
                else:
                    self.wfile.write(b"<html><body>Patched input sanitization</body></html>")

            def do_POST(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                if vulnerable_mode:
                    self.wfile.write(
                        f"<html><body>Posted data received with {canary}</body></html>".encode("utf-8")
                    )
                else:
                    self.wfile.write(b"<html><body>Patched POST handler</body></html>")

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), MockVulnHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            # 1. Test GET non-mock script against vulnerable response
            vulnerable_mode = True
            get_script = self.verifier.synthesize_script(
                target_url=f"http://127.0.0.1:{port}/vuln",
                vuln_type="sqli",
                canary=canary,
                method="GET",
                parameter="id",
                mock_mode=False,
            )
            # Ensure body is defined in script
            self.assertIn("body = resp.read()", get_script)
            res_get = self.verifier.execute_in_sandbox(get_script, timeout_seconds=5)
            self.assertEqual(res_get["returncode"], 0)
            self.assertEqual(res_get["status"], "verified")
            self.assertIn("VERIFICATION_SUCCESS", res_get["stdout"])

            # 2. Test GET non-mock script against patched response (demote/fail)
            vulnerable_mode = False
            res_get_patched = self.verifier.execute_in_sandbox(get_script, timeout_seconds=5)
            self.assertNotEqual(res_get_patched["returncode"], 0)
            self.assertEqual(res_get_patched["status"], "failed")

            # 3. Test POST non-mock script against vulnerable response
            vulnerable_mode = True
            post_script = self.verifier.synthesize_script(
                target_url=f"http://127.0.0.1:{port}/post_vuln",
                vuln_type="sqli",
                canary=canary,
                method="POST",
                parameter="data",
                mock_mode=False,
            )
            self.assertIn("body = resp.read()", post_script)
            res_post = self.verifier.execute_in_sandbox(post_script, timeout_seconds=5)
            self.assertEqual(res_post["returncode"], 0)
            self.assertEqual(res_post["status"], "verified")
            self.assertIn("VERIFICATION_SUCCESS", res_post["stdout"])

            # 4. Test POST non-mock script against patched response (demote/fail)
            vulnerable_mode = False
            res_post_patched = self.verifier.execute_in_sandbox(post_script, timeout_seconds=5)
            self.assertNotEqual(res_post_patched["returncode"], 0)
            self.assertEqual(res_post_patched["status"], "failed")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
