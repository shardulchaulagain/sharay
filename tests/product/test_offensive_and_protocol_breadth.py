"""Comprehensive Test Suite for Sector 2 (Protocols, Crawler, SAST) & Sector 2B (Offensive Capability & Purple-Team)."""

import hashlib
import unittest
from unittest.mock import patch

from packages.offensive_capability import (
    AttackGraphChainExecutor,
    AuthorizedExploitModule,
    CMDiExecutionOracle,
    ConcurrencyRaceOracle,
    LFISafeConfigOracle,
    MitreAttackMapper,
    SQLiRowExtractionOracle,
    SSTITemplateMathOracle,
    WAFEfficacyAnalyzer,
)
from packages.scanner_adapters.integrations.crawler import (
    _HTMLStructureExtractor,
    crawl,
)
from packages.scanner_adapters.integrations.jwt_grpc_scanner import (
    GraphQLAdvancedFuzzer,
    JWTAttackSuite,
    WebSocketAdvancedFuzzer,
    gRPCScanner,
)
from packages.security_policies import Destination
from packages.source_scanners import SourceScannerPipeline


class OffensiveAndProtocolBreadthTests(unittest.TestCase):
    """Exhaustive test suite for Sector 2 & 2B implementations."""

    # --- Sector 2.4: Authenticated Stateful Crawler ---

    def test_crawler_csrf_extraction_and_cookie_jar(self):
        """Sector 2.4: HTML structure extractor captures CSRF tokens and crawl maintains cookie jar."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="csrf-token" content="secret-meta-csrf-9988">
        </head>
        <body>
            <a href="/dashboard">Dashboard</a>
            <form action="/transfer" method="POST">
                <input type="hidden" name="user_token" value="secret-form-csrf-1122" />
                <input type="text" name="amount" value="100" />
            </form>
        </body>
        </html>
        """
        extractor = _HTMLStructureExtractor("http://target.local")
        extractor.feed(html)

        self.assertIn("csrf-token", extractor.csrf_tokens)
        self.assertEqual(extractor.csrf_tokens["csrf-token"], "secret-meta-csrf-9988")
        self.assertIn("user_token", extractor.csrf_tokens)
        self.assertEqual(extractor.csrf_tokens["user_token"], "secret-form-csrf-1122")

        # Test crawl with session cookies
        dest = Destination(
            url="http://target.local",
            scheme="http",
            host="target.local",
            port=80,
            path="/",
            origin="http://target.local",
            ip="127.0.0.1",
        )
        with patch("packages.scanner_adapters.integrations.crawler._fetch_page") as mock_fetch:
            # First fetch returns a Set-Cookie header
            mock_fetch.return_value = (
                200,
                {"content-type": "text/html", "set-cookie": "session_id=active_sess_5544; Path=/"},
                html,
            )
            res = crawl(
                dest,
                "127.0.0.1",
                cookies={"initial_cookie": "val_1"},
                max_depth=1,
            )

        self.assertTrue(res["authenticated"])
        self.assertIn("session_id", res["session_cookies"])
        self.assertEqual(res["session_cookies"]["session_id"], "active_sess_5544")
        self.assertIn("csrf-token", res["csrf_tokens"])

    # --- Sector 2.6: Source Scanners Pipeline ---

    def test_source_scanners_normalization(self):
        """Sector 2.6: Semgrep, Gitleaks, and OSV outputs are normalized into valid finding envelopes."""
        semgrep_raw = """{
            "results": [{
                "check_id": "python.lang.security.deserialization.pickle",
                "path": "app/views.py",
                "start": {"line": 42},
                "extra": {
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-502: Deserialization of Untrusted Data"]}
                }
            }],
            "paths": {"scanned": ["app/views.py"]}
        }"""
        semgrep_findings = SourceScannerPipeline.normalize_semgrep(semgrep_raw)
        self.assertEqual(len(semgrep_findings), 1)
        f = semgrep_findings[0]
        self.assertEqual(f["category"], "sast_vulnerability")
        self.assertEqual(f["cwe_id"], "CWE-502: Deserialization of Untrusted Data")
        self.assertEqual(f["affected_path"], "app/views.py")
        self.assertEqual(f["line_number"], 42)

        gitleaks_raw = """[{
            "RuleID": "aws-access-key-id",
            "File": "config/settings.py",
            "StartLine": 15,
            "Fingerprint": "dummy_gitleaks_fp",
            "Secret": "AKIAIOSFODNN7EXAMPLE"
        }]"""
        gitleaks_findings = SourceScannerPipeline.normalize_gitleaks(gitleaks_raw)
        self.assertEqual(len(gitleaks_findings), 1)
        gf = gitleaks_findings[0]
        self.assertEqual(gf["category"], "unsecured_credentials")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", gf["description"])  # Secret must NOT be leaked
        self.assertEqual(gf["cwe_id"], "CWE-798")

    # --- Sector 2.7: Protocol Breadth (JWT, gRPC, GraphQL, WebSocket) ---

    def test_jwt_attack_suite(self):
        """Sector 2.7: JWT attack suite generates and audits alg=none and HMAC key confusion."""
        # Standard RS256 token mock
        h_b64 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        p_b64 = "eyJzdWIiOiJ1c2VyXzEwMSIsInJvbGUiOiJhZG1pbiJ9"
        dummy_sig = "dummy_signature_bytes_12345"
        token = f"{h_b64}.{p_b64}.{dummy_sig}"

        # Test alg=none forgery
        none_token = JWTAttackSuite.forge_alg_none(token)
        self.assertTrue(none_token.endswith("."))
        n_header, n_payload, n_sig = JWTAttackSuite.decode_token(none_token)
        self.assertEqual(n_header["alg"], "none")
        self.assertEqual(n_sig, "")

        # Test key confusion forgery
        public_key_pem = (
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----"
        )
        confused_token = JWTAttackSuite.forge_hmac_key_confusion(token, public_key_pem)
        c_header, _, c_sig = JWTAttackSuite.decode_token(confused_token)
        self.assertEqual(c_header["alg"], "HS256")
        self.assertTrue(len(c_sig) > 0)

        # Audit against simulated endpoint accepting alg: none
        def mock_verify(url, headers=None):
            auth = headers.get("Authorization", "")
            if none_token in auth:
                return 200, b'{"status": "authorized"}', 10.0
            return 401, b'{"error": "unauthorized"}', 10.0

        findings = JWTAttackSuite.audit_token(token, mock_verify, "http://target.local/api/admin")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-347")
        self.assertEqual(findings[0]["status"], "confirmed")

    def test_grpc_and_graphql_and_websocket_analyzers(self):
        """Sector 2.7: gRPC frame construction, GraphQL nesting, and WebSocket CSWSH."""
        frame = gRPCScanner.build_grpc_frame(b"test_payload")
        self.assertEqual(frame[0], 0)  # Uncompressed flag
        self.assertEqual(int.from_bytes(frame[1:5], "big"), 12)  # Length 12
        self.assertEqual(frame[5:], b"test_payload")

        # GraphQL circular nesting generator
        nested_query = GraphQLAdvancedFuzzer.generate_circular_query("user", "friends", depth=5)
        self.assertIn("user { friends { friends {", nested_query)

        # GraphQL alias batching generator
        alias_batch = GraphQLAdvancedFuzzer.generate_alias_batch("account", count=5)
        self.assertIn("a0: account(id: 0)", alias_batch)
        self.assertIn("a4: account(id: 4)", alias_batch)

        # WebSocket CSWSH origin validation
        def mock_ws_probe(destination, allow_ip, path, origin_header):
            # Vulnerable server accepts any origin with 101 Switching Protocols
            return 101, {"upgrade": "websocket", "connection": "upgrade"}, 15.0

        dest = Destination(
            "http://target.local", "http", "target.local", 80, "/", "http://target.local", "127.0.0.1"
        )
        ws_res = WebSocketAdvancedFuzzer.test_cswsh(mock_ws_probe, dest, "127.0.0.1")
        self.assertTrue(ws_res["vulnerable"])
        self.assertEqual(ws_res["status_code"], 101)

    # --- Sector 2B.2: Concrete Impact Oracles ---

    def test_impact_oracles(self):
        """Sector 2B.2: Verify postcondition side-effects across SQLi, LFI, CMDi, and SSTI."""
        # 1. SQLi canary row
        sqli_oracle = SQLiRowExtractionOracle("username", "admin_secret_user")
        self.assertTrue(sqli_oracle.evaluate_effect(200, b"Query result: admin_secret_user found", 30.0))
        self.assertFalse(sqli_oracle.evaluate_effect(200, b"Query result: empty", 30.0))

        # 2. LFI safe config
        lfi_oracle = LFISafeConfigOracle("/etc/passwd")
        self.assertTrue(lfi_oracle.evaluate_effect(200, b"root:x:0:0:root:/root:/bin/bash", 20.0))
        self.assertFalse(lfi_oracle.evaluate_effect(200, b"File not found", 20.0))

        # 3. CMDi math execution
        cmdi_oracle = CMDiExecutionOracle(expected_calc="49", canary_token="sharay_exec_proof")
        # Legitimate execution: calculates 49 and includes canary
        self.assertTrue(cmdi_oracle.evaluate_effect(200, b"Output: 49\nsharay_exec_proof", 20.0))
        # Raw echo reflection must be rejected!
        self.assertFalse(cmdi_oracle.evaluate_effect(200, b"echo 49 sharay_exec_proof", 20.0))

        # 4. SSTI template math evaluation
        ssti_oracle = SSTITemplateMathOracle(7, 7)
        # Evaluated: 49
        self.assertTrue(ssti_oracle.evaluate_effect(200, b"Calculated: 49", 20.0))
        # Raw string: "7*7" reflected without evaluation must be rejected
        self.assertFalse(ssti_oracle.evaluate_effect(200, b"Calculated: 7*7", 20.0))

    # --- Sector 2B.3: Min-Cut Exploit Chaining ---

    def test_attack_graph_mincut_chaining(self):
        """Sector 2B.3: Min-cut bottleneck edges are mapped and executed into a multi-step chain."""
        cut_edges = [
            ("AuthService", "UserDatabase", 10.0),
            ("UserDatabase", "AdminShell", 5.0),
        ]
        executor = AttackGraphChainExecutor()
        steps = executor.build_chain_from_mincut("chain-mc-1", cut_edges, "http://target.local")
        self.assertEqual(len(steps), 2)
        self.assertIn("AuthService", steps[0].step_name)
        self.assertIn("AdminShell", steps[1].step_name)

    # --- Sector 2B.4: Authorized Exploitation Module ---

    def test_authorized_exploit_module_benign_session(self):
        """Sector 2B.4: Benign exploitation executes with operator approval and generates clean receipt."""
        module = AuthorizedExploitModule()

        # Reject unapproved execution
        with self.assertRaises(PermissionError):
            module.execute_benign_session("http://target.local", "", lambda: (True, b"evidence"))

        # Approved execution
        receipt = module.execute_benign_session(
            "http://target.local",
            "operator-shardul",
            lambda: (True, b"benign_verification_data"),
        )
        self.assertTrue(receipt.clean_exit)
        self.assertEqual(receipt.operator_approved_by, "operator-shardul")
        self.assertEqual(receipt.evidence_hash, hashlib.sha256(b"benign_verification_data").hexdigest())

    # --- Sector 2B.5: Business Logic Abuse (Race Conditions) ---

    def test_concurrency_race_oracle(self):
        """Sector 2B.5: Synchronized concurrent requests detect TOCTOU / double-spend."""
        # Simulated coupon balance: only 1 should succeed, but flawed state allows 3
        coupon_redemptions = 0

        def mock_redeem():
            nonlocal coupon_redemptions
            # In a race condition, simultaneous checks both read available=True
            if coupon_redemptions < 3:
                coupon_redemptions += 1
                return 200, b"VOUCHER_REDEEMED_SUCCESS", 10.0
            return 400, b"VOUCHER_ALREADY_USED", 10.0

        oracle = ConcurrencyRaceOracle(concurrency=6)
        res = oracle.audit_race_condition(mock_redeem, success_indicator=b"VOUCHER_REDEEMED_SUCCESS")
        self.assertTrue(res["vulnerable"])
        self.assertGreater(res["successful_actions"], 1)

    # --- Sector 2B.6: WAF Efficacy Analyzer ---

    def test_waf_efficacy_analyzer(self):
        """Sector 2B.6: Evaluates raw vs mutated payloads to measure WAF bypass efficacy."""
        analyzer = WAFEfficacyAnalyzer()

        def mock_waf_probe(payload: str):
            # WAF blocks standard SQLi with spaces, but allows comments
            if " " in payload:
                return 403, b"Blocked by WAF", 5.0
            return 200, b"OK", 5.0

        payloads = ["SELECT * FROM users", "UNION SELECT 1, 2, 3"]
        report = analyzer.analyze_target_waf(mock_waf_probe, payloads)
        self.assertEqual(report["raw_block_rate"], 1.0)
        self.assertEqual(report["mutated_block_rate"], 0.0)
        self.assertEqual(report["waf_bypass_delta"], 1.0)
        self.assertEqual(report["waf_posture"], "Strict")

    # --- Sector 2B.8: MITRE ATT&CK Mapping & Purple-Team Matrix ---

    def test_mitre_attack_purple_team_matrix(self):
        """Sector 2B.8: Maps findings to MITRE ATT&CK techniques and produces purple-team report."""
        findings = [
            {"category": "sqli", "title": "SQL Injection in /api/users", "severity": "critical"},
            {"category": "cmdi", "title": "OS Command Injection in /ping", "severity": "critical"},
            {"category": "unsecured_credentials", "title": "Hardcoded API Key", "severity": "high"},
        ]
        matrix = MitreAttackMapper.generate_purple_team_matrix(findings)
        self.assertEqual(matrix["total_techniques_exercised"], 3)
        self.assertIn("Initial Access", matrix["tactics_coverage"])
        self.assertIn("Execution", matrix["tactics_coverage"])
        self.assertIn("Credential Access", matrix["tactics_coverage"])
        self.assertIn("T1190", matrix["technique_frequency"])
        self.assertIn("T1059", matrix["technique_frequency"])
        self.assertIn("T1552", matrix["technique_frequency"])


if __name__ == "__main__":
    unittest.main()
