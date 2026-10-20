"""Acceptance test suite for Sector O3 (Real Payload Engine) and Sector O4 (Response-Driven Adaptive Loop).

Verifies:
1. Recursive Context-Free Grammar (CFG) generation across all 10 vulnerability classes.
2. Semantic AST grammar mutation (node-level transformations, not simple regex replacement).
3. Context-aware injection breakout and multi-stage encoder chains.
4. Closed-loop feedback response analysis adjusting subsequent probes.
5. WAF probe-and-adapt filter learning and evasion matrix synthesis.
6. Dynamic oracle auto-selection based on observed target response properties.
"""

from __future__ import annotations

import unittest

from packages.payload_engine import (
    ASTMutationEngine,
    CFGGrammarEngine,
    ClosedLoopAdaptiveOrchestrator,
    ContextAwareEncoder,
    DynamicOracleSelector,
    InjectionContext,
    VulnClass,
    WAFProbeLearner,
)


class TestSectorO3AndO4PayloadAndAdaptiveEngine(unittest.TestCase):
    def test_cfg_grammar_coverage_across_classes(self):
        """O3.1: True recursive production-rule grammars generate payloads across 10 classes."""
        cfg = CFGGrammarEngine(seed=42)

        classes_to_test = [
            VulnClass.SQLI,
            VulnClass.SSTI,
            VulnClass.XXE,
            VulnClass.NOSQL,
            VulnClass.LDAP,
            VulnClass.XPATH,
            VulnClass.DESERIALIZATION,
            VulnClass.SSRF,
            VulnClass.PROTOTYPE_POLLUTION,
            VulnClass.GRAPHQL,
        ]

        for vc in classes_to_test:
            payloads = cfg.generate(vc, count=3)
            self.assertGreaterEqual(len(payloads), 3, f"Class {vc} failed to generate >=3 payloads")
            for p in payloads:
                self.assertTrue(len(p) > 0, f"Class {vc} generated an empty payload")

        # Verify class-specific syntax validity
        ssti = cfg.generate(VulnClass.SSTI, subtype="jinja2")[0]
        self.assertIn("{{", ssti)
        self.assertIn("}}", ssti)

        xxe = cfg.generate(VulnClass.XXE, subtype="parameter_entity")[0]
        self.assertIn("<!ENTITY", xxe)

        nosql = cfg.generate(VulnClass.NOSQL)[0]
        self.assertTrue("$where" in nosql or "$ne" in nosql or "$regex" in nosql)

        pp = cfg.generate(VulnClass.PROTOTYPE_POLLUTION)[0]
        self.assertTrue("__proto__" in pp or "constructor.prototype" in pp)

    def test_semantic_ast_mutation_not_string_replace(self):
        """O3.2: AST mutations parse grammar trees and transform node operators and whitespace."""
        mutator = ASTMutationEngine(seed=1337)
        original_sqli = "SELECT username, password FROM users WHERE id = 1 UNION SELECT 1, 2"

        # Mutate SQL AST
        tree = mutator.parse_sql(original_sqli)
        mutated_ast = mutator.mutate_sql_tree(tree)
        mutated_code = mutator.unparse_sql(mutated_ast)

        self.assertNotEqual(original_sqli, mutated_code)
        # Check that equivalence or valid SQL structure was preserved
        self.assertIn("SELECT", mutated_code.upper())
        self.assertIn("UNION", mutated_code.upper())

    def test_context_aware_injection_and_encoder_chains(self):
        """O3.3: Detects injection context and applies breakout delimiters + encoder chains."""
        encoder = ContextAwareEncoder()

        # HTML attribute context
        attr_payload = encoder.wrap_for_context("alert(1)", InjectionContext.HTML_ATTRIBUTE)
        self.assertTrue(attr_payload.startswith('"') or attr_payload.startswith("'") or ">" in attr_payload)

        # JavaScript string literal context
        js_payload = encoder.wrap_for_context("alert(1)", InjectionContext.JS_STRING_LITERAL)
        self.assertTrue("';alert(1)//" in js_payload or '";alert(1)//' in js_payload)

        # Encoder chain: double-URL encode
        encoded = encoder.apply_encoding_chain("<script>alert(1)</script>", ["url", "url"])
        self.assertEqual(encoded, "%253Cscript%253Ealert(1)%253C%252Fscript%253E")

        # Encoder chain: base64 wrap
        b64_encoded = encoder.apply_encoding_chain("cat /etc/passwd", ["base64_sh"])
        self.assertIn("echo ", b64_encoded)
        self.assertIn("| base64 -d | sh", b64_encoded)

    def test_closed_loop_feedback_adaptation(self):
        """O4.1: Live response feedback steers payload selection and bypass transformation."""
        orchestrator = ClosedLoopAdaptiveOrchestrator()

        # Step 1: Initial probe triggers a 403 WAF block
        decision1 = orchestrator.process_response(
            probe="UNION SELECT 1, 2",
            status_code=403,
            body="Access Denied by WAF (Keyword Blocked: UNION)",
            latency_ms=12.0,
        )
        self.assertEqual(decision1.action, "switch_bypass_strategy")
        self.assertEqual(decision1.detected_filter, "keyword_block")

        # Step 2: Next probe uses inline comments to route around keyword filter
        next_probe = orchestrator.synthesize_next_probe("UNION SELECT 1, 2", decision1)
        self.assertIn("/**/", next_probe)

        # Step 3: Second probe bypasses WAF and elicits reflection
        decision2 = orchestrator.process_response(
            probe=next_probe,
            status_code=200,
            body="<html>Results: 1, 2</html>",
            latency_ms=15.0,
        )
        self.assertEqual(decision2.action, "confirm_finding")
        self.assertTrue(decision2.success)

    def test_waf_probe_and_adapt_learner(self):
        """O4.2: Sends benign canary tokens to learn exact blocked characters and keywords."""
        learner = WAFProbeLearner()

        # Mock target evaluation: blocks 'SELECT' and '<script>' but allows comments and hex
        def mock_target(probe_text: str) -> int:
            if "SELECT" in probe_text or "<script>" in probe_text:
                return 403
            return 200

        filter_rules = learner.learn_waf_profile(mock_target)
        self.assertTrue(filter_rules["blocks_select"])
        self.assertTrue(filter_rules["blocks_script_tag"])
        self.assertFalse(filter_rules["blocks_inline_comments"])

        # Generate recommended bypass encoding
        bypass_strategy = learner.recommend_bypass_strategy(filter_rules)
        self.assertEqual(bypass_strategy, "inline_comment_fragmentation_with_hex")

    def test_dynamic_oracle_auto_selection(self):
        """O4.3: Automatically picks the optimal oracle based on observed target signals."""
        selector = DynamicOracleSelector()

        # Signal 1: Delay matches injected sleep
        oracle_time = selector.select_oracle(
            baseline_latency_ms=20.0,
            probe_latency_ms=5035.0,
            baseline_body="Standard page",
            probe_body="Standard page",
            error_strings=[],
        )
        self.assertEqual(oracle_time, "time_delay_oracle")

        # Signal 2: Content length differential on True vs False
        oracle_diff = selector.select_oracle(
            baseline_latency_ms=20.0,
            probe_latency_ms=21.0,
            baseline_body="<html>Welcome Alice</html>",
            probe_body="<html>Login Failed</html>",
            error_strings=[],
        )
        self.assertEqual(oracle_diff, "boolean_differential_oracle")

        # Signal 3: SQL error string reflected in body
        oracle_err = selector.select_oracle(
            baseline_latency_ms=20.0,
            probe_latency_ms=22.0,
            baseline_body="Normal",
            probe_body="You have an error in your SQL syntax near 'UNION' at line 1",
            error_strings=["syntax error", "near '"],
        )
        self.assertEqual(oracle_err, "error_based_oracle")


if __name__ == "__main__":
    unittest.main()
