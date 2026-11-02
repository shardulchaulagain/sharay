"""Acceptance tests for Formal AND/OR Attack Graph, Noisy Propagation, and Breakpoint Min-Cut (F1–F8)."""

import unittest

from services.ai_analysis_worker.reasoning import (
    ANDNode,
    AttackGraph,
    BreakpointAnalyzer,
    ColdReplayRunner,
    ORNode,
)


class FormalAttackGraphAcceptanceTests(unittest.TestCase):
    def test_and_or_semantics_and_noisy_confidence_propagation(self):
        graph = AttackGraph()

        # Precondition OR nodes
        c1 = ORNode(node_id="cond:network_reachability", label="Network Reachable", base_confidence=0.7)
        c2 = ORNode(node_id="cond:missing_auth", label="Missing Authentication", base_confidence=0.7)
        graph.add_formal_node(c1)
        graph.add_formal_node(c2)

        # Exploit AND node (requires BOTH network reachability AND missing auth)
        exploit = ANDNode(node_id="exploit:unauthenticated_exec", label="Unauthenticated Code Exec")
        graph.add_formal_node(exploit)

        graph.add_formal_edge("cond:network_reachability", "exploit:unauthenticated_exec")
        graph.add_formal_edge("cond:missing_auth", "exploit:unauthenticated_exec")

        # Resulting compromised condition OR node
        c_compromise = ORNode(node_id="cond:rce_achieved", label="RCE Achieved")
        graph.add_formal_node(c_compromise)
        graph.add_formal_edge("exploit:unauthenticated_exec", "cond:rce_achieved")

        # Evaluate graph confidence
        confidences = graph.evaluate_noisy_confidence()

        # Noisy-AND: 0.7 * 0.7 = 0.49
        exploit_conf = confidences["exploit:unauthenticated_exec"]
        self.assertAlmostEqual(exploit_conf, 0.49, places=2)

        # Compromise OR node: 1 - (1 - 0.49) = 0.49
        comp_conf = confidences["cond:rce_achieved"]
        self.assertAlmostEqual(comp_conf, 0.49, places=2)

    def test_noisy_or_confidence_combines_independent_paths(self):
        graph = AttackGraph()

        # Two independent exploit vectors reaching the same database compromise
        e1 = ANDNode(node_id="exploit:sqli", label="SQL Injection", base_confidence=0.5)
        e2 = ANDNode(node_id="exploit:leaked_creds", label="Leaked DB Creds", base_confidence=0.5)
        db_pwn = ORNode(node_id="cond:db_compromised", label="Database Compromised")

        graph.add_formal_node(e1)
        graph.add_formal_node(e2)
        graph.add_formal_node(db_pwn)

        graph.add_formal_edge("exploit:sqli", "cond:db_compromised")
        graph.add_formal_edge("exploit:leaked_creds", "cond:db_compromised")

        confidences = graph.evaluate_noisy_confidence()
        # Noisy-OR: 1 - (1 - 0.5) * (1 - 0.5) = 1 - 0.25 = 0.75
        self.assertAlmostEqual(confidences["cond:db_compromised"], 0.75, places=2)

    def test_breakpoint_min_cut_analysis_identifies_highest_leverage_remediation(self):
        graph = AttackGraph()

        # Root vulnerability: SSRF on instructions.php
        ssrf = ORNode(node_id="vuln:ssrf_instructions", label="SSRF on instructions.php", base_confidence=0.9)
        graph.add_formal_node(ssrf)

        # Three exploit paths all depending on that single SSRF
        # 1. SSRF -> Redis port 6379 -> RCE
        # 2. SSRF -> AWS IMDS 169.254.169.254 -> IAM credential exfil
        # 3. SSRF -> Internal Admin Panel -> Data Dump
        e1 = ANDNode(node_id="exploit:redis_write", label="SSRF to Redis Webshell", base_confidence=0.8)
        e2 = ANDNode(node_id="exploit:imds_exfil", label="SSRF to IMDS Credentials", base_confidence=0.8)
        e3 = ANDNode(node_id="exploit:internal_admin", label="SSRF to Internal Admin", base_confidence=0.8)

        target1 = ORNode(node_id="cond:rce", label="Root Shell")
        target2 = ORNode(node_id="cond:cloud_pwn", label="AWS Admin")
        target3 = ORNode(node_id="cond:data_leak", label="Internal Data Stolen")

        for n in [e1, e2, e3, target1, target2, target3]:
            graph.add_formal_node(n)

        graph.add_formal_edge("vuln:ssrf_instructions", "exploit:redis_write")
        graph.add_formal_edge("exploit:redis_write", "cond:rce")

        graph.add_formal_edge("vuln:ssrf_instructions", "exploit:imds_exfil")
        graph.add_formal_edge("exploit:imds_exfil", "cond:cloud_pwn")

        graph.add_formal_edge("vuln:ssrf_instructions", "exploit:internal_admin")
        graph.add_formal_edge("exploit:internal_admin", "cond:data_leak")

        analyzer = BreakpointAnalyzer(graph)
        breakpoint_report = analyzer.find_high_leverage_breakpoints()

        self.assertGreater(len(breakpoint_report), 0)
        top_cut = breakpoint_report[0]
        self.assertEqual(top_cut["cut_node"], "vuln:ssrf_instructions")
        self.assertEqual(top_cut["broken_paths_count"], 3)
        self.assertIn("Patch SSRF on instructions.php", top_cut["recommended_action"])

    def test_cold_replay_runner_sequential_chain_execution(self):
        runner = ColdReplayRunner()

        def step1_mock():
            return {"status": "success", "token": "ssrf_key_777"}

        def step2_mock(prev):
            return {"status": "success", "pwned": True, "token": prev.get("token")}

        chain = [
            {"name": "Probe SSRF endpoint", "executor": step1_mock},
            {"name": "Pivot to Redis using SSRF token", "executor": step2_mock},
        ]

        replay_result = runner.execute_chain(chain)

        self.assertTrue(replay_result["success"])
        self.assertEqual(len(replay_result["hops"]), 2)
        self.assertEqual(replay_result["hops"][0]["name"], "Probe SSRF endpoint")
        self.assertEqual(replay_result["hops"][1]["output"]["token"], "ssrf_key_777")


if __name__ == "__main__":
    unittest.main()
