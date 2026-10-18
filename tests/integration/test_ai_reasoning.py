"""Tests for Phase 4 Adversarial Attack Graph Modeling & AI Reasoning Engine."""

import unittest
from typing import Any

from services.ai_analysis_worker import Provider
from services.ai_analysis_worker.reasoning import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    score_finding_adversarially,
    synthesize_adversarial_hypotheses,
)


class MockProvider(Provider):
    def __init__(self, name: str = "test_llm"):
        self.name = name
        self.calls: list[dict] = []

    def propose(self, prompt: dict) -> bytes:
        self.calls.append(prompt)
        return b'{"confidence": "high", "reasoning": "Confirmed reproducible."}'


class AIReasoningTests(unittest.TestCase):
    def test_attack_graph_construction_and_ingestion(self):
        graph = AttackGraph()

        observations: list[dict[str, Any]] = [
            {
                "kind": "recon_asset_inventory",
                "data": {"assets": [{"value": "127.0.0.1", "kind": "ip"}]},
            },
            {
                "kind": "network_service",
                "category": "network_inventory",
                "address": "127.0.0.1",
                "port": 8080,
                "service": "http",
            },
            {
                "kind": "crawler_summary",
                "endpoints": ["/api/v1/auth", "/api/v1/users"],
                "parameters": ["token", "user_id"],
            },
        ]

        findings = [
            {
                "fingerprint": "nuclei:cve-2024-1234",
                "title": "Spring Boot Actuator Exposure",
                "severity": "critical",
                "category": "rce",
                "affected_url": "http://127.0.0.1:8080/api/v1/auth",
            },
            {
                "fingerprint": "zap:10020",
                "title": "X-Frame-Options Header Missing",
                "severity": "medium",
                "category": "clickjacking",
                "affected_url": "http://127.0.0.1:8080/api/v1/users",
            },
        ]

        graph.ingest(observations, findings)
        graph_dict = graph.to_dict()

        self.assertGreaterEqual(graph_dict["nodes_count"], 4)
        self.assertGreaterEqual(graph_dict["edges_count"], 2)

        # Verify attack paths are discovered and sorted by severity
        paths = graph.find_attack_paths()
        self.assertTrue(len(paths) >= 1)
        # Critical finding should be top priority
        self.assertEqual(paths[0]["severity"], "critical")
        self.assertIn("Spring Boot Actuator", paths[0]["target_vulnerability"])

    def test_synthesize_adversarial_hypotheses(self):
        graph = AttackGraph()
        node_ep = AttackNode("endpoint:/login", "endpoint", "Endpoint /login")
        node_vuln = AttackNode(
            "finding:sqli",
            "vulnerability",
            "[HIGH] SQL Injection in Login",
            {"severity": "high", "category": "sql_injection"},
        )
        graph.add_node(node_ep)
        graph.add_node(node_vuln)
        graph.add_edge(AttackEdge("endpoint:/login", "finding:sqli", "vulnerable_to", 8.0))

        hypotheses = synthesize_adversarial_hypotheses(graph, "http://127.0.0.1:8080/login")
        self.assertEqual(len(hypotheses), 1)
        h = hypotheses[0]
        self.assertEqual(h["severity"], "high")
        self.assertTrue(h["proposed_validation"]["non_destructive"])
        self.assertEqual(h["status"], "proposed")

    def test_score_finding_adversarially_deterministic_and_with_provider(self):
        finding = {
            "title": "Missing Content-Security-Policy Header",
            "severity": "medium",
            "description": "The response did not include a Content-Security-Policy header.",
            "evidence": "HTTP 200 OK without CSP",
            "fingerprint": "csp_missing_123",
        }

        # Deterministic scoring
        res = score_finding_adversarially(finding)
        self.assertEqual(res["confidence"], "high")
        self.assertEqual(res["false_positive_risk"], "negligible")
        self.assertIn("absence of mandatory HTTP", res["explainability"])

        # With active AI provider
        provider = MockProvider("gemini-pro")
        res_ai = score_finding_adversarially(finding, provider=provider)
        self.assertEqual(len(provider.calls), 1)
        self.assertIn("finding_title", provider.calls[0])
        self.assertIn("AI Adversarial verification", res_ai["explainability"])


if __name__ == "__main__":
    unittest.main()
