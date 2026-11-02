"""Unit and integration test suite for Sector 5: Graph Min-Cut & Dominator Trees."""

from __future__ import annotations

from services.ai_analysis_worker.graph import (
    AttackGraphAnalyzer,
    EdmondsKarpMinCut,
)
from services.ai_analysis_worker.reasoning import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    BreakpointAnalyzer,
    synthesize_threat_model,
)


def test_edmonds_karp_classic_network():
    """Verify Edmonds-Karp on a textbook flow network."""
    solver = EdmondsKarpMinCut()
    solver.add_edge("s", "u", 10.0)
    solver.add_edge("s", "v", 5.0)
    solver.add_edge("u", "v", 15.0)
    solver.add_edge("u", "t", 10.0)
    solver.add_edge("v", "t", 10.0)

    result = solver.compute_min_cut("s", "t")
    assert result.max_flow == 15.0
    assert result.is_disconnected is True
    assert ("u", "t") in result.cut_edges or ("s", "u") in result.cut_edges


def test_attack_graph_node_min_cut_and_disconnection():
    """Verify that node-split reduction finds the minimal remediation cut and proves disconnection."""
    analyzer = AttackGraphAnalyzer()

    analyzer.add_node("entry:web", "Public Web Ingress", "ingress", remediation_cost=100.0)
    analyzer.add_node("vuln:sqli", "SQL Injection on /search", "vulnerability", remediation_cost=2.0)
    analyzer.add_node("vuln:ssrf", "SSRF on /webhook", "vulnerability", remediation_cost=2.0)
    analyzer.add_node("chokepoint:api_gateway", "Internal API Gateway Auth", "service", remediation_cost=0.5)
    analyzer.add_node("crown:database", "Customer Database", "crown_jewel", remediation_cost=100.0)

    analyzer.add_edge("entry:web", "vuln:sqli")
    analyzer.add_edge("entry:web", "vuln:ssrf")
    analyzer.add_edge("vuln:sqli", "chokepoint:api_gateway")
    analyzer.add_edge("vuln:ssrf", "chokepoint:api_gateway")
    analyzer.add_edge("chokepoint:api_gateway", "crown:database")

    sources = ["entry:web"]
    crown_jewels = ["crown:database"]

    cut_info = analyzer.find_node_min_cut(sources, crown_jewels)

    assert cut_info["remediation_min_cut_cost"] == 0.5
    assert cut_info["breakpoint_nodes"] == ["chokepoint:api_gateway"]
    assert cut_info["verified_disconnected"] is True


def test_attack_graph_multi_cut_disconnection():
    """Verify independent parallel paths without a single chokepoint."""
    analyzer = AttackGraphAnalyzer()

    analyzer.add_node("entry", "Ingress", "ingress")
    analyzer.add_node("vuln_a", "Path A Vuln", "vulnerability", remediation_cost=1.0)
    analyzer.add_node("vuln_b", "Path B Vuln", "vulnerability", remediation_cost=1.0)
    analyzer.add_node("sink", "Target Server", "crown_jewel")

    analyzer.add_edge("entry", "vuln_a")
    analyzer.add_edge("vuln_a", "sink")
    analyzer.add_edge("entry", "vuln_b")
    analyzer.add_edge("vuln_b", "sink")

    cut_info = analyzer.find_node_min_cut(["entry"], ["sink"])
    assert cut_info["remediation_min_cut_cost"] == 2.0
    assert set(cut_info["breakpoint_nodes"]) == {"vuln_a", "vuln_b"}
    assert cut_info["verified_disconnected"] is True


def test_dominator_tree_computation():
    """Verify immediate dominators in an exploit DAG."""
    analyzer = AttackGraphAnalyzer()

    analyzer.add_node("r", "Root Ingress", "ingress")
    analyzer.add_node("a", "Node A", "step")
    analyzer.add_node("b", "Node B", "step")
    analyzer.add_node("c", "Chokepoint C", "chokepoint")
    analyzer.add_node("d", "Target D", "sink")

    analyzer.add_edge("r", "a")
    analyzer.add_edge("r", "b")
    analyzer.add_edge("a", "c")
    analyzer.add_edge("b", "c")
    analyzer.add_edge("c", "d")

    idom = analyzer.compute_dominator_tree("r")
    assert idom["r"] is None
    assert idom["a"] == "r"
    assert idom["b"] == "r"
    assert idom["c"] == "r"
    assert idom["d"] == "c"


def test_breakpoint_analyzer_integration():
    """Verify BreakpointAnalyzer computes min-cut over formal attack graph."""
    graph = AttackGraph()
    graph.add_node(AttackNode("root:web", "asset", "Web Host"))
    graph.add_node(AttackNode("vuln:rce", "vulnerability", "Log4j RCE", {"severity": "critical"}))
    graph.add_edge(AttackEdge("root:web", "vuln:rce", "vulnerable_to"))

    analyzer = BreakpointAnalyzer(graph)
    breakpoints = analyzer.find_high_leverage_breakpoints()
    assert len(breakpoints) >= 1
    assert breakpoints[0]["cut_node"] == "vuln:rce"
    assert breakpoints[0]["is_min_cut"] is True
    assert breakpoints[0]["verified_disconnected"] is True


def test_synthesize_threat_model_includes_grounding_and_mincut():
    """Verify synthesize_threat_model produces grounding verdict and min-cut breakpoints."""
    findings = [
        {
            "fingerprint": "fp-1",
            "title": "SQL Injection in Login",
            "category": "injection",
            "severity": "high",
            "affected_url": "https://target.local/login",
            "cwe_id": "CWE-89",
        }
    ]
    observations = [
        {"kind": "crawler_summary", "endpoints": ["/login", "/dashboard"]},
        {"kind": "open_port", "port": 443, "service": "https"},
    ]

    model = synthesize_threat_model("https://target.local", findings, observations)
    assert "grounding_verdict" in model
    assert model["grounding_verdict"]["is_grounded"] is True
    assert "provenance_manifest" in model
    assert model["provenance_manifest"]["status"] == "cryptographically_grounded"
    assert "breakpoints" in model
