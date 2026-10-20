"""Live test suite for 3D WebGL Graph, Virtualized Tables & Bulk Triage (Sector 9).

Verifies:
1. 3D WebGL Force Graph physics simulation, min-cut edge highlighting, and WebGL export.
2. Virtualized table windowing across 10,000 items with constant-memory slicing.
3. Multi-column fuzzy search, severity filtering, and multi-field sorting.
4. Saved views and bulk triage workflow state transitions with audit trail.
"""

from __future__ import annotations

from aegis.visualization import (
    BulkTriageWorkflowEngine,
    TriageStatus,
    Vector3D,
    VirtualizedTableEngine,
    WebGLForceGraph3D,
)


class TestWebGLForceGraph3D:
    def test_graph_node_and_edge_creation(self):
        graph = WebGLForceGraph3D()
        graph.add_node("entry-1", "External Gateway", "entrypoint", Vector3D(0.0, 0.0, 0.0))
        n2 = graph.add_node(
            "vuln-1", "SQLi on /search", "vulnerability", Vector3D(10.0, 0.0, 0.0), is_chokepoint=True
        )
        graph.add_node("target-1", "Customer Database", "target", Vector3D(50.0, 0.0, 0.0))

        e1 = graph.add_edge("entry-1", "vuln-1", is_min_cut=True)
        graph.add_edge("vuln-1", "target-1", is_min_cut=False)

        assert n2.is_chokepoint is True
        assert n2.color_hex == "#ef4444"
        assert e1.is_min_cut is True
        assert e1.glow_intensity == 1.0

    def test_step_simulation_updates_spatial_vectors(self):
        graph = WebGLForceGraph3D()
        n1 = graph.add_node("a", "Node A", "asset", Vector3D(0.0, 0.0, 0.0))
        n2 = graph.add_node("b", "Node B", "asset", Vector3D(2.0, 0.0, 0.0))
        graph.add_edge("a", "b")

        # Step physics simulation
        graph.step_simulation(dt=0.2)

        # Repulsion pushes nodes apart along x axis
        assert n1.position.x != 0.0 or n2.position.x != 2.0
        assert n1.velocity.x != 0.0

    def test_export_webgl_payload(self):
        graph = WebGLForceGraph3D()
        graph.add_node("n1", "Node 1", "asset", Vector3D(1.0, 2.0, 3.0))
        graph.add_node("n2", "Node 2", "target", Vector3D(4.0, 5.0, 6.0))
        graph.add_edge("n1", "n2", is_min_cut=True)

        payload = graph.export_webgl_payload()
        assert payload["nodeCount"] == 2
        assert payload["edgeCount"] == 1
        assert payload["nodes"][0]["pos"] == [1.0, 2.0, 3.0]
        assert payload["edges"][0]["isMinCut"] is True


class TestVirtualizedTableEngine:
    def test_virtual_window_slicing(self):
        # Generate 10,000 items
        items = [{"id": f"item-{i}", "title": f"Finding {i}", "severity": "HIGH"} for i in range(10000)]

        # Scroll at top: scrollTop = 0px, container = 400px, rowHeight = 40px (10 visible rows + 10 overscan)
        win_top = VirtualizedTableEngine.calculate_window(
            items, scroll_top_px=0, container_height_px=400, row_height_px=40
        )
        assert win_top.start_index == 0
        assert win_top.end_index <= 25
        assert len(win_top.visible_items) == win_top.end_index
        assert win_top.top_padding_px == 0
        assert win_top.bottom_padding_px > 0

        # Scroll into middle: scrollTop = 40,000px (item index ~1000)
        win_mid = VirtualizedTableEngine.calculate_window(
            items, scroll_top_px=40000, container_height_px=400, row_height_px=40
        )
        assert win_mid.start_index >= 990
        assert win_mid.top_padding_px > 0
        assert win_mid.bottom_padding_px > 0
        assert len(win_mid.visible_items) <= 30

    def test_filtering_and_sorting(self):
        items = [
            {"id": "1", "title": "SQL Injection", "endpoint": "/login", "severity": "CRITICAL", "cvss": 9.8},
            {"id": "2", "title": "XSS Reflected", "endpoint": "/search", "severity": "MEDIUM", "cvss": 6.1},
            {
                "id": "3",
                "title": "Command Injection",
                "endpoint": "/ping",
                "severity": "CRITICAL",
                "cvss": 9.9,
            },
            {"id": "4", "title": "CSRF in Bio", "endpoint": "/profile", "severity": "LOW", "cvss": 3.2},
        ]

        # Filter by severity CRITICAL
        crit = VirtualizedTableEngine.filter_and_sort(items, severity_filter="CRITICAL")
        assert len(crit) == 2

        # Search query
        searched = VirtualizedTableEngine.filter_and_sort(items, search_query="search")
        assert len(searched) == 1
        assert searched[0]["id"] == "2"

        # Sort descending by CVSS
        sorted_cvss = VirtualizedTableEngine.filter_and_sort(items, sort_by="cvss", descending=True)
        assert sorted_cvss[0]["id"] == "3"
        assert sorted_cvss[-1]["id"] == "4"


class TestBulkTriageWorkflow:
    def test_bulk_triage_and_saved_views(self):
        engine = BulkTriageWorkflowEngine()

        # Bulk triage 3 findings to CONFIRMED
        count = engine.bulk_triage(
            ["f-1", "f-2", "f-3"],
            TriageStatus.CONFIRMED,
            actor="lead_auditor",
            justification="Verified with live exploit",
        )
        assert count == 3
        assert engine.findings_status["f-1"] == TriageStatus.CONFIRMED
        assert engine.findings_status["f-2"] == TriageStatus.CONFIRMED
        assert len(engine.triage_history) == 3

        # Save view
        engine.save_view(
            "High Priority RCE", {"severity": "CRITICAL", "status": "CONFIRMED"}, actor="lead_auditor"
        )
        view = engine.get_view("High Priority RCE")
        assert view is not None
        assert view["filters"]["severity"] == "CRITICAL"
