"""Mathematically Proven Max-Flow/Min-Cut & Dominator Tree Engine for Attack Graphs.

Sector 5: AI Reasoning Layer (Milestone P1.5).
Replaces heuristic breakpoint counting with:
1. Edmonds-Karp Residual Network Max-Flow / Min-Cut on node-split capacities.
2. Immediate Dominator Tree (Aho-Ullman / Lengauer-Tarjan style chokepoints).
3. Provable Disconnection Certificate (guaranteeing 0 reachable sink paths post-cut).
"""

from __future__ import annotations

import collections
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class FlowEdge:
    source: str
    target: str
    capacity: float
    flow: float = 0.0
    is_residual: bool = False
    original_edge: bool = True


@dataclass
class MinCutResult:
    max_flow: float
    cut_edges: List[Tuple[str, str]]
    cut_nodes: List[str]
    reachable_from_source: Set[str]
    sink_partition: Set[str]
    is_disconnected: bool
    summary: str


class EdmondsKarpMinCut:
    """Computes exact Maximum-Flow and Minimum-Cut over directed networks."""

    def __init__(self):
        # adj: u -> list of edge indices in self.edges
        self.adj: Dict[str, List[int]] = collections.defaultdict(list)
        self.edges: List[FlowEdge] = []
        self.nodes: Set[str] = set()

    def add_edge(self, u: str, v: str, capacity: float):
        self.nodes.add(u)
        self.nodes.add(v)
        # Forward edge
        idx_fwd = len(self.edges)
        self.edges.append(FlowEdge(u, v, capacity, flow=0.0, is_residual=False, original_edge=True))
        self.adj[u].append(idx_fwd)

        # Backward (residual) edge
        idx_rev = len(self.edges)
        self.edges.append(FlowEdge(v, u, 0.0, flow=0.0, is_residual=True, original_edge=False))
        self.adj[v].append(idx_rev)

    def _bfs_find_path(self, source: str, sink: str) -> Optional[List[int]]:
        parent_edge: Dict[str, int] = {}
        queue = collections.deque([source])
        visited = {source}

        while queue:
            curr = queue.popleft()
            if curr == sink:
                break
            for edge_idx in self.adj[curr]:
                edge = self.edges[edge_idx]
                residual_cap = edge.capacity - edge.flow
                if residual_cap > 1e-9 and edge.target not in visited:
                    visited.add(edge.target)
                    parent_edge[edge.target] = edge_idx
                    queue.append(edge.target)

        if sink not in parent_edge:
            return None

        # Reconstruct path of edge indices
        path = []
        curr = sink
        while curr != source:
            edge_idx = parent_edge[curr]
            path.append(edge_idx)
            curr = self.edges[edge_idx].source
        path.reverse()
        return path

    def compute_min_cut(self, source: str, sink: str) -> MinCutResult:
        """Runs Edmonds-Karp to compute maximum flow and extracts the minimum cut."""
        if source not in self.nodes or sink not in self.nodes:
            return MinCutResult(
                max_flow=0.0,
                cut_edges=[],
                cut_nodes=[],
                reachable_from_source=set(),
                sink_partition=set(),
                is_disconnected=True,
                summary="Source or sink not in network",
            )

        # 1. Maximize flow via augmenting paths
        total_flow = 0.0
        while True:
            path = self._bfs_find_path(source, sink)
            if not path:
                break

            # Find bottleneck capacity
            bottleneck = min(self.edges[idx].capacity - self.edges[idx].flow for idx in path)
            for idx in path:
                self.edges[idx].flow += bottleneck
                # Update backward edge
                rev_idx = idx ^ 1
                self.edges[rev_idx].flow -= bottleneck
            total_flow += bottleneck

        # 2. Find reachable set in residual graph
        reachable = set()
        queue = collections.deque([source])
        reachable.add(source)
        while queue:
            curr = queue.popleft()
            for edge_idx in self.adj[curr]:
                edge = self.edges[edge_idx]
                if edge.capacity - edge.flow > 1e-9 and edge.target not in reachable:
                    reachable.add(edge.target)
                    queue.append(edge.target)

        # 3. Identify cut edges (forward edges from S to T)
        cut_edges = []
        for edge in self.edges:
            if edge.original_edge and edge.source in reachable and edge.target not in reachable:
                cut_edges.append((edge.source, edge.target))

        sink_partition = self.nodes - reachable
        is_disconnected = sink not in reachable

        return MinCutResult(
            max_flow=round(total_flow, 4),
            cut_edges=cut_edges,
            cut_nodes=[],
            reachable_from_source=reachable,
            sink_partition=sink_partition,
            is_disconnected=is_disconnected,
            summary=f"Min-cut capacity {total_flow:.2f} isolates sink via {len(cut_edges)} edge cut(s).",
        )


class AttackGraphAnalyzer:
    """Analyzes Attack Graph DAGs using Min-Cut and Dominator Trees."""

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Tuple[str, str, float]] = []  # (src, tgt, capacity)

    def add_node(self, node_id: str, label: str, kind: str, remediation_cost: float = 1.0):
        self.nodes[node_id] = {
            "label": label,
            "kind": kind,
            "cost": max(0.1, float(remediation_cost)),
        }

    def add_edge(self, source_id: str, target_id: str, weight: float = 1.0):
        self.edges.append((source_id, target_id, max(0.1, float(weight))))

    def find_node_min_cut(
        self, sources: List[str], crown_jewels: List[str]
    ) -> Dict[str, Any]:
        """Node-split reduction: splits each intermediate node u into (u_in -> u_out)
        with capacity equal to remediation cost. An edge cut in the transformed graph
        directly yields the optimal set of node breakpoints to patch!
        """
        solver = EdmondsKarpMinCut()
        super_source = "__SUPER_SOURCE__"
        super_sink = "__SUPER_SINK__"

        # Connect super source to all ingress sources (infinite capacity)
        for s in sources:
            if s in self.nodes:
                solver.add_edge(super_source, f"{s}_in", capacity=float("inf"))

        # For each internal node, add internal split edge with node remediation cost
        for nid, info in self.nodes.items():
            cost = info["cost"]
            # Crown jewels and ingress entry points have inf capacity unless explicitly remediable
            if nid in crown_jewels or nid in sources:
                cost = float("inf")
            solver.add_edge(f"{nid}_in", f"{nid}_out", capacity=cost)

        # For each directed attack edge u -> v, add (u_out -> v_in) with inf capacity
        for src, tgt, _w in self.edges:
            solver.add_edge(f"{src}_out", f"{tgt}_in", capacity=float("inf"))

        # Connect all crown jewels to super sink (infinite capacity)
        for t in crown_jewels:
            if t in self.nodes:
                solver.add_edge(f"{t}_out", super_sink, capacity=float("inf"))

        cut_result = solver.compute_min_cut(super_source, super_sink)

        # Extract which node split edges were cut
        cut_nodes = []
        for u, v in cut_result.cut_edges:
            if u.endswith("_in") and v.endswith("_out"):
                orig_id = u[:-3]
                cut_nodes.append(orig_id)

        # Verification: prove that removing cut_nodes eliminates ALL paths from sources to crown jewels
        disconnected = self.verify_disconnection(sources, crown_jewels, cut_nodes)

        return {
            "remediation_min_cut_cost": cut_result.max_flow,
            "breakpoint_nodes": cut_nodes,
            "breakpoint_labels": [self.nodes[n]["label"] for n in cut_nodes if n in self.nodes],
            "verified_disconnected": disconnected,
            "crown_jewels": crown_jewels,
            "sources": sources,
        }

    def verify_disconnection(
        self, sources: List[str], crown_jewels: List[str], removed_nodes: List[str]
    ) -> bool:
        """Formal BFS reachability check to prove no paths remain from source to sink."""
        removed_set = set(removed_nodes)
        adj = collections.defaultdict(list)
        for s, t, _ in self.edges:
            if s not in removed_set and t not in removed_set:
                adj[s].append(t)

        queue = collections.deque([s for s in sources if s not in removed_set])
        visited = set(queue)

        jewel_set = set(crown_jewels)
        while queue:
            curr = queue.popleft()
            if curr in jewel_set:
                return False  # Path still exists!
            for neighbor in adj[curr]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        return True

    def compute_dominator_tree(self, root: str) -> Dict[str, Optional[str]]:
        """Computes immediate dominators (idom) for nodes reachable from root.
        
        A node d dominates n if every path from root to n must pass through d.
        Immediate dominator idom[n] is the unique strict dominator closest to n.
        """
        adj: Dict[str, List[str]] = collections.defaultdict(list)
        preds: Dict[str, List[str]] = collections.defaultdict(list)
        for s, t, _ in self.edges:
            adj[s].append(t)
            preds[t].append(s)

        # 1. Reachable nodes
        reachable = []
        visited = {root}
        queue = collections.deque([root])
        while queue:
            curr = queue.popleft()
            reachable.append(curr)
            for nxt in adj[curr]:
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)

        # 2. Iterative dominator algorithm
        dom: Dict[str, Set[str]] = {n: set(reachable) for n in reachable}
        dom[root] = {root}

        changed = True
        while changed:
            changed = False
            for n in reachable:
                if n == root:
                    continue
                pred_list = [p for p in preds[n] if p in dom]
                if not pred_list:
                    new_dom = {n}
                else:
                    new_dom = set.intersection(*(dom[p] for p in pred_list)) | {n}
                if new_dom != dom[n]:
                    dom[n] = new_dom
                    changed = True

        # 3. Extract immediate dominators
        idom: Dict[str, Optional[str]] = {root: None}
        for n in reachable:
            if n == root:
                continue
            strict_doms = dom[n] - {n}
            # The immediate dominator is dominated by all other strict dominators
            curr_idom = None
            for cand in strict_doms:
                if dom[cand] == strict_doms:
                    curr_idom = cand
                    break
            # Fallback to cand with max depth
            if curr_idom is None and strict_doms:
                curr_idom = max(strict_doms, key=lambda d: len(dom[d]))
            idom[n] = curr_idom

        return idom
