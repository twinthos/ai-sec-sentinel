#!/usr/bin/env python3
"""Blast Radius Map — directed graph of agent security relationships.

Nodes: agents, tools, APIs, data stores, computers, credentials, MCP servers, destinations.
Edges: actual authorised capabilities (not guesses).
Calculates direct and transitive reachability.
"""

from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field


@dataclass
class Node:
    node_id: str
    node_type: str  # agent, tool, api, datastore, computer, credential, mcp, destination
    label: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    capability: str  # read, write, execute, delegate, etc.
    authorized: bool = True
    revoked: bool = False


class BlastRadiusMap:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._adjacency: Dict[str, List[Edge]] = {}
    
    def add_node(self, node: Node):
        self.nodes[node.node_id] = node
    
    def add_edge(self, edge: Edge):
        self.edges.append(edge)
        self._adjacency.setdefault(edge.source, []).append(edge)
    
    def revoke_edge(self, source: str, target: str, capability: str = None):
        """Revoke an edge (permission removed)."""
        for e in self.edges:
            if e.source == source and e.target == target:
                if capability is None or e.capability == capability:
                    e.revoked = True
                    e.authorized = False
    
    def get_reachable(self, start: str, include_revoked: bool = False) -> Set[str]:
        """Get all nodes reachable from start via authorised edges. Handles cycles."""
        visited = set()
        stack = [start]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for edge in self._adjacency.get(current, []):
                if edge.revoked and not include_revoked:
                    continue
                if not edge.authorized and not include_revoked:
                    continue
                if edge.target not in visited:
                    stack.append(edge.target)
        visited.discard(start)  # Don't include start node
        return visited
    
    def get_direct_reach(self, start: str) -> List[str]:
        """Get directly reachable nodes (one hop)."""
        result = []
        for edge in self._adjacency.get(start, []):
            if edge.authorized and not edge.revoked:
                result.append(edge.target)
        return result
    
    def get_reachability_path(self, start: str, target: str) -> Optional[List[str]]:
        """Find a path from start to target. Returns None if unreachable."""
        from collections import deque
        visited = {start}
        queue = deque([(start, [start])])
        while queue:
            current, path = queue.popleft()
            for edge in self._adjacency.get(current, []):
                if edge.revoked or not edge.authorized:
                    continue
                if edge.target == target:
                    return path + [edge.target]
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge.target]))
        return None
    
    def get_blast_radius_report(self, agent_id: str) -> dict:
        """Generate blast radius report for an agent."""
        reachable = self.get_reachable(agent_id)
        direct = self.get_direct_reach(agent_id)
        
        # Categorise by node type
        by_type = {}
        for nid in reachable:
            node = self.nodes.get(nid)
            if node:
                by_type.setdefault(node.node_type, []).append(nid)
        
        return {
            "agent": agent_id,
            "direct_reach": direct,
            "transitive_reach": sorted(reachable),
            "total_reachable": len(reachable),
            "by_type": by_type,
            "risk_factors": self._calculate_risk_factors(agent_id, reachable),
        }
    
    def _calculate_risk_factors(self, agent_id: str, reachable: Set[str]) -> List[str]:
        """Simple explainable risk factors. Not a scientific score."""
        factors = []
        types = [self.nodes.get(n, Node("", "")).node_type for n in reachable]
        if "credential" in types:
            factors.append("Agent can reach credentials")
        if "datastore" in types:
            factors.append("Agent can reach data stores")
        if "external" in types or "destination" in types:
            factors.append("Agent can reach external destinations")
        if len(reachable) > 10:
            factors.append(f"Large blast radius ({len(reachable)} resources)")
        if not factors:
            factors.append("Limited reachability")
        return factors
    
    def has_cycle(self) -> bool:
        """Detect if the graph has cycles."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {nid: WHITE for nid in self.nodes}
        
        def dfs(node):
            color[node] = GRAY
            for edge in self._adjacency.get(node, []):
                if edge.revoked or not edge.authorized:
                    continue
                if color.get(edge.target, WHITE) == GRAY:
                    return True
                if color.get(edge.target, WHITE) == WHITE:
                    if dfs(edge.target):
                        return True
            color[node] = BLACK
            return False
        
        for nid in self.nodes:
            if color[nid] == WHITE:
                if dfs(nid):
                    return True
        return False


def run_blast_radius_tests():
    print("=== Blast Radius Tests ===")
    
    brm = BlastRadiusMap()
    
    # Build graph
    brm.add_node(Node("agent1", "agent", "Agent 1"))
    brm.add_node(Node("tool1", "tool", "File Read"))
    brm.add_node(Node("db1", "datastore", "Customer DB"))
    brm.add_node(Node("cred1", "credential", "API Key"))
    brm.add_node(Node("ext1", "destination", "External API"))
    
    brm.add_edge(Edge("agent1", "tool1", "execute"))
    brm.add_edge(Edge("tool1", "db1", "read"))
    brm.add_edge(Edge("tool1", "cred1", "read"))
    brm.add_edge(Edge("db1", "ext1", "write"))
    
    # Test 1: Direct reach
    print("\n1. Direct reach:")
    direct = brm.get_direct_reach("agent1")
    assert "tool1" in direct
    print(f"   PASS: agent1 -> {direct}")
    
    # Test 2: Transitive reach
    print("\n2. Transitive reach:")
    reachable = brm.get_reachable("agent1")
    assert "db1" in reachable
    assert "cred1" in reachable
    assert "ext1" in reachable
    print(f"   PASS: reaches {sorted(reachable)}")
    
    # Test 3: Revoked permission
    print("\n3. Revoked permission:")
    brm.revoke_edge("tool1", "cred1", "read")
    reachable2 = brm.get_reachable("agent1")
    assert "cred1" not in reachable2
    assert "db1" in reachable2
    print(f"   PASS: cred1 no longer reachable after revoke")
    
    # Test 4: Cycle detection
    print("\n4. Cycle detection:")
    brm2 = BlastRadiusMap()
    for n in ["a", "b", "c"]:
        brm2.add_node(Node(n, "agent", n))
    brm2.add_edge(Edge("a", "b", "delegate"))
    brm2.add_edge(Edge("b", "c", "delegate"))
    brm2.add_edge(Edge("c", "a", "delegate"))
    assert brm2.has_cycle() == True
    print("   PASS: cycle detected")
    
    # Test 5: No cycle
    print("\n5. No cycle:")
    brm3 = BlastRadiusMap()
    for n in ["a", "b", "c"]:
        brm3.add_node(Node(n, "agent", n))
    brm3.add_edge(Edge("a", "b", "delegate"))
    brm3.add_edge(Edge("b", "c", "delegate"))
    assert brm3.has_cycle() == False
    print("   PASS: no false positive cycle")
    
    # Test 6: Path finding
    print("\n6. Path finding:")
    path = brm.get_reachability_path("agent1", "ext1")
    assert path is not None
    assert path[0] == "agent1" and path[-1] == "ext1"
    print(f"   PASS: path = {path}")
    
    # Test 7: Blast radius report
    print("\n7. Blast radius report:")
    report = brm.get_blast_radius_report("agent1")
    assert report["total_reachable"] > 0
    assert "risk_factors" in report
    print(f"   PASS: {report['total_reachable']} reachable, factors: {report['risk_factors']}")
    
    print("\n=== All blast radius tests passed ===")


if __name__ == "__main__":
    run_blast_radius_tests()
