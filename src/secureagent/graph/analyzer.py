"""Graph analyzer for SecureAgent."""

import logging
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field

from .models import CapabilityGraph, Node, Edge, NodeType, EdgeType

logger = logging.getLogger(__name__)


@dataclass
class BlastRadiusResult:
    """Result of blast radius analysis."""

    affected_nodes: List[Node]
    affected_count: int
    impact_score: float
    critical_paths: List[List[str]]
    recommendations: List[str]


@dataclass
class RiskPath:
    """A path representing security risk."""

    nodes: List[str]
    risk_score: float
    risk_type: str
    description: str


@dataclass
class GraphMetrics:
    """Metrics about the capability graph."""

    total_nodes: int
    total_edges: int
    node_counts_by_type: Dict[str, int]
    average_degree: float
    max_degree: int
    connected_components: int
    high_risk_nodes: int
    critical_paths_count: int


class GraphAnalyzer:
    """Analyze capability graphs for security risks."""

    def __init__(self, graph: CapabilityGraph):
        """Initialize analyzer with graph."""
        self.graph = graph

    def calculate_node_risk(self, node_id: str) -> float:
        """Calculate risk score for a node based on graph structure."""
        node = self.graph.get_node(node_id)
        if not node:
            return 0.0

        risk_score = node.risk_score

        # Factor 1: Number of capabilities (outgoing edges)
        capabilities = len(self.graph.get_edges_from(node_id))
        risk_score += min(capabilities * 0.05, 0.3)

        # Factor 2: Data access
        data_nodes = [
            n
            for n in self.graph.get_neighbors(node_id)
            if n.type == NodeType.DATA_SOURCE
        ]
        if data_nodes:
            risk_score += 0.2

        # Factor 3: Lacks guardrails
        guardrails = [
            e
            for e in self.graph.get_edges_to(node_id)
            if e.type == EdgeType.PROTECTS
        ]
        if not guardrails and node.type == NodeType.AGENT:
            risk_score += 0.15

        # Factor 4: High-risk tools
        tools = [
            n for n in self.graph.get_neighbors(node_id) if n.type == NodeType.TOOL
        ]
        high_risk_tools = [
            t for t in tools if t.properties.get("risk_level", "low") == "high"
        ]
        risk_score += len(high_risk_tools) * 0.1

        return min(risk_score, 1.0)

    def analyze_blast_radius(self, node_id: str) -> BlastRadiusResult:
        """Analyze the blast radius if a node is compromised."""
        if node_id not in self.graph.nodes:
            return BlastRadiusResult(
                affected_nodes=[],
                affected_count=0,
                impact_score=0.0,
                critical_paths=[],
                recommendations=[],
            )

        # Find all reachable nodes
        affected_ids = self._find_reachable_nodes(node_id)
        affected_nodes = [self.graph.nodes[nid] for nid in affected_ids]

        # Calculate impact score
        impact_score = self._calculate_impact_score(affected_nodes)

        # Find critical paths (paths to high-value targets)
        critical_paths = self._find_critical_paths(node_id, affected_ids)

        # Generate recommendations
        recommendations = self._generate_blast_radius_recommendations(
            node_id, affected_nodes, critical_paths
        )

        return BlastRadiusResult(
            affected_nodes=affected_nodes,
            affected_count=len(affected_nodes),
            impact_score=impact_score,
            critical_paths=critical_paths,
            recommendations=recommendations,
        )

    def find_risk_paths(self) -> List[RiskPath]:
        """Find paths representing security risks."""
        risk_paths = []

        # Find paths from agents to data sources
        agents = self.graph.get_nodes_by_type(NodeType.AGENT)
        data_sources = self.graph.get_nodes_by_type(NodeType.DATA_SOURCE)

        for agent in agents:
            for data_source in data_sources:
                path = self.graph.get_path(agent.id, data_source.id)
                if path:
                    risk_score = self._calculate_path_risk(path)
                    if risk_score > 0.5:
                        risk_paths.append(
                            RiskPath(
                                nodes=path,
                                risk_score=risk_score,
                                risk_type="data_access",
                                description=f"Agent {agent.name} can access {data_source.name}",
                            )
                        )

        # Find paths with excessive permissions
        permissions = self.graph.get_nodes_by_type(NodeType.PERMISSION)
        for perm in permissions:
            if perm.properties.get("level") == "admin":
                predecessors = self.graph.get_predecessors(perm.id)
                for pred in predecessors:
                    risk_paths.append(
                        RiskPath(
                            nodes=[pred.id, perm.id],
                            risk_score=0.9,
                            risk_type="excessive_privilege",
                            description=f"{pred.name} has admin permissions",
                        )
                    )

        return sorted(risk_paths, key=lambda p: p.risk_score, reverse=True)

    def find_missing_guardrails(self) -> List[Tuple[Node, List[str]]]:
        """Find nodes that should have guardrails but don't."""
        unprotected = []

        agents = self.graph.get_nodes_by_type(NodeType.AGENT)
        for agent in agents:
            # Check for guardrails protecting this agent
            protecting_edges = [
                e for e in self.graph.get_edges_to(agent.id) if e.type == EdgeType.PROTECTS
            ]

            if not protecting_edges:
                # Determine what guardrails are needed
                needed = self._determine_needed_guardrails(agent)
                if needed:
                    unprotected.append((agent, needed))

        return unprotected

    def calculate_metrics(self) -> GraphMetrics:
        """Calculate graph metrics."""
        # Count nodes by type
        node_counts = {}
        for node in self.graph.nodes.values():
            type_name = node.type.value
            node_counts[type_name] = node_counts.get(type_name, 0) + 1

        # Calculate degrees
        degrees = []
        for node_id in self.graph.nodes:
            degree = len(self.graph.get_edges_from(node_id)) + len(
                self.graph.get_edges_to(node_id)
            )
            degrees.append(degree)

        # Count connected components
        visited: Set[str] = set()
        components = 0
        for node_id in self.graph.nodes:
            if node_id not in visited:
                component = self.graph.get_connected_component(node_id)
                visited.update(component)
                components += 1

        # Count high risk nodes
        high_risk = sum(
            1 for n in self.graph.nodes.values() if n.risk_score >= 0.7
        )

        return GraphMetrics(
            total_nodes=len(self.graph.nodes),
            total_edges=len(self.graph.edges),
            node_counts_by_type=node_counts,
            average_degree=sum(degrees) / len(degrees) if degrees else 0,
            max_degree=max(degrees) if degrees else 0,
            connected_components=components,
            high_risk_nodes=high_risk,
            critical_paths_count=len(self.find_risk_paths()),
        )

    def _find_reachable_nodes(self, start_id: str) -> Set[str]:
        """Find all nodes reachable from start node."""
        visited: Set[str] = set()
        stack = [start_id]

        while stack:
            current = stack.pop()
            if current not in visited:
                visited.add(current)
                for neighbor_id in self.graph._adjacency.get(current, []):
                    stack.append(neighbor_id)

        return visited

    def _calculate_impact_score(self, affected_nodes: List[Node]) -> float:
        """Calculate impact score based on affected nodes."""
        if not affected_nodes:
            return 0.0

        # Weight different node types
        type_weights = {
            NodeType.DATA_SOURCE: 1.0,
            NodeType.RESOURCE: 0.8,
            NodeType.MODEL: 0.7,
            NodeType.AGENT: 0.6,
            NodeType.TOOL: 0.4,
            NodeType.PERMISSION: 0.5,
        }

        total_weight = sum(
            type_weights.get(n.type, 0.3) * (1 + n.risk_score) for n in affected_nodes
        )

        # Normalize by number of total nodes
        normalized = total_weight / max(len(self.graph.nodes), 1)
        return min(normalized, 1.0)

    def _find_critical_paths(
        self, start_id: str, affected_ids: Set[str]
    ) -> List[List[str]]:
        """Find paths to critical nodes."""
        critical_paths = []

        # Find paths to data sources and high-risk nodes
        for node_id in affected_ids:
            node = self.graph.nodes.get(node_id)
            if node and (
                node.type == NodeType.DATA_SOURCE or node.risk_score >= 0.7
            ):
                path = self.graph.get_path(start_id, node_id)
                if path and len(path) > 1:
                    critical_paths.append(path)

        return critical_paths[:10]  # Limit to top 10

    def _calculate_path_risk(self, path: List[str]) -> float:
        """Calculate risk score for a path."""
        if not path:
            return 0.0

        risk = 0.0
        for node_id in path:
            node = self.graph.nodes.get(node_id)
            if node:
                risk += node.risk_score

        # Longer paths are slightly less risky
        risk = risk / len(path)

        # Check for guardrails along path
        has_guardrail = any(
            self.graph.nodes.get(nid).type == NodeType.GUARDRAIL for nid in path
        )
        if has_guardrail:
            risk *= 0.7

        return risk

    def _determine_needed_guardrails(self, agent: Node) -> List[str]:
        """Determine what guardrails an agent needs."""
        needed = []

        # Check capabilities
        tools = [
            n
            for n in self.graph.get_neighbors(agent.id)
            if n.type == NodeType.TOOL
        ]

        tool_names = [t.name.lower() for t in tools]

        if any("shell" in t or "exec" in t for t in tool_names):
            needed.append("Command execution guardrail")

        if any("file" in t or "write" in t for t in tool_names):
            needed.append("File system guardrail")

        if any("http" in t or "api" in t or "web" in t for t in tool_names):
            needed.append("Network access guardrail")

        if any("sql" in t or "database" in t for t in tool_names):
            needed.append("Database access guardrail")

        # Check data access
        data_access = [
            n
            for n in self.graph.get_neighbors(agent.id)
            if n.type == NodeType.DATA_SOURCE
        ]
        if data_access:
            needed.append("Data access guardrail")

        return needed

    def _generate_blast_radius_recommendations(
        self,
        source_id: str,
        affected_nodes: List[Node],
        critical_paths: List[List[str]],
    ) -> List[str]:
        """Generate recommendations to reduce blast radius."""
        recommendations = []

        source = self.graph.nodes.get(source_id)
        if not source:
            return recommendations

        # Recommend based on affected count
        if len(affected_nodes) > 10:
            recommendations.append(
                f"High blast radius: {len(affected_nodes)} nodes affected. "
                "Consider implementing network segmentation."
            )

        # Recommend based on critical paths
        data_paths = [
            p
            for p in critical_paths
            if any(
                self.graph.nodes.get(nid).type == NodeType.DATA_SOURCE
                for nid in p
            )
        ]
        if data_paths:
            recommendations.append(
                f"Found {len(data_paths)} paths to data sources. "
                "Implement additional access controls."
            )

        # Recommend guardrails
        missing_guardrails = self._determine_needed_guardrails(source)
        if missing_guardrails:
            recommendations.append(
                f"Missing guardrails: {', '.join(missing_guardrails)}"
            )

        return recommendations
