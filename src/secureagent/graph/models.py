"""Graph data models for SecureAgent."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from enum import Enum


class NodeType(str, Enum):
    """Types of nodes in the capability graph."""

    AGENT = "agent"
    TOOL = "tool"
    DATA_SOURCE = "data_source"
    MODEL = "model"
    RESOURCE = "resource"
    PERMISSION = "permission"
    GUARDRAIL = "guardrail"
    FINDING = "finding"


class EdgeType(str, Enum):
    """Types of edges in the capability graph."""

    USES = "uses"
    ACCESSES = "accesses"
    CALLS = "calls"
    GRANTS = "grants"
    PROTECTS = "protects"
    RELATED_TO = "related_to"
    DEPENDS_ON = "depends_on"
    FLOWS_TO = "flows_to"


@dataclass
class Node:
    """Node in the capability graph."""

    id: str
    type: NodeType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, Node):
            return self.id == other.id
        return False


@dataclass
class Edge:
    """Edge in the capability graph."""

    source_id: str
    target_id: str
    type: EdgeType
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash((self.source_id, self.target_id, self.type))


class CapabilityGraph:
    """Graph representing agent capabilities and relationships."""

    def __init__(self):
        """Initialize empty graph."""
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._adjacency: Dict[str, List[str]] = {}
        self._reverse_adjacency: Dict[str, List[str]] = {}

    def add_node(self, node: Node) -> None:
        """Add a node to the graph."""
        self.nodes[node.id] = node
        if node.id not in self._adjacency:
            self._adjacency[node.id] = []
        if node.id not in self._reverse_adjacency:
            self._reverse_adjacency[node.id] = []

    def add_edge(self, edge: Edge) -> None:
        """Add an edge to the graph."""
        if edge.source_id not in self.nodes:
            raise ValueError(f"Source node {edge.source_id} not in graph")
        if edge.target_id not in self.nodes:
            raise ValueError(f"Target node {edge.target_id} not in graph")

        self.edges.append(edge)
        self._adjacency[edge.source_id].append(edge.target_id)
        self._reverse_adjacency[edge.target_id].append(edge.source_id)

    def get_node(self, node_id: str) -> Optional[Node]:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> List[Node]:
        """Get all nodes connected from this node."""
        neighbor_ids = self._adjacency.get(node_id, [])
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def get_predecessors(self, node_id: str) -> List[Node]:
        """Get all nodes connected to this node."""
        pred_ids = self._reverse_adjacency.get(node_id, [])
        return [self.nodes[pid] for pid in pred_ids if pid in self.nodes]

    def get_edges_from(self, node_id: str) -> List[Edge]:
        """Get all edges from a node."""
        return [e for e in self.edges if e.source_id == node_id]

    def get_edges_to(self, node_id: str) -> List[Edge]:
        """Get all edges to a node."""
        return [e for e in self.edges if e.target_id == node_id]

    def get_nodes_by_type(self, node_type: NodeType) -> List[Node]:
        """Get all nodes of a specific type."""
        return [n for n in self.nodes.values() if n.type == node_type]

    def get_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """Find shortest path between two nodes using BFS."""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        visited: Set[str] = set()
        queue: List[List[str]] = [[source_id]]

        while queue:
            path = queue.pop(0)
            node = path[-1]

            if node == target_id:
                return path

            if node not in visited:
                visited.add(node)
                for neighbor_id in self._adjacency.get(node, []):
                    new_path = path + [neighbor_id]
                    queue.append(new_path)

        return None

    def get_connected_component(self, node_id: str) -> Set[str]:
        """Get all nodes in the connected component containing this node."""
        if node_id not in self.nodes:
            return set()

        visited: Set[str] = set()
        stack = [node_id]

        while stack:
            current = stack.pop()
            if current not in visited:
                visited.add(current)
                # Add both directions
                stack.extend(self._adjacency.get(current, []))
                stack.extend(self._reverse_adjacency.get(current, []))

        return visited

    def get_subgraph(self, node_ids: Set[str]) -> "CapabilityGraph":
        """Extract a subgraph containing only specified nodes."""
        subgraph = CapabilityGraph()

        for node_id in node_ids:
            if node_id in self.nodes:
                subgraph.add_node(self.nodes[node_id])

        for edge in self.edges:
            if edge.source_id in node_ids and edge.target_id in node_ids:
                subgraph.add_edge(edge)

        return subgraph

    def remove_node(self, node_id: str) -> None:
        """Remove a node and all its edges."""
        if node_id in self.nodes:
            del self.nodes[node_id]
            self.edges = [
                e
                for e in self.edges
                if e.source_id != node_id and e.target_id != node_id
            ]
            if node_id in self._adjacency:
                del self._adjacency[node_id]
            if node_id in self._reverse_adjacency:
                del self._reverse_adjacency[node_id]

            # Clean up references
            for adj_list in self._adjacency.values():
                while node_id in adj_list:
                    adj_list.remove(node_id)
            for adj_list in self._reverse_adjacency.values():
                while node_id in adj_list:
                    adj_list.remove(node_id)

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type.value,
                    "name": n.name,
                    "properties": n.properties,
                    "risk_score": n.risk_score,
                    "metadata": n.metadata,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.type.value,
                    "weight": e.weight,
                    "properties": e.properties,
                }
                for e in self.edges
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityGraph":
        """Create graph from dictionary."""
        graph = cls()

        for node_data in data.get("nodes", []):
            node = Node(
                id=node_data["id"],
                type=NodeType(node_data["type"]),
                name=node_data["name"],
                properties=node_data.get("properties", {}),
                risk_score=node_data.get("risk_score", 0.0),
                metadata=node_data.get("metadata", {}),
            )
            graph.add_node(node)

        for edge_data in data.get("edges", []):
            edge = Edge(
                source_id=edge_data["source"],
                target_id=edge_data["target"],
                type=EdgeType(edge_data["type"]),
                weight=edge_data.get("weight", 1.0),
                properties=edge_data.get("properties", {}),
            )
            graph.add_edge(edge)

        return graph
