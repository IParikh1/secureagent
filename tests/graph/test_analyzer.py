"""Tests for graph analyzer."""

import pytest

from secureagent.graph.models import Node, Edge, NodeType, EdgeType, CapabilityGraph
from secureagent.graph.analyzer import GraphAnalyzer, BlastRadiusResult, RiskPath, GraphMetrics


class TestCapabilityGraph:
    """Tests for CapabilityGraph."""

    def test_graph_initialization(self):
        """Test graph initialization."""
        graph = CapabilityGraph()
        assert graph is not None
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_add_node(self):
        """Test adding nodes."""
        graph = CapabilityGraph()

        node = Node(
            id="agent-1",
            name="Test Agent",
            type=NodeType.AGENT,
        )
        graph.add_node(node)

        assert len(graph.nodes) == 1
        assert graph.get_node("agent-1") is not None

    def test_add_edge(self):
        """Test adding edges."""
        graph = CapabilityGraph()

        node1 = Node(id="agent-1", name="Agent", type=NodeType.AGENT)
        node2 = Node(id="tool-1", name="Tool", type=NodeType.TOOL)
        graph.add_node(node1)
        graph.add_node(node2)

        edge = Edge(
            source_id="agent-1",
            target_id="tool-1",
            type=EdgeType.USES,
        )
        graph.add_edge(edge)

        assert len(graph.edges) == 1

    def test_get_neighbors(self):
        """Test getting neighbor nodes."""
        graph = CapabilityGraph()

        agent = Node(id="agent-1", name="Agent", type=NodeType.AGENT)
        tool1 = Node(id="tool-1", name="Tool 1", type=NodeType.TOOL)
        tool2 = Node(id="tool-2", name="Tool 2", type=NodeType.TOOL)

        graph.add_node(agent)
        graph.add_node(tool1)
        graph.add_node(tool2)

        graph.add_edge(Edge(source_id="agent-1", target_id="tool-1", type=EdgeType.USES))
        graph.add_edge(Edge(source_id="agent-1", target_id="tool-2", type=EdgeType.USES))

        neighbors = graph.get_neighbors("agent-1")
        assert len(neighbors) == 2

    def test_remove_node(self):
        """Test removing nodes."""
        graph = CapabilityGraph()

        node = Node(id="agent-1", name="Agent", type=NodeType.AGENT)
        graph.add_node(node)
        graph.remove_node("agent-1")

        assert len(graph.nodes) == 0


class TestGraphAnalyzer:
    """Tests for GraphAnalyzer."""

    @pytest.fixture
    def sample_graph(self):
        """Create a sample graph for testing."""
        graph = CapabilityGraph()

        # Add nodes
        agent = Node(
            id="agent-1",
            name="AI Agent",
            type=NodeType.AGENT,
            risk_score=0.7,
        )
        tool_shell = Node(
            id="tool-shell",
            name="Shell Tool",
            type=NodeType.TOOL,
            risk_score=0.9,
        )
        tool_file = Node(
            id="tool-file",
            name="File Tool",
            type=NodeType.TOOL,
            risk_score=0.6,
        )
        resource_db = Node(
            id="resource-db",
            name="Database",
            type=NodeType.RESOURCE,
            risk_score=0.8,
        )

        graph.add_node(agent)
        graph.add_node(tool_shell)
        graph.add_node(tool_file)
        graph.add_node(resource_db)

        # Add edges
        graph.add_edge(Edge(source_id="agent-1", target_id="tool-shell", type=EdgeType.USES))
        graph.add_edge(Edge(source_id="agent-1", target_id="tool-file", type=EdgeType.USES))
        graph.add_edge(Edge(source_id="tool-file", target_id="resource-db", type=EdgeType.ACCESSES))

        return graph

    def test_analyzer_initialization(self, sample_graph):
        """Test analyzer initialization."""
        analyzer = GraphAnalyzer(sample_graph)
        assert analyzer is not None

    def test_analyze_blast_radius(self, sample_graph):
        """Test blast radius analysis."""
        analyzer = GraphAnalyzer(sample_graph)

        result = analyzer.analyze_blast_radius("agent-1")

        assert result is not None
        assert isinstance(result, BlastRadiusResult)
        assert hasattr(result, "affected_nodes")
        assert hasattr(result, "affected_count")
        assert hasattr(result, "impact_score")
        assert result.affected_count >= 0

    def test_analyze_blast_radius_unknown_node(self, sample_graph):
        """Test blast radius for unknown node."""
        analyzer = GraphAnalyzer(sample_graph)

        result = analyzer.analyze_blast_radius("unknown-node")

        assert result is not None
        assert result.affected_count == 0

    def test_find_risk_paths(self, sample_graph):
        """Test finding high-risk paths."""
        analyzer = GraphAnalyzer(sample_graph)

        paths = analyzer.find_risk_paths()

        assert paths is not None
        assert isinstance(paths, list)
        # All items should be RiskPath objects
        for path in paths:
            assert isinstance(path, RiskPath)
            assert hasattr(path, "nodes")
            assert hasattr(path, "risk_score")

    def test_calculate_node_risk(self, sample_graph):
        """Test node risk calculation."""
        analyzer = GraphAnalyzer(sample_graph)

        risk = analyzer.calculate_node_risk("agent-1")

        assert risk is not None
        assert 0.0 <= risk <= 1.0
        # Agent with tools should have elevated risk
        assert risk > 0.5

    def test_calculate_node_risk_unknown_node(self, sample_graph):
        """Test node risk for unknown node."""
        analyzer = GraphAnalyzer(sample_graph)

        risk = analyzer.calculate_node_risk("unknown-node")
        assert risk == 0.0

    def test_calculate_metrics(self, sample_graph):
        """Test graph metrics calculation."""
        analyzer = GraphAnalyzer(sample_graph)

        metrics = analyzer.calculate_metrics()

        assert metrics is not None
        assert isinstance(metrics, GraphMetrics)
        assert metrics.total_nodes == 4
        assert metrics.total_edges == 3
        assert metrics.average_degree > 0

    def test_find_missing_guardrails(self, sample_graph):
        """Test finding nodes missing guardrails."""
        analyzer = GraphAnalyzer(sample_graph)

        missing = analyzer.find_missing_guardrails()

        assert missing is not None
        assert isinstance(missing, list)
        # Each item should be (Node, List[str])
        for item in missing:
            assert isinstance(item, tuple)
            assert len(item) == 2


class TestBlastRadiusResult:
    """Tests for BlastRadiusResult dataclass."""

    def test_result_creation(self):
        """Test creating a BlastRadiusResult."""
        result = BlastRadiusResult(
            affected_nodes=[],
            affected_count=0,
            impact_score=0.0,
            critical_paths=[],
            recommendations=[],
        )
        assert result.affected_count == 0
        assert result.impact_score == 0.0


class TestRiskPath:
    """Tests for RiskPath dataclass."""

    def test_risk_path_creation(self):
        """Test creating a RiskPath."""
        path = RiskPath(
            nodes=["agent-1", "tool-1"],
            risk_score=0.8,
            risk_type="data_access",
            description="Test path",
        )
        assert path.risk_score == 0.8
        assert len(path.nodes) == 2


class TestGraphMetrics:
    """Tests for GraphMetrics dataclass."""

    def test_metrics_creation(self):
        """Test creating GraphMetrics."""
        metrics = GraphMetrics(
            total_nodes=10,
            total_edges=15,
            node_counts_by_type={"agent": 2, "tool": 5},
            average_degree=3.0,
            max_degree=5,
            connected_components=1,
            high_risk_nodes=3,
            critical_paths_count=2,
        )
        assert metrics.total_nodes == 10
        assert metrics.total_edges == 15
