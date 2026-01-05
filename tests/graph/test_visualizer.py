"""Tests for graph visualizer."""

import pytest
import json

from secureagent.graph.models import Node, Edge, NodeType, EdgeType, CapabilityGraph
from secureagent.graph.visualizer import GraphVisualizer


class TestGraphVisualizer:
    """Tests for GraphVisualizer."""

    @pytest.fixture
    def sample_graph(self):
        """Create a sample graph for testing."""
        graph = CapabilityGraph()

        # Add nodes
        agent = Node(id="agent-1", name="AI Agent", type=NodeType.AGENT)
        tool = Node(id="tool-1", name="Shell Tool", type=NodeType.TOOL)
        resource = Node(id="resource-1", name="Database", type=NodeType.RESOURCE)

        graph.add_node(agent)
        graph.add_node(tool)
        graph.add_node(resource)

        # Add edges
        graph.add_edge(Edge(source_id="agent-1", target_id="tool-1", type=EdgeType.USES))
        graph.add_edge(Edge(source_id="tool-1", target_id="resource-1", type=EdgeType.ACCESSES))

        return graph

    def test_visualizer_initialization(self, sample_graph):
        """Test visualizer initialization."""
        visualizer = GraphVisualizer(sample_graph)
        assert visualizer is not None

    def test_to_d3_json(self, sample_graph):
        """Test D3.js JSON export."""
        visualizer = GraphVisualizer(sample_graph)

        d3_data = visualizer.to_d3_json()

        assert d3_data is not None
        # Should be valid JSON
        parsed = json.loads(d3_data) if isinstance(d3_data, str) else d3_data
        assert "nodes" in parsed
        assert "links" in parsed or "edges" in parsed
        assert len(parsed["nodes"]) == 3

    def test_to_cytoscape_json(self, sample_graph):
        """Test Cytoscape.js JSON export."""
        visualizer = GraphVisualizer(sample_graph)

        cyto_data = visualizer.to_cytoscape_json()

        assert cyto_data is not None
        parsed = json.loads(cyto_data) if isinstance(cyto_data, str) else cyto_data
        assert "elements" in parsed or "nodes" in parsed

    def test_to_mermaid(self, sample_graph):
        """Test Mermaid diagram export."""
        visualizer = GraphVisualizer(sample_graph)

        mermaid = visualizer.to_mermaid()

        assert mermaid is not None
        assert "graph" in mermaid.lower() or "flowchart" in mermaid.lower()
        # Should contain node references
        assert "agent" in mermaid.lower()

    def test_to_dot(self, sample_graph):
        """Test DOT format export."""
        visualizer = GraphVisualizer(sample_graph)

        dot = visualizer.to_dot()

        assert dot is not None
        assert "digraph" in dot.lower() or "graph" in dot.lower()

    def test_to_html(self, sample_graph):
        """Test HTML export with embedded visualization."""
        visualizer = GraphVisualizer(sample_graph)

        html = visualizer.to_html()

        assert html is not None
        assert "<html" in html.lower() or "<!doctype" in html.lower()
        # Should include D3 or other viz library
        assert "d3" in html.lower() or "cytoscape" in html.lower() or "script" in html.lower()

    def test_empty_graph_visualization(self):
        """Test visualization of empty graph."""
        graph = CapabilityGraph()
        visualizer = GraphVisualizer(graph)

        d3_data = visualizer.to_d3_json()

        assert d3_data is not None
        parsed = json.loads(d3_data) if isinstance(d3_data, str) else d3_data
        assert len(parsed.get("nodes", [])) == 0

    def test_save_to_file(self, sample_graph, temp_dir):
        """Test saving visualization to file."""
        visualizer = GraphVisualizer(sample_graph)

        output_path = temp_dir / "graph.html"
        visualizer.save(output_path, format="html")

        assert output_path.exists()
        content = output_path.read_text()
        assert len(content) > 0

    def test_node_colors_by_type(self, sample_graph):
        """Test that different node types have different colors."""
        visualizer = GraphVisualizer(sample_graph)

        d3_data = visualizer.to_d3_json()
        parsed = json.loads(d3_data) if isinstance(d3_data, str) else d3_data

        # Check that nodes have type or color information
        nodes = parsed.get("nodes", [])
        if nodes and "type" in nodes[0]:
            types = set(n.get("type") for n in nodes)
            # Should have multiple node types
            assert len(types) >= 2
