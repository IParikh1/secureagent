"""Graph visualizer for SecureAgent."""

import json
from typing import Optional, Dict, Any, List
from pathlib import Path

from .models import CapabilityGraph, Node, NodeType


class GraphVisualizer:
    """Visualize capability graphs."""

    NODE_COLORS = {
        NodeType.AGENT: "#3498db",
        NodeType.TOOL: "#e74c3c",
        NodeType.DATA_SOURCE: "#2ecc71",
        NodeType.MODEL: "#9b59b6",
        NodeType.RESOURCE: "#f39c12",
        NodeType.PERMISSION: "#1abc9c",
        NodeType.GUARDRAIL: "#27ae60",
        NodeType.FINDING: "#e67e22",
    }

    NODE_SHAPES = {
        NodeType.AGENT: "box",
        NodeType.TOOL: "diamond",
        NodeType.DATA_SOURCE: "cylinder",
        NodeType.MODEL: "ellipse",
        NodeType.RESOURCE: "hexagon",
        NodeType.PERMISSION: "parallelogram",
        NodeType.GUARDRAIL: "triangle",
        NodeType.FINDING: "star",
    }

    def __init__(self, graph: CapabilityGraph):
        """Initialize visualizer with graph."""
        self.graph = graph

    def to_d3_json(self) -> Dict[str, Any]:
        """Convert graph to D3.js compatible JSON."""
        nodes = []
        for node in self.graph.nodes.values():
            nodes.append(
                {
                    "id": node.id,
                    "name": node.name,
                    "type": node.type.value,
                    "color": self.NODE_COLORS.get(node.type, "#95a5a6"),
                    "risk_score": node.risk_score,
                    "properties": node.properties,
                }
            )

        links = []
        for edge in self.graph.edges:
            links.append(
                {
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "type": edge.type.value,
                    "weight": edge.weight,
                }
            )

        return {"nodes": nodes, "links": links}

    def to_cytoscape_json(self) -> Dict[str, Any]:
        """Convert graph to Cytoscape.js compatible JSON."""
        elements = []

        # Add nodes
        for node in self.graph.nodes.values():
            elements.append(
                {
                    "data": {
                        "id": node.id,
                        "label": node.name,
                        "type": node.type.value,
                        "risk_score": node.risk_score,
                    },
                    "classes": node.type.value,
                }
            )

        # Add edges
        for i, edge in enumerate(self.graph.edges):
            elements.append(
                {
                    "data": {
                        "id": f"edge_{i}",
                        "source": edge.source_id,
                        "target": edge.target_id,
                        "type": edge.type.value,
                    },
                    "classes": edge.type.value,
                }
            )

        return {"elements": elements}

    def to_mermaid(self) -> str:
        """Convert graph to Mermaid diagram syntax."""
        lines = ["graph TD"]

        # Define node shapes
        shape_map = {
            NodeType.AGENT: ("([", "])"),
            NodeType.TOOL: ("{", "}"),
            NodeType.DATA_SOURCE: ("[(", ")]"),
            NodeType.MODEL: ("((", "))"),
            NodeType.RESOURCE: ("{{", "}}"),
            NodeType.PERMISSION: ("[/", "/]"),
            NodeType.GUARDRAIL: ("[\\", "\\]"),
            NodeType.FINDING: (">", "]"),
        }

        # Add nodes
        for node in self.graph.nodes.values():
            left, right = shape_map.get(node.type, ("[", "]"))
            safe_name = node.name.replace('"', "'")
            lines.append(f'    {node.id}{left}"{safe_name}"{right}')

        # Add edges
        edge_arrows = {
            "uses": "-->",
            "accesses": "-.->",
            "calls": "==>",
            "grants": "--o",
            "protects": "--x",
            "related_to": "---",
            "depends_on": "-->",
            "flows_to": "==>",
        }

        for edge in self.graph.edges:
            arrow = edge_arrows.get(edge.type.value, "-->")
            lines.append(f"    {edge.source_id} {arrow} {edge.target_id}")

        return "\n".join(lines)

    def to_dot(self) -> str:
        """Convert graph to Graphviz DOT format."""
        lines = ["digraph G {", '    rankdir=LR;', '    node [fontname="Arial"];']

        # Define node styles
        for node in self.graph.nodes.values():
            color = self.NODE_COLORS.get(node.type, "#95a5a6")
            shape = self.NODE_SHAPES.get(node.type, "box")
            safe_name = node.name.replace('"', '\\"')
            lines.append(
                f'    "{node.id}" [label="{safe_name}", '
                f'shape={shape}, style=filled, fillcolor="{color}"];'
            )

        # Add edges
        for edge in self.graph.edges:
            style = "solid"
            if edge.type.value in ["protects", "related_to"]:
                style = "dashed"
            lines.append(
                f'    "{edge.source_id}" -> "{edge.target_id}" '
                f'[label="{edge.type.value}", style={style}];'
            )

        lines.append("}")
        return "\n".join(lines)

    def to_html(self, title: str = "Capability Graph") -> str:
        """Generate standalone HTML visualization using vis.js."""
        graph_data = self.to_d3_json()

        # Convert to vis.js format
        vis_nodes = []
        for node in graph_data["nodes"]:
            vis_nodes.append(
                {
                    "id": node["id"],
                    "label": node["name"],
                    "color": node["color"],
                    "title": f"Type: {node['type']}<br>Risk: {node['risk_score']:.2f}",
                }
            )

        vis_edges = []
        for link in graph_data["links"]:
            vis_edges.append(
                {
                    "from": link["source"],
                    "to": link["target"],
                    "label": link["type"],
                    "arrows": "to",
                }
            )

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{ margin: 0; padding: 20px; font-family: Arial, sans-serif; }}
        #graph {{ width: 100%; height: 80vh; border: 1px solid #ddd; }}
        h1 {{ color: #333; }}
        .legend {{ display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }}
        .legend-item {{ display: flex; align-items: center; gap: 8px; }}
        .legend-color {{ width: 20px; height: 20px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div class="legend">
        <div class="legend-item"><div class="legend-color" style="background: #3498db"></div>Agent</div>
        <div class="legend-item"><div class="legend-color" style="background: #e74c3c"></div>Tool</div>
        <div class="legend-item"><div class="legend-color" style="background: #2ecc71"></div>Data Source</div>
        <div class="legend-item"><div class="legend-color" style="background: #9b59b6"></div>Model</div>
        <div class="legend-item"><div class="legend-color" style="background: #f39c12"></div>Resource</div>
        <div class="legend-item"><div class="legend-color" style="background: #1abc9c"></div>Permission</div>
        <div class="legend-item"><div class="legend-color" style="background: #27ae60"></div>Guardrail</div>
    </div>
    <div id="graph"></div>
    <script>
        var nodes = new vis.DataSet({json.dumps(vis_nodes)});
        var edges = new vis.DataSet({json.dumps(vis_edges)});
        var container = document.getElementById('graph');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
            physics: {{ stabilization: true }},
            interaction: {{ hover: true }},
            nodes: {{
                shape: 'box',
                font: {{ size: 14 }},
                borderWidth: 2
            }},
            edges: {{
                font: {{ size: 10, align: 'middle' }},
                smooth: {{ type: 'continuous' }}
            }}
        }};
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>"""

    def save(
        self,
        output_path: Path,
        format: str = "html",
    ) -> None:
        """Save visualization to file."""
        output_path = Path(output_path)

        if format == "html":
            content = self.to_html()
        elif format == "json":
            content = json.dumps(self.to_d3_json(), indent=2)
        elif format == "mermaid":
            content = self.to_mermaid()
        elif format == "dot":
            content = self.to_dot()
        else:
            raise ValueError(f"Unsupported format: {format}")

        output_path.write_text(content)

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the graph for display."""
        node_counts = {}
        for node in self.graph.nodes.values():
            type_name = node.type.value
            node_counts[type_name] = node_counts.get(type_name, 0) + 1

        high_risk_nodes = [
            n for n in self.graph.nodes.values() if n.risk_score >= 0.7
        ]

        return {
            "total_nodes": len(self.graph.nodes),
            "total_edges": len(self.graph.edges),
            "nodes_by_type": node_counts,
            "high_risk_count": len(high_risk_nodes),
            "high_risk_nodes": [
                {"id": n.id, "name": n.name, "risk_score": n.risk_score}
                for n in high_risk_nodes[:5]
            ],
        }
