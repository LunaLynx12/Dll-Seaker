"""
Graph Generator - Generate visual dependency graphs
"""

from typing import Dict, List, Any, Optional
from pathlib import Path


class GraphGenerator:
    """Generate visual dependency graphs"""
    
    def __init__(self):
        """Initialize graph generator"""
        pass
    
    def generate_dot(self, dependencies: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Generate Graphviz DOT format"""
        dot_lines = [
            'digraph Dependencies {',
            '  rankdir=LR;',
            '  nodesep=1.5;',  # Minimum space between nodes
            '  ranksep=2.0;',  # Minimum space between ranks
            '  node [shape=box, style=rounded, width=2, height=0.8, margin=0.3];',
            '  edge [minlen=2];',  # Minimum edge length
        ]
        
        # Add main DLL
        main_dll = dependencies.get('main_dll', 'DLL')
        dot_lines.append(f'  "{main_dll}" [color=blue, fontsize=14, fontname="Arial"];')
        
        # Add direct dependencies
        direct = dependencies.get('direct', [])
        for dep in direct:
            dot_lines.append(f'  "{main_dll}" -> "{dep}";')
            dot_lines.append(f'  "{dep}" [color=green, fontsize=12, fontname="Arial"];')
        
        # Add tree dependencies
        tree = dependencies.get('tree', {})
        for parent, child_data in tree.items():
            self._add_tree_to_dot(dot_lines, parent, child_data, main_dll)
        
        # Add missing dependencies
        missing = dependencies.get('missing', [])
        for dep in missing:
            dot_lines.append(f'  "{main_dll}" -> "{dep}";')
            dot_lines.append(f'  "{dep}" [color=red, style=dashed, fontsize=12, fontname="Arial"];')
        
        dot_lines.append('}')
        
        dot_content = '\n'.join(dot_lines)
        
        if output_path:
            Path(output_path).write_text(dot_content, encoding='utf-8')
        
        return dot_content
    
    def _add_tree_to_dot(self, dot_lines: List[str], parent: str, child_data: Dict[str, Any], main_dll: str):
        """Recursively add tree structure to DOT"""
        direct = child_data.get('direct', [])
        for dep in direct:
            dot_lines.append(f'  "{parent}" -> "{dep}";')
            dot_lines.append(f'  "{dep}" [color=orange, fontsize=12, fontname="Arial"];')
        
        tree = child_data.get('tree', {})
        for child_parent, grandchild_data in tree.items():
            self._add_tree_to_dot(dot_lines, child_parent, grandchild_data, main_dll)
    
    def generate_html_graph(self, dependencies: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Generate interactive HTML graph using D3.js"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>DLL Dependency Graph</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .node { cursor: pointer; }
        .link { stroke: #999; stroke-opacity: 0.6; stroke-width: 2px; }
        .node-label { 
            font-size: 11px; 
            font-weight: 500;
            pointer-events: none;
            text-anchor: start;
            dominant-baseline: middle;
        }
        .node circle { stroke-width: 2px; }
    </style>
</head>
<body>
    <h1>DLL Dependency Graph</h1>
    <svg id="graph" width="1200" height="800"></svg>
    <script>
        var data = """ + self._dependencies_to_json(dependencies) + """;
        
        var svg = d3.select("#graph"),
            width = +svg.attr("width"),
            height = +svg.attr("height");
        
        var simulation = d3.forceSimulation()
            .force("link", d3.forceLink().id(function(d) { return d.id; }).distance(150))
            .force("charge", d3.forceManyBody().strength(-500))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(function(d) { return 60; }));
        
        var link = svg.append("g")
            .selectAll("line")
            .data(data.links)
            .enter().append("line")
            .attr("class", "link")
            .attr("stroke-width", function(d) { return Math.sqrt(d.value); });
        
        var node = svg.append("g")
            .selectAll("circle")
            .data(data.nodes)
            .enter().append("circle")
            .attr("r", 12)
            .attr("fill", function(d) { return d.color; })
            .attr("stroke", "#fff")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        var label = svg.append("g")
            .selectAll("text")
            .data(data.nodes)
            .enter().append("text")
            .attr("class", "node-label")
            .text(function(d) { return d.id; })
            .attr("dx", 18)
            .attr("dy", 4);
        
        simulation.nodes(data.nodes).on("tick", ticked);
        simulation.force("link").links(data.links);
        
        function ticked() {
            link
                .attr("x1", function(d) { return d.source.x; })
                .attr("y1", function(d) { return d.source.y; })
                .attr("x2", function(d) { return d.target.x; })
                .attr("y2", function(d) { return d.target.y; });
            
            node
                .attr("cx", function(d) { return d.x; })
                .attr("cy", function(d) { return d.y; });
            
            label
                .attr("x", function(d) { return d.x + 18; })
                .attr("y", function(d) { return d.y + 4; });
        }
        
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        
        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
    </script>
</body>
</html>"""
        
        if output_path:
            Path(output_path).write_text(html, encoding='utf-8')
        
        return html
    
    def _dependencies_to_json(self, dependencies: Dict[str, Any]) -> str:
        """Convert dependencies to JSON for D3.js"""
        import json
        
        nodes = []
        links = []
        
        main_dll = dependencies.get('main_dll', 'DLL')
        nodes.append({'id': main_dll, 'color': '#1f77b4'})
        
        direct = dependencies.get('direct', [])
        for dep in direct:
            nodes.append({'id': dep, 'color': '#2ca02c'})
            links.append({'source': main_dll, 'target': dep, 'value': 1})
        
        missing = dependencies.get('missing', [])
        for dep in missing:
            if dep not in [n['id'] for n in nodes]:
                nodes.append({'id': dep, 'color': '#d62728'})
            links.append({'source': main_dll, 'target': dep, 'value': 1})
        
        tree = dependencies.get('tree', {})
        for parent, child_data in tree.items():
            child_direct = child_data.get('direct', [])
            for dep in child_direct:
                if dep not in [n['id'] for n in nodes]:
                    nodes.append({'id': dep, 'color': '#ff7f0e'})
                links.append({'source': parent, 'target': dep, 'value': 1})
        
        return json.dumps({'nodes': nodes, 'links': links}, indent=8)

