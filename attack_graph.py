"""
Attack Graph Visualization

Generates an interactive HTML/SVG diagram showing exploit chains.
Nodes = findings, Edges = "led to" relationships (chaining).

Usage:
    from attack_graph import generate_attack_graph
    generate_attack_graph(findings, output="reports/attack_graph.html")

Requires: Python 3.12+
"""
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from typing import Any

from mcp_agent_v2 import Finding


def generate_attack_graph(findings: list[Finding], output: str = "reports/attack_graph.html") -> Path:
    """Generate an interactive attack graph as self-contained HTML."""
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    path = Path(output)

    # Build nodes and edges
    nodes = []
    edges = []
    node_ids: dict[str, int] = {}

    for i, f in enumerate(findings):
        node_id = f"n{i}"
        node_ids[f.title] = i
        color = {"critical": "#f85149", "high": "#f0883e", "medium": "#d29922", "low": "#58a6ff"}.get(f.severity, "#8b949e")
        nodes.append({
            "id": i,
            "label": f.title[:40],
            "severity": f.severity,
            "category": f.category,
            "details": f.details[:100],
            "color": color,
        })

        # Create edges from chaining
        if f.chained_from:
            # Find the source node
            for j, other in enumerate(findings):
                if other.title in f.chained_from or other.category in f.chained_from:
                    edges.append({"from": j, "to": i})
                    break

    # Auto-create edges based on category progression
    category_order = ["resource_enum", "tool_disclosure", "info_disclosure", "credential_leak", "env_leak", "ssrf_cloud", "cross_server_access", "chained_access"]
    prev_by_category: dict[str, int] = {}
    for i, f in enumerate(findings):
        if f.category in category_order:
            idx = category_order.index(f.category)
            # Link to previous category in chain
            for prev_cat in category_order[:idx]:
                if prev_cat in prev_by_category:
                    edge = {"from": prev_by_category[prev_cat], "to": i}
                    if edge not in edges:
                        edges.append(edge)
                    break
            prev_by_category[f.category] = i

    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Attack Graph</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui;background:#0f1117;color:#e1e4e8;overflow:hidden}}
#graph{{width:100vw;height:100vh}}
.tooltip{{position:absolute;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;font-size:0.8rem;max-width:300px;pointer-events:none;display:none;z-index:100}}
.tooltip .sev{{font-weight:700;text-transform:uppercase;margin-bottom:0.3rem}}
.legend{{position:fixed;bottom:1rem;left:1rem;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;font-size:0.75rem}}
.legend div{{display:flex;align-items:center;gap:0.5rem;margin:0.3rem 0}}
.legend .dot{{width:12px;height:12px;border-radius:50%}}
h1{{position:fixed;top:1rem;left:50%;transform:translateX(-50%);font-size:1.2rem;color:#58a6ff}}
</style>
</head>
<body>
<h1>Attack Graph — Exploit Chain Visualization</h1>
<canvas id="graph"></canvas>
<div class="tooltip" id="tooltip"></div>
<div class="legend">
<div><span class="dot" style="background:#f85149"></span> Critical</div>
<div><span class="dot" style="background:#f0883e"></span> High</div>
<div><span class="dot" style="background:#d29922"></span> Medium</div>
<div><span class="dot" style="background:#58a6ff"></span> Low</div>
</div>
<script>
const nodes = {nodes_json};
const edges = {edges_json};
const canvas = document.getElementById('graph');
const ctx = canvas.getContext('2d');
const tooltip = document.getElementById('tooltip');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

// Force-directed layout
const positions = nodes.map((_, i) => ({{
    x: canvas.width/2 + (Math.cos(i * 2.4) * (150 + i * 30)),
    y: canvas.height/2 + (Math.sin(i * 2.4) * (150 + i * 30)),
    vx: 0, vy: 0
}}));

function simulate() {{
    // Repulsion
    for(let i=0;i<nodes.length;i++) {{
        for(let j=i+1;j<nodes.length;j++) {{
            let dx=positions[i].x-positions[j].x, dy=positions[i].y-positions[j].y;
            let d=Math.sqrt(dx*dx+dy*dy)||1;
            let f=2000/(d*d);
            positions[i].vx+=dx/d*f; positions[i].vy+=dy/d*f;
            positions[j].vx-=dx/d*f; positions[j].vy-=dy/d*f;
        }}
    }}
    // Attraction (edges)
    for(let e of edges) {{
        let dx=positions[e.to].x-positions[e.from].x, dy=positions[e.to].y-positions[e.from].y;
        let d=Math.sqrt(dx*dx+dy*dy)||1;
        let f=(d-200)*0.01;
        positions[e.from].vx+=dx/d*f; positions[e.from].vy+=dy/d*f;
        positions[e.to].vx-=dx/d*f; positions[e.to].vy-=dy/d*f;
    }}
    // Center gravity
    for(let p of positions) {{
        p.vx+=(canvas.width/2-p.x)*0.001;
        p.vy+=(canvas.height/2-p.y)*0.001;
        p.x+=p.vx*0.3; p.y+=p.vy*0.3;
        p.vx*=0.9; p.vy*=0.9;
    }}
}}

function draw() {{
    ctx.clearRect(0,0,canvas.width,canvas.height);
    // Edges
    ctx.strokeStyle='#30363d'; ctx.lineWidth=2;
    for(let e of edges) {{
        let from=positions[e.from], to=positions[e.to];
        ctx.beginPath(); ctx.moveTo(from.x,from.y); ctx.lineTo(to.x,to.y); ctx.stroke();
        // Arrow
        let angle=Math.atan2(to.y-from.y,to.x-from.x);
        let ax=to.x-Math.cos(angle)*25, ay=to.y-Math.sin(angle)*25;
        ctx.beginPath(); ctx.moveTo(ax,ay);
        ctx.lineTo(ax-10*Math.cos(angle-0.4),ay-10*Math.sin(angle-0.4));
        ctx.lineTo(ax-10*Math.cos(angle+0.4),ay-10*Math.sin(angle+0.4));
        ctx.closePath(); ctx.fillStyle='#30363d'; ctx.fill();
    }}
    // Nodes
    for(let i=0;i<nodes.length;i++) {{
        let p=positions[i], n=nodes[i];
        let r = n.severity==='critical'?22:n.severity==='high'?18:14;
        ctx.beginPath(); ctx.arc(p.x,p.y,r,0,Math.PI*2);
        ctx.fillStyle=n.color+'40'; ctx.fill();
        ctx.strokeStyle=n.color; ctx.lineWidth=2; ctx.stroke();
        ctx.fillStyle='#e1e4e8'; ctx.font='11px system-ui'; ctx.textAlign='center';
        ctx.fillText(n.label,p.x,p.y+r+14);
    }}
}}

function animate() {{ simulate(); draw(); requestAnimationFrame(animate); }}
animate();

canvas.addEventListener('mousemove', e => {{
    let found=false;
    for(let i=0;i<nodes.length;i++) {{
        let dx=e.clientX-positions[i].x, dy=e.clientY-positions[i].y;
        if(Math.sqrt(dx*dx+dy*dy)<25) {{
            tooltip.style.display='block';
            tooltip.style.left=(e.clientX+15)+'px';
            tooltip.style.top=(e.clientY+15)+'px';
            tooltip.innerHTML=`<div class="sev" style="color:${{nodes[i].color}}">${{nodes[i].severity}}</div><b>${{nodes[i].label}}</b><br>${{nodes[i].category}}<br><small>${{nodes[i].details}}</small>`;
            found=true; break;
        }}
    }}
    if(!found) tooltip.style.display='none';
}});
</script>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    return path
