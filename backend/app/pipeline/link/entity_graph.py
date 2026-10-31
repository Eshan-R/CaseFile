"""Entity graph builder using NetworkX.

Builds a multi-entity graph from all detections in one incident for
fast path and reach queries.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from app.store import duck


def build_entity_graph(detections: list[dict]) -> nx.DiGraph:
    """Construct a directed graph from a list of detection rows.

    Nodes: host, user, src_ip, technique
    Edges: host→technique, user→technique, src_ip→host
    """
    G: nx.DiGraph = nx.DiGraph()

    for det in detections:
        tech_id = det["technique_id"]
        host = det["host"]
        tactic = det.get("tactic", "")
        ts = str(det.get("ts", ""))

        # Load associated events to enrich node attributes
        _, events = duck.list_events(detection_id=det["detection_id"], limit=20)

        # Nodes
        G.add_node(host, kind="host", label=host)
        G.add_node(tech_id, kind="technique", label=tech_id, tactic=tactic)

        # host → technique edge
        if G.has_edge(host, tech_id):
            G[host][tech_id]["count"] = G[host][tech_id].get("count", 1) + 1
        else:
            G.add_edge(host, tech_id, label="executed", ts=ts, count=1,
                       detection_id=det["detection_id"])

        for ev in events:
            user = ev.get("user_name")
            src_ip = ev.get("src_ip")

            if user:
                G.add_node(user, kind="user", label=user)
                G.add_edge(user, tech_id, label="performed")

            if src_ip:
                G.add_node(src_ip, kind="ip", label=src_ip)
                G.add_edge(src_ip, host, label="connected_to")

    return G


def graph_to_cytoscape(G: nx.DiGraph, incident_id: str) -> dict[str, Any]:
    """Serialise the NetworkX graph to a Cytoscape.js-compatible dict."""
    nodes = [
        {
            "id": str(n),
            "label": G.nodes[n].get("label", str(n)),
            "kind": G.nodes[n].get("kind", "unknown"),
            "data": {k: v for k, v in G.nodes[n].items()
                     if k not in ("label", "kind")},
        }
        for n in G.nodes
    ]
    edges = [
        {
            "id": f"e_{u}_{v}",
            "source": str(u),
            "target": str(v),
            "label": G[u][v].get("label", ""),
            "data": {k: v for k, v in G[u][v].items() if k != "label"},
        }
        for u, v in G.edges
    ]
    return {"incident_id": incident_id, "nodes": nodes, "edges": edges}

