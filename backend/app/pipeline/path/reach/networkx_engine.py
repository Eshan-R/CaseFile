"""NetworkX-based reach engine.

Analyses what hosts, users, and techniques an attacker could
pivot to from their current foothold.
"""

from __future__ import annotations

import json
from typing import Any

import networkx as nx

from app.store import duck


def _load_recommendations() -> dict[str, str]:
    """Load tactic → recommendation mapping from knowledge/recommendations.yaml."""
    import os

    import yaml

    path = "knowledge/recommendations.yaml"
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def compute_reach(incident_id: str) -> dict[str, Any]:
    """Compute what the attacker could reach next from this incident.

    Returns a ReachResponse-shaped dict (JSON-serialisable).
    """
    inc = duck.get_incident(incident_id)
    if not inc:
        return {"incident_id": incident_id, "seed_hosts": [], "reachable": []}

    # Load the pre-built entity graph
    graph_json = inc.get("graph_json")
    if not graph_json:
        return {"incident_id": incident_id, "seed_hosts": [], "reachable": []}

    graph_data = json.loads(graph_json)
    G: nx.DiGraph = nx.DiGraph()

    for n in graph_data.get("nodes", []):
        G.add_node(n["id"], **n)
    for e in graph_data.get("edges", []):
        G.add_edge(e["source"], e["target"], **e.get("data", {}), label=e.get("label", ""))

    hosts = json.loads(inc["hosts"]) if isinstance(inc["hosts"], str) else inc["hosts"]
    recs = _load_recommendations()

    reachable: list[dict] = []
    seen: set[str] = set()

    for host in hosts:
        if host not in G:
            continue
        for neighbour in nx.descendants(G, host):
            if neighbour in seen:
                continue
            seen.add(neighbour)
            node_data = G.nodes.get(neighbour, {})
            kind = node_data.get("kind", "unknown")
            tactic = node_data.get("tactic")
            reachable.append({
                "entity": neighbour,
                "entity_kind": kind,
                "technique_id": neighbour if kind == "technique" else None,
                "tactic": tactic,
                "recommendation": recs.get(tactic or "", None),
            })

    return {
        "incident_id": incident_id,
        "seed_hosts": hosts,
        "reachable": reachable,
    }

