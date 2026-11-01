"""Entity graph builder using NetworkX with typed nodes, step order, and predicted reach edges."""

from __future__ import annotations

import ipaddress
from typing import Any

import networkx as nx

from app.store import duck


def classify_entity_node(node_id: str, default_kind: str, critical_assets: set[str] | None = None) -> str:
    """Classify a node into: external_ip, internal_host, user, critical_asset, technique."""
    if default_kind == "technique":
        return "technique"
    if default_kind == "user":
        return "user"
    if critical_assets and node_id in critical_assets:
        return "critical_asset"

    # Check IPv4/IPv6
    try:
        ip_obj = ipaddress.ip_address(node_id)
        if ip_obj.is_private or ip_obj.is_loopback:
            return "internal_host"
        return "external_ip"
    except ValueError:
        pass

    if default_kind in ("host", "unknown", "ip"):
        return "internal_host"
    return default_kind


def build_entity_graph(
    detections: list[dict],
    bulk_entities: dict[str, dict] | None = None,
    steps: list[dict] | None = None,
    reach_data: dict | None = None,
) -> nx.DiGraph:
    """Construct a directed graph from detection rows, steps, and lateral reach.

    Nodes: external_ip, internal_host, user, technique, critical_asset
    Edges:
      - host -> technique (with step_order, kill_chain_stage, first_seen, last_seen, evidence_event_ids)
      - user -> technique (performed)
      - ip -> host (connected_to)
      - host -> reachable_target (predicted=True, reason, priority)
    """
    G: nx.DiGraph = nx.DiGraph()
    crit_assets: set[str] = set()

    if reach_data:
        blast = reach_data.get("blast_radius", {})
        crit_assets.update(blast.get("critical_assets_reached", []))

    # Index step info by (technique_id, host)
    step_info_map: dict[tuple[str, str], dict[str, Any]] = {}
    if steps:
        for s in steps:
            t_id = s.get("technique_id", "")
            for h in s.get("hosts", []):
                step_info_map[(t_id, h)] = s
            if not s.get("hosts"):
                step_info_map[(t_id, "")] = s

    for det in detections:
        tech_id = det["technique_id"]
        host = det["host"]
        tactic = det.get("tactic", "")
        ts = str(det.get("ts", ""))
        d_id = det.get("detection_id", "")

        # Look up step info
        s_info = step_info_map.get((tech_id, host)) or step_info_map.get((tech_id, "")) or {}
        step_order = int(s_info.get("step_order", 1))
        stage = str(s_info.get("kill_chain_stage") or det.get("kill_chain_stage") or tactic)
        f_seen = str(s_info.get("first_seen") or ts)
        l_seen = str(s_info.get("last_seen") or ts)
        eids = list(s_info.get("evidence_event_ids", []))[:8]

        # Typed nodes
        host_kind = classify_entity_node(host, "host", crit_assets)
        G.add_node(host, kind=host_kind, label=host, type=host_kind)
        G.add_node(
            tech_id,
            kind="technique",
            label=tech_id,
            tactic=tactic,
            stage=stage,
            type="technique",
            step_order=step_order,
        )

        # host -> technique edge
        if G.has_edge(host, tech_id):
            G[host][tech_id]["count"] = G[host][tech_id].get("count", 1) + 1
        else:
            G.add_edge(
                host,
                tech_id,
                label="executed",
                ts=ts,
                count=1,
                detection_id=d_id,
                step_order=step_order,
                technique_id=tech_id,
                kill_chain_stage=stage,
                first_seen=f_seen,
                last_seen=l_seen,
                evidence_event_ids=eids,
                predicted=False,
            )

        if bulk_entities is not None and d_id in bulk_entities:
            info = bulk_entities[d_id]
            for user in info.get("users", []):
                G.add_node(user, kind="user", label=user, type="user")
                G.add_edge(user, tech_id, label="performed", predicted=False)
            for src_ip in info.get("src_ips", []):
                ip_kind = classify_entity_node(src_ip, "ip", crit_assets)
                G.add_node(src_ip, kind=ip_kind, label=src_ip, type=ip_kind)
                G.add_edge(src_ip, host, label="connected_to", predicted=False)
        elif bulk_entities is None:
            try:
                _, events = duck.list_events(detection_id=d_id, limit=20)
                for ev in events:
                    user = ev.get("user_name")
                    src_ip = ev.get("src_ip")
                    if user:
                        G.add_node(user, kind="user", label=user, type="user")
                        G.add_edge(user, tech_id, label="performed", predicted=False)
                    if src_ip:
                        ip_kind = classify_entity_node(src_ip, "ip", crit_assets)
                        G.add_node(src_ip, kind=ip_kind, label=src_ip, type=ip_kind)
                        G.add_edge(src_ip, host, label="connected_to", predicted=False)
            except Exception:
                pass

    # Add predicted reach edges if reach data available
    if reach_data:
        seed_hosts = reach_data.get("compromised_nodes", [])
        primary_seed = seed_hosts[0] if seed_hosts else (list(G.nodes)[0] if G.nodes else None)
        targets = reach_data.get("reachable_targets", [])[:15]
        for t in targets:
            tgt_id = str(t.get("target_label", t.get("target_id", "")))
            if not tgt_id or not primary_seed:
                continue
            tgt_kind = classify_entity_node(tgt_id, "host", crit_assets)
            G.add_node(tgt_id, kind=tgt_kind, label=tgt_id, type=tgt_kind)
            if primary_seed not in G:
                seed_kind = classify_entity_node(primary_seed, "host", crit_assets)
                G.add_node(primary_seed, kind=seed_kind, label=primary_seed, type=seed_kind)
            G.add_edge(
                primary_seed,
                tgt_id,
                label="predicted_reach",
                predicted=True,
                reason=str(t.get("reason", "observed network vector")),
                priority=str(t.get("priority", "medium")),
                hops=int(t.get("hops", 1)),
                evidence_event_ids=list(t.get("evidence_event_ids", []))[:4],
            )

    return G


def graph_to_cytoscape(G: nx.DiGraph, incident_id: str) -> dict[str, Any]:
    """Serialise the NetworkX graph to Cytoscape.js format with Dagre LR positioning metadata."""
    nodes = []
    for n in G.nodes:
        node_attrs = dict(G.nodes[n])
        node_id = str(n)
        kind = node_attrs.get("kind", "internal_host")
        label = node_attrs.get("label", node_id)
        step_order = node_attrs.get("step_order", 0)

        # Explicit fallback coordinates for horizontal left-to-right progression
        data_payload = {
            "id": node_id,
            "label": label,
            "kind": kind,
            "type": kind,
            "step_order": step_order,
        }
        for ak, av in node_attrs.items():
            if ak not in ("id", "label", "kind", "type", "step_order"):
                data_payload[ak] = av

        nodes.append({
            "id": node_id,
            "label": label,
            "kind": kind,
            "data": data_payload,
        })

    edges = []
    for u, v in G.edges:
        source_node = str(u)
        target_node = str(v)
        edge_attrs = dict(G[u][v])
        edge_id = f"e_{source_node}_{target_node}"
        label = edge_attrs.get("label", "")
        predicted = bool(edge_attrs.get("predicted", False))

        data_payload = {
            "id": edge_id,
            "source": source_node,
            "target": target_node,
            "label": label,
            "predicted": predicted,
            "step_order": edge_attrs.get("step_order", 0),
            "technique_id": edge_attrs.get("technique_id", ""),
            "kill_chain_stage": edge_attrs.get("kill_chain_stage", ""),
            "first_seen": edge_attrs.get("first_seen", ""),
            "last_seen": edge_attrs.get("last_seen", ""),
            "evidence_event_ids": edge_attrs.get("evidence_event_ids", []),
            "reason": edge_attrs.get("reason", ""),
            "priority": edge_attrs.get("priority", "medium"),
        }
        for ak, av in edge_attrs.items():
            if ak not in data_payload:
                data_payload[ak] = av

        edges.append({
            "id": edge_id,
            "source": source_node,
            "target": target_node,
            "label": label,
            "data": data_payload,
        })

    return {"incident_id": incident_id, "nodes": nodes, "edges": edges}
