"""NetworkX-based reach engine.

Computes blast radius, reachable targets, and predictive attack paths
using directed graph analysis, edge probability weighting, and shortest simple paths.
"""

from __future__ import annotations

import logging
import math
import time
from datetime import UTC, datetime
from typing import Any

import networkx as nx

from app.pipeline.path.reach.assets import identify_critical_assets, load_asset_rules
from app.pipeline.path.reach.base import ReachEngine
from app.schemas.reach import (
    DEFAULT_DISCLAIMER,
    BlastRadius,
    NextReach,
    PredictedPath,
    ReachableTarget,
)

logger = logging.getLogger(__name__)


def _parse_ts(val: Any) -> datetime | None:
    """Parse string or datetime to UTC datetime."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val.astimezone(UTC) if val.tzinfo else val.replace(tzinfo=UTC)
    try:
        clean = str(val).replace("Z", "+00:00").strip()
        dt = datetime.fromisoformat(clean)
        return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    except Exception:
        return None


def _calculate_edge_prob(
    edge: dict[str, Any],
    incident_start: datetime | None,
    is_service_account: bool = False,
) -> tuple[float, str]:
    """Compute edge probability p and plain-English reason string.

    Formula:
      - p = 0.9 if admin, else min(0.8, 0.2 + 0.1 * log2(count + 1))
      - +0.05 if last_seen is within 7 days of incident start (cap at 0.95)
      - if broad service account: lowered probability and tagged reason.
    """
    src = str(edge.get("source", "unknown"))
    tgt = str(edge.get("target", "unknown"))
    count = int(edge.get("count", 1) or 1)
    is_admin = bool(edge.get("is_admin") or edge.get("kind") == "admin")
    kind = str(edge.get("kind", "logon")).lower()
    last_seen_dt = _parse_ts(edge.get("last_seen"))

    # 1. Base probability
    if is_admin:
        p = 0.9
        base_reason = f"{src} has admin logons on {tgt}"
    else:
        p = min(0.8, 0.2 + 0.1 * math.log2(count + 1))
        if kind == "connection":
            base_reason = f"{src} connected to {tgt} {count} {'times' if count != 1 else 'time'}"
        else:
            base_reason = f"{src} logged on to {tgt} {count} {'times' if count != 1 else 'time'}"

    # 2. Recency bonus: within 7 days of incident start
    if incident_start and last_seen_dt:
        days_diff = abs((incident_start - last_seen_dt).total_seconds()) / 86400.0
        if days_diff <= 7.0:
            p += 0.05

    # Cap at 0.95
    p = min(0.95, round(p, 4))

    # 3. Broad service account penalty
    if is_service_account:
        # Lower probability significantly and indicate broad service account
        p = min(0.25, round(p * 0.4, 4))
        base_reason = f"{src} (broad service account) access on {tgt}"

    return p, base_reason


class NetworkXEngine(ReachEngine):
    """NetworkX implementation of the ReachEngine."""

    name: str = "networkx"

    def compute(
        self,
        incident: dict[str, Any],
        access_edges: list[dict[str, Any]],
        config: dict[str, Any] | None = None,
    ) -> NextReach:
        """Compute NextReach from incident and access edges."""
        cfg = config or {}
        max_hops = int(cfg.get("max_hops", 4))
        sa_threshold = int(cfg.get("service_account_threshold", 10))
        time_budget_sec = float(cfg.get("time_budget_seconds", 2.0))
        max_candidates_per_target = int(cfg.get("max_candidates_per_target", 20))
        max_out_edges = int(cfg.get("max_out_edges", 200))

        incident_id = str(incident.get("incident_id", "inc_unknown"))
        inc_first_seen = _parse_ts(incident.get("first_seen"))

        # Extract compromised nodes (hosts + users)
        inc_hosts = incident.get("hosts", [])
        if isinstance(inc_hosts, str):
            import json
            try:
                inc_hosts = json.loads(inc_hosts)
            except Exception:
                inc_hosts = [inc_hosts]

        inc_users = incident.get("users", [])
        if isinstance(inc_users, str):
            import json
            try:
                inc_users = json.loads(inc_users)
            except Exception:
                inc_users = [inc_users]

        compromised_nodes = sorted(list({str(h).strip() for h in inc_hosts if h} | {str(u).strip() for u in inc_users if u}))

        # If no access edges or no compromised nodes, handle as isolated incident
        if not access_edges or not compromised_nodes:
            return NextReach(
                incident_id=incident_id,
                compromised_nodes=compromised_nodes,
                blast_radius=BlastRadius(hosts_count=0, users_count=0, total_nodes=0, critical_assets_reached=[]),
                predicted_paths=[],
                reachable_targets=[],
                engine=self.name,
                disclaimer=DEFAULT_DISCLAIMER,
                message="Isolated incident: no outgoing access edges found.",
            )

        # 1. Identify broad service accounts (users reaching > sa_threshold distinct hosts)
        user_hosts_map: dict[str, set[str]] = {}
        all_hosts_seen: set[str] = set(inc_hosts)
        all_users_seen: set[str] = set(inc_users)

        for e in access_edges:
            src = str(e.get("source", "")).strip()
            tgt = str(e.get("target", "")).strip()
            if not src or not tgt:
                continue
            src_kind = str(e.get("source_kind", "")).lower()
            if src_kind == "user" or e.get("is_admin") or e.get("kind") in ("logon", "admin"):
                user_hosts_map.setdefault(src, set()).add(tgt)
                all_users_seen.add(src)
                all_hosts_seen.add(tgt)
            else:
                all_hosts_seen.add(src)
                all_hosts_seen.add(tgt)

        service_accounts = {u for u, hsts in user_hosts_map.items() if len(hsts) > sa_threshold}

        # 2. Build Multi/Merged Directed Graph (Deduplicate edges, remove self-loops)
        merged_edges: dict[tuple[str, str], dict[str, Any]] = {}
        for e in access_edges:
            src = str(e.get("source", "")).strip()
            tgt = str(e.get("target", "")).strip()
            # Guard: missing names or self-loops
            if not src or not tgt or src == tgt:
                continue

            is_sa = src in service_accounts
            p, reason = _calculate_edge_prob(e, inc_first_seen, is_service_account=is_sa)
            key = (src, tgt)
            e_ev_ids = e.get("evidence_event_ids", []) or []

            if key not in merged_edges:
                merged_edges[key] = {
                    "source": src,
                    "target": tgt,
                    "prob": p,
                    "reason": reason,
                    "is_admin": bool(e.get("is_admin") or e.get("kind") == "admin"),
                    "count": int(e.get("count", 1) or 1),
                    "evidence_event_ids": list(e_ev_ids)[:3],
                }
            else:
                # Merge duplicate edge: keep highest probability, combine evidence
                existing = merged_edges[key]
                if p > existing["prob"]:
                    existing["prob"] = p
                    existing["reason"] = reason
                existing["count"] += int(e.get("count", 1) or 1)
                existing["is_admin"] = existing["is_admin"] or bool(e.get("is_admin") or e.get("kind") == "admin")
                combined_eids = list(dict.fromkeys(existing["evidence_event_ids"] + list(e_ev_ids)))
                existing["evidence_event_ids"] = combined_eids[:3]

        G: nx.DiGraph = nx.DiGraph()

        # Add nodes with metadata
        for h in all_hosts_seen:
            G.add_node(h, kind="host")
        for u in all_users_seen:
            if u not in G:
                G.add_node(u, kind="user")

        # High-degree node guard: group by source and expand only top 200 edges by weight
        edges_by_src: dict[str, list[dict[str, Any]]] = {}
        for ed in merged_edges.values():
            edges_by_src.setdefault(ed["source"], []).append(ed)

        for src, out_eds in edges_by_src.items():
            if len(out_eds) > max_out_edges:
                # Sort descending by probability then count
                out_eds.sort(key=lambda x: (x["prob"], x["count"]), reverse=True)
                out_eds = out_eds[:max_out_edges]
            for ed in out_eds:
                tgt = ed["target"]
                prob = max(0.01, min(0.95, ed["prob"]))
                cost = -math.log(prob)
                G.add_edge(
                    src,
                    tgt,
                    prob=prob,
                    weight=cost,
                    reason=ed["reason"],
                    evidence_event_ids=ed["evidence_event_ids"],
                    edge_id=f"{src}->{tgt}",
                )

        # 3. Identify critical assets
        asset_rules = load_asset_rules()
        critical_assets = identify_critical_assets(all_hosts_seen, access_edges, asset_rules)

        # 4. Blast Radius (Reachable within max_hops excluding compromised nodes)
        comp_set = set(compromised_nodes)
        reachable_dist: dict[str, int] = {}
        best_incoming_edge: dict[str, dict[str, Any]] = {}
        best_node_prob: dict[str, float] = {}

        # BFS from each compromised node
        for seed in compromised_nodes:
            if seed not in G:
                continue
            # Single-source shortest path lengths by hop
            lengths = nx.single_source_shortest_path_length(G, seed, cutoff=max_hops)
            for node, dist in lengths.items():
                if node in comp_set:
                    continue
                if node not in reachable_dist or dist < reachable_dist[node]:
                    reachable_dist[node] = dist

        # If nothing is reachable
        if not reachable_dist:
            return NextReach(
                incident_id=incident_id,
                compromised_nodes=compromised_nodes,
                blast_radius=BlastRadius(hosts_count=0, users_count=0, total_nodes=0, critical_assets_reached=[]),
                predicted_paths=[],
                reachable_targets=[],
                engine=self.name,
                disclaimer=DEFAULT_DISCLAIMER,
                message="Isolated incident: no outgoing access edges found.",
            )

        blast_hosts: list[str] = []
        blast_users: list[str] = []
        critical_reached: set[str] = set()

        for node, dist in reachable_dist.items():
            n_kind = G.nodes.get(node, {}).get("kind", "host" if node in all_hosts_seen else "user")
            if n_kind == "user":
                blast_users.append(node)
            else:
                blast_hosts.append(node)
                if node in critical_assets:
                    critical_reached.add(node)

        blast_radius = BlastRadius(
            hosts_count=len(blast_hosts),
            users_count=len(blast_users),
            total_nodes=len(blast_hosts) + len(blast_users),
            critical_assets_reached=sorted(list(critical_reached)),
        )

        # 5. Build ReachableTarget models
        # For each reachable target, find the best incoming edge from any predecessor
        for node in reachable_dist:
            for pred in G.predecessors(node):
                e_data = G.edges[pred, node]
                p = e_data["prob"]
                if node not in best_node_prob or p > best_node_prob[node]:
                    best_node_prob[node] = p
                    best_incoming_edge[node] = e_data

        reachable_targets: list[ReachableTarget] = []
        for node, hops in reachable_dist.items():
            n_kind = G.nodes.get(node, {}).get("kind", "host" if node in all_hosts_seen else "user")
            is_crit = node in critical_assets
            in_deg = G.in_degree(node) if node in G else 0
            best_edge = best_incoming_edge.get(node, {})
            score = best_node_prob.get(node, 0.5)

            if is_crit:
                priority = "critical"
            elif in_deg >= 5 or score >= 0.7:
                priority = "high"
            elif hops <= 2:
                priority = "medium"
            else:
                priority = "low"

            reason = best_edge.get("reason", f"Path reach via network access to {node}")
            e_ids = best_edge.get("evidence_event_ids", [])

            reachable_targets.append(
                ReachableTarget(
                    target_id=node,
                    target_label=node,
                    target_kind=n_kind,
                    hops=hops,
                    reason=reason,
                    priority=priority,
                    evidence_event_ids=list(e_ids)[:3],
                    score=round(score, 4),
                    is_critical=is_crit,
                )
            )

        # Deterministic sorting for targets: priority order, hops asc, -score, name
        priority_ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        reachable_targets.sort(
            key=lambda t: (
                priority_ranks.get(t.priority, 4),
                t.hops,
                -(t.score or 0.0),
                t.target_label,
            )
        )

        # 6. Predicted Attack Paths (Top 5 loop-free paths to distinct target hosts)
        # Select target candidates: critical assets or high in-degree hosts
        candidate_target_hosts = [
            node for node in blast_hosts
            if node in critical_assets or G.in_degree(node) >= 2
        ]
        # Fallback if few critical/high-degree: include other blast hosts
        if len(candidate_target_hosts) < 5:
            remaining = [h for h in blast_hosts if h not in candidate_target_hosts]
            candidate_target_hosts.extend(remaining)

        # Sort candidate target hosts deterministically (critical first, then in-degree desc, then name)
        candidate_target_hosts.sort(
            key=lambda h: (0 if h in critical_assets else 1, -G.in_degree(h), h)
        )

        path_candidates: list[PredictedPath] = []
        t0 = time.perf_counter()
        degraded_to_bfs = False

        for target in candidate_target_hosts:
            target_crit = "critical" if target in critical_assets else ("high" if G.in_degree(target) >= 5 else "standard")
            for seed in compromised_nodes:
                if seed not in G or not nx.has_path(G, seed, target):
                    continue

                # Check time budget
                if (time.perf_counter() - t0) > time_budget_sec:
                    if not degraded_to_bfs:
                        logger.warning(
                            "Reach path search exceeded time budget (%.2fs); degrading to hop-limited BFS.",
                            time_budget_sec,
                        )
                        degraded_to_bfs = True
                    # Run BFS shortest path as fallback
                    try:
                        bfs_path = nx.shortest_path(G, seed, target)
                        if len(bfs_path) - 1 <= max_hops:
                            score = 1.0
                            reasons = []
                            edge_ids = []
                            for i in range(len(bfs_path) - 1):
                                u, v = bfs_path[i], bfs_path[i + 1]
                                ed = G.edges[u, v]
                                score *= ed["prob"]
                                reasons.append(ed["reason"])
                                edge_ids.append(ed["edge_id"])
                            path_candidates.append(
                                PredictedPath(
                                    node_ids=bfs_path,
                                    edge_ids=edge_ids,
                                    hops=len(bfs_path) - 1,
                                    score=round(score, 4),
                                    target_label=target,
                                    target_criticality=target_crit,
                                    reasons=reasons,
                                )
                            )
                    except Exception:
                        pass
                    continue

                # Normal shortest_simple_paths with weight=cost (-ln(p))
                try:
                    paths_gen = nx.shortest_simple_paths(G, seed, target, weight="weight")
                    count_per_target = 0
                    for raw_path in paths_gen:
                        count_per_target += 1
                        if count_per_target > max_candidates_per_target:
                            break

                        hops = len(raw_path) - 1
                        if hops > max_hops:
                            continue

                        # Compute score and gather reasons
                        score = 1.0
                        reasons = []
                        edge_ids = []
                        for i in range(len(raw_path) - 1):
                            u, v = raw_path[i], raw_path[i + 1]
                            ed = G.edges[u, v]
                            score *= ed["prob"]
                            reasons.append(ed["reason"])
                            edge_ids.append(ed["edge_id"])

                        path_candidates.append(
                            PredictedPath(
                                node_ids=raw_path,
                                edge_ids=edge_ids,
                                hops=hops,
                                score=round(score, 4),
                                target_label=target,
                                target_criticality=target_crit,
                                reasons=reasons,
                            )
                        )
                except Exception:
                    continue

        # Sort candidate paths deterministically: score desc, hops asc, target_label asc, node_ids
        path_candidates.sort(
            key=lambda p: (-p.score, p.hops, p.target_label, p.node_ids)
        )

        # Filter to top 5 paths with DISTINCT target hosts
        distinct_top_paths: list[PredictedPath] = []
        seen_targets: set[str] = set()

        for p in path_candidates:
            if p.target_label not in seen_targets:
                seen_targets.add(p.target_label)
                distinct_top_paths.append(p)
                if len(distinct_top_paths) == 5:
                    break

        return NextReach(
            incident_id=incident_id,
            compromised_nodes=compromised_nodes,
            blast_radius=blast_radius,
            predicted_paths=distinct_top_paths,
            reachable_targets=reachable_targets,
            engine=self.name,
            disclaimer=DEFAULT_DISCLAIMER,
            message="Degraded to BFS due to time budget." if degraded_to_bfs else None,
        )


def compute_reach(incident_id: str) -> dict[str, Any]:
    """Legacy helper for backward compatibility."""
    from app.store import duck

    inc = duck.get_incident(incident_id)
    if not inc:
        return {"incident_id": incident_id, "seed_hosts": [], "reachable": []}

    engine = NetworkXEngine()
    next_res = engine.compute(inc, [])
    return {
        "incident_id": incident_id,
        "seed_hosts": next_res.compromised_nodes,
        "reachable": [
            {
                "entity": t.target_id,
                "entity_kind": t.target_kind,
                "technique_id": None,
                "tactic": None,
                "recommendation": t.reason,
            }
            for t in next_res.reachable_targets
        ],
    }
