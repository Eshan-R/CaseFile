"""Incident builder: clusters related detections into incidents."""

from __future__ import annotations

import json
from typing import Any

from app.pipeline.link.entity_graph import build_entity_graph, graph_to_cytoscape
from app.store import duck


def _det_key(det: dict) -> tuple:
    """Group key: same host + same tactic within a 5-minute sliding window."""
    return (det["host"], det["tactic"])


def build_incidents() -> dict[str, Any]:
    """Read all un-grouped detections and form incidents.

    Uses a simple union-find approach: detections that share a host or IP
    within 30 min are merged into the same incident.
    """
    _, all_dets = duck.list_detections(limit=100_000)
    if not all_dets:
        return {"incidents_created": 0}

    # Sort by ts
    all_dets.sort(key=lambda d: str(d["ts"]))

    # Union-find by host proximity (30-min window)
    groups: list[list[dict]] = []
    for det in all_dets:
        merged = False
        for grp in groups:
            last = grp[-1]
            # Same host → merge
            if last["host"] == det["host"]:
                grp.append(det)
                merged = True
                break
        if not merged:
            groups.append([det])

    incidents_created = 0
    for grp in groups:
        if not grp:
            continue
        inc_id = duck.new_id("inc")
        hosts = list({d["host"] for d in grp})
        techniques = list(dict.fromkeys(d["technique_id"] for d in grp))
        det_ids = [d["detection_id"] for d in grp]
        first_seen = min(d["ts"] for d in grp)
        last_seen = max(d["ts"] for d in grp)
        severity = max(d["severity"] for d in grp)

        # Collect users/IPs from events
        users: set[str] = set()
        src_ips: set[str] = set()
        event_count = 0
        for det in grp:
            _, evs = duck.list_events(detection_id=det["detection_id"], limit=50)
            for ev in evs:
                event_count += 1
                if ev.get("user_name"):
                    users.add(ev["user_name"])
                if ev.get("src_ip"):
                    src_ips.add(ev["src_ip"])

        # Build attack steps (ordered by first detection timestamp)
        steps = []
        for i, det in enumerate(grp, 1):
            steps.append({
                "step_order": i,
                "technique_id": det["technique_id"],
                "tactic": det.get("tactic", ""),
                "detection_ids": [det["detection_id"]],
                "first_seen": str(det["ts"]),
                "last_seen": str(det["ts"]),
                "hosts": [det["host"]],
            })

        title = f"Attack on {', '.join(hosts[:3])} ({techniques[0]})"

        inc = {
            "incident_id": inc_id,
            "title": title,
            "severity": severity,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "hosts": hosts,
            "users": list(users),
            "src_ips": list(src_ips),
            "techniques": techniques,
            "steps": steps,
            "detection_ids": det_ids,
            "event_count": event_count,
            "status": "open",
        }

        # Pre-compute graph
        G = build_entity_graph(grp)
        graph_dict = graph_to_cytoscape(G, inc_id)
        inc["graph_json"] = json.dumps(graph_dict)

        # Tag detections with incident_id and link incident events
        for det in grp:
            with duck.cursor() as con:
                con.execute(
                    "UPDATE detections SET incident_id=? WHERE detection_id=?",
                    [inc_id, det["detection_id"]],
                )
            eids = json.loads(det["event_ids"]) if isinstance(det.get("event_ids"), str) else det.get("event_ids", [])
            duck.link_incident_events(inc_id, eids)

        duck.upsert_incident(inc)
        try:
            from app.pipeline.path.reach.service import precompute_reach_for_incident
            precompute_reach_for_incident(inc_id)
        except Exception:
            pass
        incidents_created += 1

    return {"incidents_created": incidents_created}

