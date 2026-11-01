#!/usr/bin/env python3
"""Check graph invariants across incidents and mock graph builders."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Add backend directory to sys.path
repo_root = Path(__file__).resolve().parents[1]
backend_dir = repo_root / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.pipeline.link.entity_graph import build_entity_graph, graph_to_cytoscape  # noqa: E402


def verify_graph_invariants(graph_dict: dict, incident_id: str, has_detections: bool = True) -> list[str]:
    """Assert graph invariants on a Cytoscape graph dict.

    Invariants:
    1. nodes and edges are non-empty for incidents with detections
    2. every edge's source and target exist in nodes
    3. every node has a data dict with unique id
    """
    errors: list[str] = []
    nodes = graph_dict.get("nodes", [])
    edges = graph_dict.get("edges", [])

    if has_detections:
        if not nodes:
            errors.append(f"Incident {incident_id}: nodes array is empty despite having detections")
        if not edges:
            errors.append(f"Incident {incident_id}: edges array is empty despite having detections")

    node_ids: set[str] = set()
    for idx, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"Incident {incident_id}: node[{idx}] is not a dict")
            continue
        n_id = node.get("id")
        if n_id is None:
            errors.append(f"Incident {incident_id}: node[{idx}] missing 'id'")
            continue
        n_id_str = str(n_id)
        if n_id_str in node_ids:
            errors.append(f"Incident {incident_id}: duplicate node ID '{n_id_str}'")
        node_ids.add(n_id_str)

        data = node.get("data")
        if not isinstance(data, dict):
            errors.append(f"Incident {incident_id}: node '{n_id_str}' missing or invalid 'data' dict")
        else:
            if str(data.get("id")) != n_id_str:
                errors.append(
                    f"Incident {incident_id}: node '{n_id_str}' data.id mismatch ('{data.get('id')}' != '{n_id_str}')"
                )

    for idx, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"Incident {incident_id}: edge[{idx}] is not a dict")
            continue
        src = edge.get("source")
        tgt = edge.get("target")
        if src is None or str(src) not in node_ids:
            errors.append(f"Incident {incident_id}: edge source '{src}' not found in nodes")
        if tgt is None or str(tgt) not in node_ids:
            errors.append(f"Incident {incident_id}: edge target '{tgt}' not found in nodes")

        data = edge.get("data")
        if isinstance(data, dict):
            d_src = data.get("source")
            d_tgt = data.get("target")
            if d_src is not None and str(d_src) not in node_ids:
                errors.append(f"Incident {incident_id}: edge data.source '{d_src}' not found in nodes")
            if d_tgt is not None and str(d_tgt) not in node_ids:
                errors.append(f"Incident {incident_id}: edge data.target '{d_tgt}' not found in nodes")

    return errors


def check_mock_graphs() -> list[str]:
    """Test graph invariants against synthetic graph scenarios."""
    all_errors: list[str] = []

    # Scenario 1: Multi-stage incident with steps, users, IPs, and predicted reach
    detections = [
        {
            "detection_id": "det_1",
            "host": "10.10.20.50",
            "technique_id": "T1110",
            "tactic": "credential_access",
            "kill_chain_stage": "Exploitation",
            "ts": "2026-10-23 08:00:00",
        },
        {
            "detection_id": "det_2",
            "host": "10.10.20.50",
            "technique_id": "T1078",
            "tactic": "defense_evasion",
            "kill_chain_stage": "Installation",
            "ts": "2026-10-23 08:10:00",
        },
        {
            "detection_id": "det_3",
            "host": "10.10.20.77",
            "technique_id": "T1021",
            "tactic": "lateral_movement",
            "kill_chain_stage": "Lateral Movement",
            "ts": "2026-10-23 08:20:00",
        },
    ]
    bulk_entities = {
        "det_1": {"users": ["alice"], "src_ips": ["198.51.100.22"]},
        "det_2": {"users": ["alice"], "src_ips": []},
        "det_3": {"users": ["bob"], "src_ips": ["10.10.20.50"]},
    }
    steps = [
        {
            "step_order": 1,
            "technique_id": "T1110",
            "hosts": ["10.10.20.50"],
            "kill_chain_stage": "Exploitation",
            "first_seen": "2026-10-23 08:00:00",
            "last_seen": "2026-10-23 08:05:00",
            "evidence_event_ids": ["ev_1", "ev_2"],
        },
        {
            "step_order": 2,
            "technique_id": "T1078",
            "hosts": ["10.10.20.50"],
            "kill_chain_stage": "Installation",
            "first_seen": "2026-10-23 08:10:00",
            "last_seen": "2026-10-23 08:12:00",
            "evidence_event_ids": ["ev_3"],
        },
        {
            "step_order": 3,
            "technique_id": "T1021",
            "hosts": ["10.10.20.77"],
            "kill_chain_stage": "Lateral Movement",
            "first_seen": "2026-10-23 08:20:00",
            "last_seen": "2026-10-23 08:25:00",
            "evidence_event_ids": ["ev_4"],
        },
    ]
    reach_data = {
        "compromised_nodes": ["10.10.20.77"],
        "blast_radius": {"hosts_count": 2, "critical_assets_reached": ["DC-01"]},
        "reachable_targets": [
            {
                "target_id": "DC-01",
                "target_label": "DC-01",
                "target_kind": "host",
                "hops": 1,
                "priority": "high",
                "reason": "Domain controller accessible via SMB",
                "evidence_event_ids": ["ev_5"],
            },
            {
                "target_id": "10.10.30.90",
                "target_label": "10.10.30.90",
                "target_kind": "host",
                "hops": 1,
                "priority": "medium",
                "reason": "Observed port 445 traffic",
                "evidence_event_ids": ["ev_6"],
            },
        ],
    }

    G = build_entity_graph(
        detections=detections,
        bulk_entities=bulk_entities,
        steps=steps,
        reach_data=reach_data,
    )
    cyto = graph_to_cytoscape(G, "inc_mock_1")
    errs = verify_graph_invariants(cyto, "inc_mock_1", has_detections=True)
    all_errors.extend(errs)

    # Scenario 2: Minimal single-detection graph without reach data
    G_min = build_entity_graph(
        detections=[detections[0]],
        bulk_entities={"det_1": {"users": ["alice"], "src_ips": ["198.51.100.22"]}},
    )
    cyto_min = graph_to_cytoscape(G_min, "inc_mock_2")
    errs_min = verify_graph_invariants(cyto_min, "inc_mock_2", has_detections=True)
    all_errors.extend(errs_min)

    return all_errors


def check_database_graphs(db_path: str) -> tuple[int, list[str]]:
    """Inspect all incidents in a DuckDB database in read-only mode."""
    import duckdb

    all_errors: list[str] = []
    checked = 0
    try:
        con = duckdb.connect(db_path, read_only=True)
        # Check if incidents table exists
        tables = [r[0] for r in con.execute("SHOW TABLES").fetchall()]
        if "incidents" not in tables:
            con.close()
            return 0, []

        rows = con.execute("SELECT incident_id, detection_ids, graph_json FROM incidents").fetchall()
        for inc_id, det_ids_raw, graph_json in rows:
            det_ids = json.loads(det_ids_raw) if isinstance(det_ids_raw, str) else (det_ids_raw or [])
            has_dets = len(det_ids) > 0
            if graph_json:
                graph_dict = json.loads(graph_json) if isinstance(graph_json, str) else graph_json
                errs = verify_graph_invariants(graph_dict, inc_id, has_detections=has_dets)
                all_errors.extend(errs)
                checked += 1
        con.close()
    except Exception as exc:
        all_errors.append(f"Failed to inspect database at {db_path}: {exc}")

    return checked, all_errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify graph invariants for incidents.")
    parser.add_argument("--db", default=None, help="Path to DuckDB database file (read-only)")
    args = parser.parse_args()

    print("[*] Running graph invariant checks on synthetic/mock graphs...")
    mock_errors = check_mock_graphs()
    if mock_errors:
        print(f"[!] FAILED: Found {len(mock_errors)} invariant violations in mock graphs:")
        for err in mock_errors:
            print(f"    - {err}")
        sys.exit(1)
    print("    [+] Mock graph builder passed all invariants.")

    db_path = args.db
    if db_path and os.path.isfile(db_path):
        print(f"[*] Checking database incidents at {db_path} (read-only)...")
        checked, db_errors = check_database_graphs(db_path)
        if db_errors:
            print(f"[!] FAILED: Found {len(db_errors)} invariant violations in database graphs:")
            for err in db_errors:
                print(f"    - {err}")
            sys.exit(1)
        print(f"    [+] Checked {checked} database incidents: all passed.")

    print("[+] All graph invariants satisfied successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
