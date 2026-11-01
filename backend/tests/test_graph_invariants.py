"""Tests for graph invariants and Cytoscape serialization correctness."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import networkx as nx
from app.pipeline.link.entity_graph import build_entity_graph, graph_to_cytoscape
from app.store import duck


def assert_graph_invariants(graph_dict: dict, has_detections: bool = True) -> None:
    """Assert all core graph invariants on a Cytoscape graph dictionary.

    Invariants:
    1. nodes and edges are non-empty for incidents with detections
    2. every edge's source and target exist in nodes
    3. every node has a data dict with unique id
    """
    nodes = graph_dict.get("nodes", [])
    edges = graph_dict.get("edges", [])

    if has_detections:
        assert len(nodes) > 0, "Graph nodes must be non-empty for incident with detections"
        assert len(edges) > 0, "Graph edges must be non-empty for incident with detections"

    node_ids: set[str] = set()
    for idx, node in enumerate(nodes):
        assert isinstance(node, dict), f"Node at index {idx} must be a dict"
        n_id = node.get("id")
        assert n_id is not None, f"Node at index {idx} missing 'id'"
        n_id_str = str(n_id)
        assert n_id_str not in node_ids, f"Duplicate node ID detected: '{n_id_str}'"
        node_ids.add(n_id_str)

        data = node.get("data")
        assert isinstance(data, dict), f"Node '{n_id_str}' must have a 'data' dict"
        assert str(data.get("id")) == n_id_str, f"Node '{n_id_str}' data['id'] mismatch"

    for idx, edge in enumerate(edges):
        assert isinstance(edge, dict), f"Edge at index {idx} must be a dict"
        src = edge.get("source")
        tgt = edge.get("target")
        assert src is not None and str(src) in node_ids, (
            f"Edge source '{src}' does not exist in graph nodes: {node_ids}"
        )
        assert tgt is not None and str(tgt) in node_ids, (
            f"Edge target '{tgt}' does not exist in graph nodes: {node_ids}"
        )

        data = edge.get("data")
        assert isinstance(data, dict), f"Edge '{edge.get('id')}' must have a 'data' dict"
        assert str(data.get("source")) in node_ids, (
            f"Edge data['source'] '{data.get('source')}' not in node IDs"
        )
        assert str(data.get("target")) in node_ids, (
            f"Edge data['target'] '{data.get('target')}' not in node IDs"
        )


def test_edge_target_not_overwritten_by_attributes():
    """Verify bugfix: inner loop variable must not overwrite edge target node with attribute values."""
    G = nx.DiGraph()
    G.add_node("host_A", kind="internal_host")
    G.add_node("T1110", kind="technique")
    # Add edge with predicted=False and other attrs that could overwrite target
    G.add_edge(
        "host_A",
        "T1110",
        label="executed",
        predicted=False,
        priority="high",
        reason="test edge",
    )

    cyto = graph_to_cytoscape(G, "inc_bugfix_test")
    assert len(cyto["edges"]) == 1
    edge = cyto["edges"][0]

    # Target must be the actual destination node, NOT 'False'
    assert edge["target"] == "T1110", f"Expected edge target 'T1110', got {edge['target']!r}"
    assert edge["data"]["target"] == "T1110"
    assert edge["source"] == "host_A"
    assert edge["data"]["source"] == "host_A"
    assert_graph_invariants(cyto, has_detections=True)


def test_graph_builder_and_cytoscape_invariants():
    """Verify invariants for full entity graph built with detections, steps, and bulk entities."""
    detections = [
        {
            "detection_id": "d_100",
            "host": "10.10.20.10",
            "technique_id": "T1110",
            "tactic": "credential_access",
            "kill_chain_stage": "Exploitation",
            "ts": "2026-10-23 10:00:00",
        },
        {
            "detection_id": "d_101",
            "host": "10.10.20.20",
            "technique_id": "T1021",
            "tactic": "lateral_movement",
            "kill_chain_stage": "Lateral Movement",
            "ts": "2026-10-23 10:30:00",
        },
    ]
    bulk_entities = {
        "d_100": {"users": ["user1"], "src_ips": ["192.168.1.50"]},
        "d_101": {"users": ["user1"], "src_ips": ["10.10.20.10"]},
    }
    steps = [
        {
            "step_order": 1,
            "technique_id": "T1110",
            "hosts": ["10.10.20.10"],
            "kill_chain_stage": "Exploitation",
            "first_seen": "2026-10-23 10:00:00",
            "last_seen": "2026-10-23 10:05:00",
            "evidence_event_ids": ["ev_1"],
        },
        {
            "step_order": 2,
            "technique_id": "T1021",
            "hosts": ["10.10.20.20"],
            "kill_chain_stage": "Lateral Movement",
            "first_seen": "2026-10-23 10:30:00",
            "last_seen": "2026-10-23 10:35:00",
            "evidence_event_ids": ["ev_2"],
        },
    ]

    G = build_entity_graph(detections=detections, bulk_entities=bulk_entities, steps=steps)
    cyto = graph_to_cytoscape(G, "inc_full_1")
    assert_graph_invariants(cyto, has_detections=True)


def test_graph_invariants_with_reach_targets():
    """Verify predicted reach nodes and edges preserve all graph invariants."""
    detections = [
        {
            "detection_id": "d_200",
            "host": "10.10.20.10",
            "technique_id": "T1190",
            "tactic": "initial_access",
            "kill_chain_stage": "Exploitation",
            "ts": "2026-10-23 12:00:00",
        }
    ]
    reach_data = {
        "compromised_nodes": ["10.10.20.10"],
        "blast_radius": {"hosts_count": 2, "critical_assets_reached": ["DC-01"]},
        "reachable_targets": [
            {
                "target_id": "DC-01",
                "target_label": "DC-01",
                "target_kind": "host",
                "hops": 1,
                "priority": "high",
                "reason": "Direct SMB path to Domain Controller",
            },
            {
                "target_id": "10.10.50.99",
                "target_label": "10.10.50.99",
                "target_kind": "host",
                "hops": 2,
                "priority": "medium",
                "reason": "Internal service reachable",
            },
        ],
    }

    G = build_entity_graph(detections=detections, reach_data=reach_data)
    cyto = graph_to_cytoscape(G, "inc_reach_1")
    assert_graph_invariants(cyto, has_detections=True)

    # Check predicted reach edges have correct targets
    predicted_edges = [e for e in cyto["edges"] if e.get("data", {}).get("predicted")]
    assert len(predicted_edges) == 2
    for pe in predicted_edges:
        assert pe["target"] in ("DC-01", "10.10.50.99")
        assert pe["source"] == "10.10.20.10"


def test_graph_invariants_in_temporary_database(tmp_path, monkeypatch):
    """Verify graph persistence and invariant assertions using a clean temporary DuckDB."""
    db_path = str(tmp_path / "temp_graph_test.duckdb")
    monkeypatch.setattr(duck, "_conn", None)
    from app.config import settings
    monkeypatch.setattr(settings, "duck_path", db_path)
    monkeypatch.setattr(settings, "parquet_dir", str(tmp_path / "parquet"))
    duck._conn = None
    duck.init_db()

    # Build and serialize a graph
    G = nx.DiGraph()
    G.add_node("host_1", kind="internal_host", label="host_1")
    G.add_node("T1059", kind="technique", label="T1059")
    G.add_edge("host_1", "T1059", label="executed", predicted=False)

    cyto = graph_to_cytoscape(G, "inc_db_test")
    assert_graph_invariants(cyto, has_detections=True)

    # Save to incident table
    duck.upsert_incident({
        "incident_id": "inc_db_test",
        "title": "Test Incident",
        "severity": 6,
        "status": "open",
        "detection_ids": ["det_x"],
        "hosts": ["host_1"],
        "users": [],
        "src_ips": [],
        "techniques": ["T1059"],
        "first_seen": "2026-10-23 00:00:00",
        "last_seen": "2026-10-23 01:00:00",
        "steps": [{"step_order": 1, "technique_id": "T1059", "hosts": ["host_1"]}],
        "graph_json": json.dumps(cyto),
    })

    # Retrieve and re-verify invariants
    inc_row = duck.get_incident("inc_db_test")
    assert inc_row is not None
    loaded_graph = json.loads(inc_row["graph_json"])
    assert_graph_invariants(loaded_graph, has_detections=True)

    if duck._conn:
        duck._conn.close()
        duck._conn = None


def test_check_graphs_cli_exits_zero():
    """Verify that scripts/check_graphs.py executes and exits with code 0."""
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "check_graphs.py"
    res = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"check_graphs.py failed:\n{res.stdout}\n{res.stderr}"
    assert "All graph invariants satisfied successfully" in res.stdout


def test_llm_status_endpoint():
    """Verify GET /api/v1/llm/status contract and security (no API key leakage)."""
    from app.api.routes.llm import router
    from app.config import settings
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    test_app = FastAPI()
    test_app.include_router(router, prefix="/api/v1")
    client = TestClient(test_app)

    resp = client.get("/api/v1/llm/status")
    assert resp.status_code == 200
    data = resp.json()

    assert data["provider"] == "gemini"
    assert data["model"] == settings.llm_model
    assert isinstance(data["key_configured"], bool)
    assert isinstance(data["budget_remaining"], int)
    assert data["budget_remaining"] >= 0

    # Strict check: never return any API key
    assert "api_key" not in data
    assert "llm_api_key" not in data
    assert "gemini_api_key" not in data
    for val in data.values():
        if isinstance(val, str):
            assert "AIza" not in val
            assert "sk-" not in val
