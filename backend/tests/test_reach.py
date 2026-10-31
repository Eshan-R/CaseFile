"""Tests for reachability engine, NetworkX path prediction, fallback, and API latency."""

from __future__ import annotations

import logging
import time

import pytest
from app.main import app
from app.pipeline.path.reach.base import NotConfigured
from app.pipeline.path.reach.engine import get_reach_engine
from app.pipeline.path.reach.neo4j_engine import Neo4jEngine
from app.pipeline.path.reach.networkx_engine import NetworkXEngine
from app.pipeline.path.reach.service import precompute_reach_for_incident
from app.schemas.reach import DEFAULT_DISCLAIMER, NextReach
from app.store import duck
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def clean_test_db(tmp_path, monkeypatch):
    """Run tests with an isolated clean DuckDB database."""
    db_path = str(tmp_path / "test_reach.duckdb")
    monkeypatch.setattr("app.config.settings.duck_path", db_path)
    duck.close()
    duck.init_db()
    yield
    duck.close()


def test_hand_crafted_graph_and_hand_computed_scores():
    """Verify hand-computed blast radius, best paths, and probability math on a known graph."""
    incident = {
        "incident_id": "inc_hand_crafted",
        "first_seen": "2026-10-25T10:00:00Z",
        "hosts": ["workstation-01"],
        "users": ["alice"],
    }

    access_edges = [
        # Edge 1: alice -> DC-01 (admin=True, last_seen within 7 days)
        # p = 0.9 (admin) + 0.05 (recency) = 0.95
        {
            "source": "alice",
            "target": "DC-01",
            "source_kind": "user",
            "target_kind": "host",
            "kind": "admin",
            "is_admin": True,
            "count": 5,
            "last_seen": "2026-10-24T10:00:00Z",
            "evidence_event_ids": ["ev_1", "ev_2"],
        },
        # Edge 2: workstation-01 -> FS-01 (count=3, connection, within 7 days)
        # p = min(0.8, 0.2 + 0.1 * log2(3+1)) = 0.40 + 0.05 = 0.45
        {
            "source": "workstation-01",
            "target": "FS-01",
            "source_kind": "host",
            "target_kind": "host",
            "kind": "connection",
            "is_admin": False,
            "count": 3,
            "last_seen": "2026-10-23T10:00:00Z",
            "evidence_event_ids": ["ev_3"],
        },
        # Edge 3: FS-01 -> DB-SERVER (count=7, connection, within 7 days)
        # p = min(0.8, 0.2 + 0.1 * log2(7+1)) = 0.50 + 0.05 = 0.55
        {
            "source": "FS-01",
            "target": "DB-SERVER",
            "source_kind": "host",
            "target_kind": "host",
            "kind": "connection",
            "is_admin": False,
            "count": 7,
            "last_seen": "2026-10-22T10:00:00Z",
            "evidence_event_ids": ["ev_4"],
        },
    ]

    engine = NetworkXEngine()
    result: NextReach = engine.compute(incident, access_edges)

    # 1. Compromised nodes
    assert sorted(result.compromised_nodes) == ["alice", "workstation-01"]

    # 2. Blast radius: DC-01, FS-01, DB-SERVER (3 hosts, 0 users)
    assert result.blast_radius.hosts_count == 3
    assert result.blast_radius.users_count == 0
    assert result.blast_radius.total_nodes == 3
    assert "DC-01" in result.blast_radius.critical_assets_reached
    assert "FS-01" in result.blast_radius.critical_assets_reached
    assert "DB-SERVER" in result.blast_radius.critical_assets_reached

    # 3. Top predicted paths to distinct target hosts
    assert len(result.predicted_paths) == 3

    # Best path: alice -> DC-01 (score 0.95)
    best_path = result.predicted_paths[0]
    assert best_path.node_ids == ["alice", "DC-01"]
    assert best_path.hops == 1
    assert best_path.score == pytest.approx(0.95, rel=1e-3)
    assert best_path.target_label == "DC-01"
    assert best_path.target_criticality == "critical"
    assert any("admin" in r.lower() for r in best_path.reasons)

    # Second path: workstation-01 -> FS-01 (score 0.45)
    path_fs = next(p for p in result.predicted_paths if p.target_label == "FS-01")
    assert path_fs.node_ids == ["workstation-01", "FS-01"]
    assert path_fs.hops == 1
    assert path_fs.score == pytest.approx(0.45, rel=1e-3)

    # Third path: workstation-01 -> FS-01 -> DB-SERVER (score 0.45 * 0.55 = 0.2475)
    path_db = next(p for p in result.predicted_paths if p.target_label == "DB-SERVER")
    assert path_db.node_ids == ["workstation-01", "FS-01", "DB-SERVER"]
    assert path_db.hops == 2
    assert path_db.score == pytest.approx(0.2475, rel=1e-3)
    assert path_db.target_criticality == "critical"

    # 4. Reachable target evidence and priorities
    target_dc = next(t for t in result.reachable_targets if t.target_id == "DC-01")
    assert target_dc.priority == "critical"
    assert "ev_1" in target_dc.evidence_event_ids

    # 5. Disclaimer presence
    assert result.disclaimer == DEFAULT_DISCLAIMER


def test_neo4j_stub_and_engine_fallback(caplog):
    """Verify Neo4jEngine raises NotConfigured and get_reach_engine falls back with warning."""
    # 1. Direct Neo4j compute raises NotConfigured
    neo_engine = Neo4jEngine()
    with pytest.raises(NotConfigured) as exc_info:
        neo_engine.compute({"incident_id": "test"}, [])
    assert "Phase 11" in str(exc_info.value)

    # 2. Selecting 'neo4j' engine logs warning and falls back to NetworkX
    with caplog.at_level(logging.WARNING):
        resolved_engine = get_reach_engine("neo4j")
    assert isinstance(resolved_engine, NetworkXEngine)
    assert any("Falling back to NetworkX" in rec.message for rec in caplog.records)


def test_reach_api_latency_under_200ms():
    """Verify GET /incidents/{id}/next returns precomputed data in under 200 ms."""
    client = TestClient(app)

    # Seed incident and precompute reach
    incident_id = "inc_latency_test"
    duck.upsert_incident({
        "incident_id": incident_id,
        "title": "Latency Test Incident",
        "severity": 4,
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T12:00:00Z",
        "hosts": ["web-01"],
        "users": ["bob"],
        "src_ips": ["10.0.0.5"],
        "techniques": ["T1078"],
        "steps": [],
        "detection_ids": [],
    })

    edges = [
        {
            "source": "bob",
            "target": "sql-01",
            "is_admin": False,
            "count": 2,
            "last_seen": "2026-10-25T09:00:00Z",
        }
    ]

    precompute_reach_for_incident(incident_id, access_edges=edges)

    # Measure latency of GET /incidents/{incident_id}/next
    latencies = []
    for _ in range(10):
        t0 = time.perf_counter()
        resp = client.get(f"/incidents/{incident_id}/next")
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)
        assert resp.status_code == 200

    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)

    assert max_latency < 200.0, f"Max latency was {max_latency:.2f}ms (must be < 200ms)"
    assert avg_latency < 50.0, f"Avg latency was {avg_latency:.2f}ms"

    # Verify content
    data = resp.json()
    assert data["incident_id"] == incident_id
    assert data["disclaimer"] == DEFAULT_DISCLAIMER
    assert len(data["predicted_paths"]) >= 1


def test_api_404_when_not_precomputed():
    """Verify GET /incidents/{id}/next returns 404 if not precomputed (never computes on request)."""
    client = TestClient(app)

    incident_id = "inc_uncomputed"
    duck.upsert_incident({
        "incident_id": incident_id,
        "title": "Uncomputed Incident",
        "severity": 2,
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T12:00:00Z",
        "hosts": ["host-x"],
        "users": [],
        "src_ips": [],
        "techniques": [],
        "steps": [],
        "detection_ids": [],
    })

    resp = client.get(f"/incidents/{incident_id}/next")
    assert resp.status_code == 404
    assert "precomputed" in resp.json()["detail"].lower()


def test_edge_cases():
    """Test edge cases: service accounts, isolated incidents, self-loops, high-degree nodes."""
    engine = NetworkXEngine()

    # 1. Broad service account (> N hosts reached)
    sa_edges = []
    for i in range(15):
        sa_edges.append({
            "source": "svc_backup",
            "target": f"srv-{i:02d}",
            "kind": "logon",
            "is_admin": False,
            "count": 10,
        })
    res_sa = engine.compute(
        {"incident_id": "inc_sa", "hosts": [], "users": ["svc_backup"]},
        sa_edges,
        config={"service_account_threshold": 10},
    )
    # The probability should be lowered
    for p in res_sa.predicted_paths:
        assert p.score <= 0.25
        assert any("service account" in r.lower() for r in p.reasons)

    # 2. Isolated incident (no outgoing edges)
    res_isolated = engine.compute(
        {"incident_id": "inc_iso", "hosts": ["lonely-host"], "users": []},
        [],
    )
    assert res_isolated.blast_radius.total_nodes == 0
    assert res_isolated.predicted_paths == []
    assert res_isolated.reachable_targets == []
    assert "Isolated incident" in (res_isolated.message or "")

    # 3. Self-loops and missing names
    messy_edges = [
        {"source": "hostA", "target": "hostA", "count": 5},  # self loop
        {"source": "", "target": "hostB", "count": 1},  # missing source
        {"source": "hostA", "target": "hostB", "count": 2},  # valid
    ]
    res_messy = engine.compute(
        {"incident_id": "inc_messy", "hosts": ["hostA"], "users": []},
        messy_edges,
    )
    assert "hostA" not in [t.target_id for t in res_messy.reachable_targets]
    assert any(t.target_id == "hostB" for t in res_messy.reachable_targets)

    # 4. Very high degree node: limit to top 200 edges
    huge_edges = [
        {"source": "core-hub", "target": f"leaf-{i}", "count": i, "is_admin": False}
        for i in range(300)
    ]
    res_huge = engine.compute(
        {"incident_id": "inc_huge", "hosts": ["core-hub"], "users": []},
        huge_edges,
        config={"max_out_edges": 200},
    )
    assert res_huge.blast_radius.hosts_count <= 200
