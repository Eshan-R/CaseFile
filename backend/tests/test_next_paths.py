"""Unit tests for predictive next paths, deterministic ranking, sensitive ports filtering, and Cytoscape integration."""

from __future__ import annotations

import time

import pytest
from app.api.routes.next_paths import router
from app.main import app
from app.pipeline.path.reach.service import (
    clear_predicted_paths_cache,
    get_predicted_next_paths,
    inject_predicted_paths_into_cytoscape,
    predict_next_paths,
)
from app.schemas.next_paths import DEFAULT_NEXT_PATHS_DISCLAIMER, NextPathsResponse
from app.store import duck
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def clean_test_db(tmp_path, monkeypatch):
    """Run tests with an isolated clean DuckDB database (never write to data/run.duckdb)."""
    db_path = str(tmp_path / "test_next_paths.duckdb")
    monkeypatch.setattr("app.config.settings.duck_path", db_path)
    monkeypatch.setattr("app.config.settings.parquet_dir", str(tmp_path / "empty_parquet"))
    duck.close()
    duck.init_db()
    clear_predicted_paths_cache()
    yield
    duck.close()
    clear_predicted_paths_cache()


@pytest.fixture
def client():
    """FastAPI TestClient with next_paths router available."""
    # Ensure route is registered
    route_paths = {getattr(r, "path", "") for r in app.routes}
    if "/api/v1/incidents/{id}/next-paths" not in route_paths:
        app.include_router(router, prefix="/api/v1")
    return TestClient(app)


def test_schema_and_disclaimer(client):
    """Verify NextPathsResponse schema conformity and standard disclaimer."""
    incident_id = "inc_schema_test"
    duck.upsert_incident({
        "incident_id": incident_id,
        "title": "Compromised Internal Host",
        "severity": 4,
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:30:00Z",
        "hosts": ["10.10.10.44"],
        "src_ips": ["10.10.10.44"],
        "techniques": ["T1003.001"],
        "steps": [
            {
                "detection_id": "det_1",
                "technique_id": "T1003.001",
                "tactic": "credential_access",
                "host": "10.10.10.44",
                "first_seen": "2026-10-25T10:00:00Z",
            }
        ],
        "detection_ids": ["det_1"],
    })

    with duck.cursor() as con:
        con.execute("""
        INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
        VALUES ('ev_rdp_1', '2026-10-25 10:15:00Z', '10.10.10.44', '10.10.20.15', 3389, 'rdp', 'accept')
        """)

    resp = client.get(f"/api/v1/incidents/{incident_id}/next-paths")
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Validate response schema
    model = NextPathsResponse(**data)
    assert model.predicted is True
    assert model.disclaimer == DEFAULT_NEXT_PATHS_DISCLAIMER
    assert model.disclaimer == "Based on access observed in the logs; a prediction, not an observation."
    assert model.reason is None
    assert len(model.paths) == 1

    item = model.paths[0]
    assert item.rank == 1
    assert item.from_entity == "10.10.10.44"
    assert item.to_entity == "10.10.20.15"
    assert item.service == "RDP"
    assert item.port == 3389
    assert item.predicted_technique == "T1021.001"
    assert item.predicted_tactic == "lateral_movement"
    assert 0.0 <= item.likelihood <= 1.0
    assert item.confidence in ("low", "medium", "high")
    assert "Monitor inbound RDP (3389) on 10.10.20.15 from 10.10.10.44" in item.monitor_or_block
    assert item.evidence.allowed_connections_observed == 1
    assert item.evidence.target_already_touched is False
    assert item.evidence.tactic_transition_support is True


def test_at_most_top_3_and_deterministic_ranking(client):
    """Verify at most top 3 paths are returned and ranked deterministically by Score."""
    incident_id = "inc_ranking_test"
    duck.upsert_incident({
        "incident_id": incident_id,
        "title": "Active Lateral Campaign",
        "severity": 4,
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:30:00Z",
        "hosts": ["10.10.10.10"],
        "src_ips": ["10.10.10.10"],
        "techniques": ["T1003"],
        "steps": [{"tactic": "credential_access", "first_seen": "2026-10-25T10:00:00Z"}],
    })

    with duck.cursor() as con:
        # Candidate 1: DC-01 (critical DC, crit=3), port 445 (SMB), 5 allowed
        # Score = (5 * 0.3) + (3 * 0.4) + 0.3 = 1.5 + 1.2 + 0.3 = 3.0
        for i in range(5):
            con.execute(f"""
            INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
            VALUES ('ev_c1_{i}', '2026-10-25 10:10:00Z', '10.10.10.10', 'DC-01', 445, 'smb', 'accept')
            """)

        # Candidate 2: 10.10.20.15 (standard host, crit=1), port 3389 (RDP), 10 allowed
        # Score = (10 * 0.3) + (1 * 0.4) + 0.3 = 3.0 + 0.4 + 0.3 = 3.7
        for i in range(10):
            con.execute(f"""
            INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
            VALUES ('ev_c2_{i}', '2026-10-25 10:12:00Z', '10.10.10.10', '10.10.20.15', 3389, 'rdp', 'accept')
            """)

        # Candidate 3: mysql-srv-01 (sql/db server, crit=2), port 1433 (MS-SQL), 4 allowed
        # Score = (4 * 0.3) + (2 * 0.4) + 0.3 = 1.2 + 0.8 + 0.3 = 2.3
        for i in range(4):
            con.execute(f"""
            INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
            VALUES ('ev_c3_{i}', '2026-10-25 10:14:00Z', '10.10.10.10', 'mysql-srv-01', 1433, 'ms-sql', 'accept')
            """)

        # Candidate 4: 10.10.30.20 (standard host, crit=1), port 22 (SSH), 2 allowed
        # Score = (2 * 0.3) + (1 * 0.4) + 0.3 = 0.6 + 0.4 + 0.3 = 1.3
        for i in range(2):
            con.execute(f"""
            INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
            VALUES ('ev_c4_{i}', '2026-10-25 10:16:00Z', '10.10.10.10', '10.10.30.20', 22, 'ssh', 'accept')
            """)

        # Candidate 5: 10.10.40.25 (standard host, crit=1), port 443 (HTTPS), 1 allowed
        # Score = (1 * 0.3) + (1 * 0.4) + 0.3 = 0.3 + 0.4 + 0.3 = 1.0
        con.execute("""
        INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
        VALUES ('ev_c5_0', '2026-10-25 10:18:00Z', '10.10.10.10', '10.10.40.25', 443, 'https', 'accept')
        """)

    resp = client.get(f"/api/v1/incidents/{incident_id}/next-paths")
    assert resp.status_code == 200
    data = resp.json()

    # Strictly at most 3 paths
    assert len(data["paths"]) == 3

    # Deterministic ranking: 10.10.20.15 (score 3.7) > DC-01 (score 3.0) > SQL-PROD (score 2.3)
    p1 = data["paths"][0]
    p2 = data["paths"][1]
    p3 = data["paths"][2]

    assert p1["rank"] == 1
    assert p1["to_entity"] == "10.10.20.15"
    assert p1["service"] == "RDP"
    assert p1["evidence"]["allowed_connections_observed"] == 10

    assert p2["rank"] == 2
    assert p2["to_entity"] == "DC-01"
    assert p2["service"] == "SMB"
    assert p2["evidence"]["asset_criticality"] == 3

    assert p3["rank"] == 3
    assert p3["to_entity"] == "mysql-srv-01"
    assert p3["service"] == "MS-SQL"
    assert p3["evidence"]["asset_criticality"] == 2


def test_sensitive_ports_filtering(client):
    """Verify only sensitive ports are considered and generic ports are strictly filtered out."""
    incident_id = "inc_ports_test"
    duck.upsert_incident({
        "incident_id": incident_id,
        "title": "Port Filtering Test",
        "severity": 3,
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:30:00Z",
        "hosts": ["10.10.10.50"],
        "src_ips": ["10.10.10.50"],
    })

    with duck.cursor() as con:
        # Sensitive port: 445 (SMB)
        con.execute("""
        INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
        VALUES ('ev_smb', '2026-10-25 10:05:00Z', '10.10.10.50', '10.10.20.10', 445, 'smb', 'accept')
        """)

        # Sensitive port: 22 (SSH)
        con.execute("""
        INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
        VALUES ('ev_ssh', '2026-10-25 10:06:00Z', '10.10.10.50', '10.10.20.11', 22, 'ssh', 'accept')
        """)

        # Non-sensitive ports: 80 (HTTP), 53 (DNS), 123 (NTP), 8000 (Custom HTTP)
        for idx, (p, s) in enumerate([(80, "http"), (53, "dns"), (123, "ntp"), (8000, "http-alt")]):
            con.execute(f"""
            INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
            VALUES ('ev_nonsens_{idx}', '2026-10-25 10:07:00Z', '10.10.10.50', '10.10.20.{20+idx}', {p}, '{s}', 'accept')
            """)

    resp = client.get(f"/api/v1/incidents/{incident_id}/next-paths")
    assert resp.status_code == 200
    paths = resp.json()["paths"]

    # Only the 2 sensitive ports should be returned
    assert len(paths) == 2
    returned_ports = {p["port"] for p in paths}
    assert returned_ports == {445, 22}
    assert 80 not in returned_ports
    assert 53 not in returned_ports
    assert 123 not in returned_ports
    assert 8000 not in returned_ports


def test_ghost_nodes_and_predicted_edges_format():
    """Verify inject_predicted_paths_into_cytoscape creates ghost nodes and predicted edges in the exact Cytoscape format."""
    incident_id = "inc_cyto_test"
    duck.upsert_incident({
        "incident_id": incident_id,
        "title": "Cytoscape Integration Test",
        "severity": 3,
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:30:00Z",
        "hosts": ["10.10.10.44"],
        "src_ips": ["10.10.10.44"],
    })

    with duck.cursor() as con:
        con.execute("""
        INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
        VALUES ('ev_rdp_cyto', '2026-10-25 10:15:00Z', '10.10.10.44', '10.10.20.99', 3389, 'rdp', 'accept')
        """)

    cyto_data = {
        "nodes": [
            {"id": "10.10.10.44", "label": "10.10.10.44", "kind": "host"},
        ],
        "edges": [],
    }

    enriched = inject_predicted_paths_into_cytoscape(cyto_data, incident_id)

    # Check ghost node
    ghost_nodes = [n for n in enriched["nodes"] if n.get("classes") == "ghost-node predicted"]
    assert len(ghost_nodes) == 1
    gn = ghost_nodes[0]
    assert gn["data"]["id"] == "10.10.20.99"
    assert gn["data"]["label"] == "10.10.20.99"
    assert gn["data"]["predicted"] is True

    # Check predicted edge
    predicted_edges = [e for e in enriched["edges"] if e.get("classes") == "predicted-edge"]
    assert len(predicted_edges) == 1
    pe = predicted_edges[0]
    assert pe["data"]["source"] == "10.10.10.44"
    assert pe["data"]["target"] == "10.10.20.99"
    assert pe["data"]["label"] == "predicted_reach"
    assert pe["data"]["predicted"] is True
    assert "allowed_connections_observed" in pe["data"]["evidence"]


def test_empty_paths_graceful_reason_fallback(client):
    """Verify empty paths returns empty list with explicit graceful reason fallback."""
    incident_id = "inc_empty_test"
    duck.upsert_incident({
        "incident_id": incident_id,
        "title": "Incident Without Lateral Sensitive Traffic",
        "severity": 2,
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:30:00Z",
        "hosts": ["10.10.10.100"],
        "src_ips": ["10.10.10.100"],
    })

    # Only non-sensitive traffic (port 80 http)
    with duck.cursor() as con:
        con.execute("""
        INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
        VALUES ('ev_http_only', '2026-10-25 10:10:00Z', '10.10.10.100', '192.168.1.1', 80, 'http', 'accept')
        """)

    resp = client.get(f"/api/v1/incidents/{incident_id}/next-paths")
    assert resp.status_code == 200
    data = resp.json()

    assert data["predicted"] is True
    assert data["disclaimer"] == DEFAULT_NEXT_PATHS_DISCLAIMER
    assert data["paths"] == []
    assert data["reason"] == "No outbound sensitive service connections observed from compromised entities"


def test_target_already_touched_penalty():
    """Verify target_already_touched applies -0.5 penalty and penalizes score deterministically."""
    incident = {
        "incident_id": "inc_penalty_test",
        "hosts": ["10.10.10.5", "10.10.20.15"],  # 10.10.20.15 already touched
        "src_ips": ["10.10.10.5"],
    }

    # Two candidate edges with identical counts and criticality, but one is already touched
    candidate_edges = [
        # Target 1: 10.10.20.15 (already in incident hosts) -> penalty -0.5
        {
            "src_host": "10.10.10.5",
            "tgt_host": "10.10.20.15",
            "dst_port": 3389,
            "service": "rdp",
            "count": 5,
        },
        # Target 2: 10.10.20.99 (new target) -> no penalty
        {
            "src_host": "10.10.10.5",
            "tgt_host": "10.10.20.99",
            "dst_port": 3389,
            "service": "rdp",
            "count": 5,
        },
    ]

    res = predict_next_paths(incident=incident, candidate_edges=candidate_edges)
    assert len(res.paths) == 2

    # New target should be ranked higher due to absence of penalty
    assert res.paths[0].to_entity == "10.10.20.99"
    assert res.paths[0].evidence.target_already_touched is False

    assert res.paths[1].to_entity == "10.10.20.15"
    assert res.paths[1].evidence.target_already_touched is True
    assert res.paths[1].likelihood < res.paths[0].likelihood


def test_tactic_transition_support_logic():
    """Verify tactic_transition_support is True for forward stages and False for backward stages."""
    # Last tactic: credential_access -> forward to lateral_movement is True
    incident_forward = {
        "incident_id": "inc_fwd",
        "hosts": ["10.10.10.5"],
        "steps": [{"tactic": "credential_access", "first_seen": "2026-10-25T10:00:00Z"}],
    }
    candidate_edges = [{
        "src_host": "10.10.10.5",
        "tgt_host": "10.10.20.15",
        "dst_port": 445,
        "service": "smb",
        "count": 2,
    }]
    res_fwd = predict_next_paths(incident=incident_forward, candidate_edges=candidate_edges)
    assert res_fwd.paths[0].evidence.tactic_transition_support is True

    # Last tactic: impact (end of chain) -> backward to lateral_movement is False
    incident_backward = {
        "incident_id": "inc_bwd",
        "hosts": ["10.10.10.5"],
        "steps": [{"tactic": "impact", "first_seen": "2026-10-25T10:00:00Z"}],
    }
    res_bwd = predict_next_paths(incident=incident_backward, candidate_edges=candidate_edges)
    assert res_bwd.paths[0].evidence.tactic_transition_support is False


def test_cache_sub_10ms_latency():
    """Verify in-memory caching serves subsequent calls in < 10 ms."""
    incident_id = "inc_perf_test"
    duck.upsert_incident({
        "incident_id": incident_id,
        "title": "Performance Test",
        "severity": 3,
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:30:00Z",
        "hosts": ["10.10.10.5"],
        "src_ips": ["10.10.10.5"],
    })

    with duck.cursor() as con:
        con.execute("""
        INSERT INTO events (event_id, ts, src_ip, dst_ip, dst_port, service, action)
        VALUES ('ev_perf_1', '2026-10-25 10:15:00Z', '10.10.10.5', '10.10.20.50', 445, 'smb', 'accept')
        """)

    # First call populates cache
    res1 = get_predicted_next_paths(incident_id)
    assert res1 is not None

    # Second call must hit cache and return in < 10ms
    t0 = time.perf_counter()
    res2 = get_predicted_next_paths(incident_id)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    assert res2 is not None
    assert latency_ms < 10.0, f"Cache lookup took {latency_ms:.3f}ms (> 10ms)"
    assert res2.paths == res1.paths


def test_not_found_incident_returns_404(client):
    """Verify requesting a non-existent incident returns 404."""
    resp = client.get("/api/v1/incidents/inc_does_not_exist/next-paths")
    assert resp.status_code == 404
