"""Tests for pattern discovery persistence, exports, and REST API routes."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from app.config import settings
from app.main import create_app
from app.pipeline.patterns.base import PatternCandidate
from app.pipeline.patterns.exporter import (
    export_iocs_csv,
    export_patterns_json,
    export_patterns_yaml,
    extract_iocs_from_patterns,
)
from app.store import duck
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_pat_api.duckdb")
    monkeypatch.setattr(settings, "duck_path", test_db)
    duck.close()
    duck.init_db()
    yield
    duck.close()


@pytest.fixture
def sample_patterns():
    t0 = datetime(2026, 10, 26, 10, 0, 0, tzinfo=UTC)
    p1 = PatternCandidate(
        pattern_id="pat_test_001",
        kind="burst",
        title="Authentication Burst from 192.168.1.100",
        support=45,
        score=8.5,
        first_seen=t0,
        last_seen=t0,
        entities=["src_ip:192.168.1.100", "dst_ip:10.0.0.1"],
        example_event_ids=["ev_1", "ev_2"],
        suggested_technique="T1110",
        suggested_tactic="Credential Access",
        details_json={"distinct_dst_ports": 1, "peak_rate_eps": 5.2},
    )
    p2 = PatternCandidate(
        pattern_id="pat_test_002",
        kind="rarity",
        title="High-Entropy DGA Hostname: evil-c2-tunnel.net",
        support=3,
        score=9.2,
        first_seen=t0,
        last_seen=t0,
        entities=["dst_ip:8.8.8.8"],
        example_event_ids=["ev_3"],
        suggested_technique="T1568",
        suggested_tactic="Command and Control",
        details_json={"dimension": "hostname", "value": "evil-c2-tunnel.net", "entropy": 4.12},
    )
    duck.save_patterns_batch([p1, p2])
    return [p1, p2]


def test_pattern_persistence_and_status_preservation(sample_patterns):
    p = duck.get_pattern("pat_test_001")
    assert p is not None
    assert p["pattern_id"] == "pat_test_001"
    assert p["status"] == "new"
    assert isinstance(p["entities"], list)
    assert "src_ip:192.168.1.100" in p["entities"]
    assert p["score"] == 8.5

    # Update status to approved
    assert duck.update_pattern_status("pat_test_001", "approved") is True
    p_approved = duck.get_pattern("pat_test_001")
    assert p_approved["status"] == "approved"

    # Re-mining: re-upsert with default status 'new', status MUST remain 'approved'!
    re_mined = PatternCandidate(
        pattern_id="pat_test_001",
        kind="burst",
        title="Authentication Burst from 192.168.1.100 (Re-mined)",
        support=50,
        score=8.8,
        status="new",
    )
    duck.upsert_pattern(re_mined)
    p_remined = duck.get_pattern("pat_test_001")
    assert p_remined["status"] == "approved"
    assert p_remined["support"] == 50
    assert p_remined["title"] == "Authentication Burst from 192.168.1.100 (Re-mined)"


def test_pattern_listing_and_filtering(sample_patterns):
    total, items = duck.list_patterns()
    assert total == 2
    assert len(items) == 2
    # Ordered by score DESC
    assert items[0]["pattern_id"] == "pat_test_002"
    assert items[1]["pattern_id"] == "pat_test_001"

    # Filter by kind
    t_burst, items_burst = duck.list_patterns(kind="burst")
    assert t_burst == 1
    assert items_burst[0]["kind"] == "burst"

    # Filter by status
    duck.update_pattern_status("pat_test_001", "approved")
    t_app, items_app = duck.list_patterns(status="approved")
    assert t_app == 1
    assert items_app[0]["pattern_id"] == "pat_test_001"


def test_exporter_utilities(tmp_path, sample_patterns):
    json_path = str(tmp_path / "patterns.json")
    yaml_path = str(tmp_path / "patterns.yaml")
    csv_path = str(tmp_path / "iocs.csv")

    export_patterns_json(output_path=json_path)
    assert os.path.exists(json_path)
    assert os.path.getsize(json_path) > 0

    export_patterns_yaml(output_path=yaml_path)
    assert os.path.exists(yaml_path)
    assert os.path.getsize(yaml_path) > 0

    export_iocs_csv(output_path=csv_path)
    assert os.path.exists(csv_path)
    assert os.path.getsize(csv_path) > 0

    iocs = extract_iocs_from_patterns()
    values = [i["ioc_value"] for i in iocs]
    assert "192.168.1.100" in values
    assert "evil-c2-tunnel.net" in values


def test_patterns_api_endpoints(sample_patterns):
    app = create_app()
    client = TestClient(app)

    # 1. List patterns
    resp = client.get("/api/v1/patterns")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2

    # 2. Get specific pattern
    resp_get = client.get("/api/v1/patterns/pat_test_001")
    assert resp_get.status_code == 200
    assert resp_get.json()["pattern_id"] == "pat_test_001"

    resp_404 = client.get("/api/v1/patterns/pat_nonexistent")
    assert resp_404.status_code == 404

    # 3. Approve pattern
    resp_app = client.post("/api/v1/patterns/pat_test_001/approve")
    assert resp_app.status_code == 200
    assert resp_app.json()["approval_status"] == "approved"
    assert client.get("/api/v1/patterns/pat_test_001").json()["status"] == "approved"

    # 4. Reject pattern
    resp_rej = client.post("/api/v1/patterns/pat_test_001/reject")
    assert resp_rej.status_code == 200
    assert resp_rej.json()["approval_status"] == "rejected"
    assert client.get("/api/v1/patterns/pat_test_001").json()["status"] == "rejected"

    # 5. Export endpoints
    resp_json = client.get("/api/v1/patterns/export/json")
    assert resp_json.status_code == 200
    assert resp_json.headers["content-type"] == "application/json"

    resp_yaml = client.get("/api/v1/patterns/export/yaml")
    assert resp_yaml.status_code == 200

    resp_iocs = client.get("/api/v1/patterns/export/iocs")
    assert resp_iocs.status_code == 200
    assert "text/csv" in resp_iocs.headers["content-type"]
