"""Unit tests for incident attack evidence logs API endpoint, severity calculations, and pagination."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app.api.routes.logs import router as logs_router
from app.main import create_app
from app.store import duck
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def clean_test_db(tmp_path, monkeypatch):
    """Run all tests against an isolated temporary DuckDB database to protect run.duckdb."""
    db_path = str(tmp_path / "test_attack_logs.duckdb")
    monkeypatch.setattr("app.config.settings.duck_path", db_path)
    monkeypatch.setattr("app.config.settings.parquet_dir", str(tmp_path / "empty_parquet"))
    duck.close()
    duck.init_db()
    with duck.cursor() as con:
        con.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS level TEXT;")
    yield
    duck.close()


@pytest.fixture
def client() -> TestClient:
    """Create a test client with logs router mounted before static files handler."""
    app = create_app()
    has_logs_route = any("/incidents/{id}/logs" in getattr(r, "path", "") for r in app.routes)
    if not has_logs_route:
        # Move static route to the end so it does not catch API routes
        static_idx = next((i for i, r in enumerate(app.routes) if getattr(r, "name", None) == "static"), None)
        static_route = app.routes.pop(static_idx) if static_idx is not None else None
        app.include_router(logs_router, prefix="/api/v1")
        app.include_router(logs_router)
        if static_route is not None:
            app.routes.append(static_route)
    return TestClient(app)


def test_empty_incident_returns_200_with_total_zero(client: TestClient):
    """GET /api/v1/incidents/{id}/logs on empty DB returns 200, total: 0, items: [], reason explanation."""
    resp = client.get("/api/v1/incidents/inc_nonexistent/logs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []
    assert data["counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert data["reason"] == "No evidence logs found for incident"


def test_incident_with_no_linked_events_returns_200(client: TestClient):
    """An incident that exists in DB but has no evidence events returns 200 with total: 0."""
    now = datetime.now(UTC).isoformat()
    with duck.cursor() as con:
        con.execute(
            """
            INSERT INTO incidents (incident_id, title, severity, risk_score, first_seen, last_seen, detection_ids, event_count)
            VALUES ('inc_empty', 'Empty Incident', 5, 50.0, ?, ?, '[]', 0)
            """,
            [now, now],
        )

    resp = client.get("/api/v1/incidents/inc_empty/logs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []
    assert data["reason"] == "No evidence logs found for incident"


def _seed_incident_with_logs():
    """Helper to seed an incident with diverse events, detections, and severity levels."""
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    t1 = datetime(2026, 10, 23, 10, 1, 0, tzinfo=UTC)
    t2 = datetime(2026, 10, 23, 10, 2, 0, tzinfo=UTC)
    t3 = datetime(2026, 10, 23, 10, 3, 0, tzinfo=UTC)
    t4 = datetime(2026, 10, 23, 10, 4, 0, tzinfo=UTC)
    t5 = datetime(2026, 10, 23, 10, 5, 0, tzinfo=UTC)

    with duck.cursor() as con:
        # 1. Insert events
        # ev_1: level='alert' -> mapped FortiGate severity = 9 (critical), no detection
        con.execute(
            """
            INSERT INTO events (event_id, ts, timestamp, host, src_ip, dst_ip, dst_port, action, attack, level, severity, raw, source_offset)
            VALUES ('ev_1', ?, ?, 'host-01', '10.10.10.1', '10.10.20.1', 443, 'drop', 'IPS_Alert', 'alert', 'alert', 'raw log 1', 100)
            """,
            [t0, t0.isoformat()],
        )

        # ev_2: level='notice' (2: low), cited by det_1 (severity 8: high) -> effective_severity = max(8, 2) = 8 (high)
        con.execute(
            """
            INSERT INTO events (event_id, ts, timestamp, host, src_ip, dst_ip, dst_port, action, attack, level, severity, raw, source_offset)
            VALUES ('ev_2', ?, ?, 'host-01', '10.10.10.2', '10.10.20.2', 80, 'accept', 'SQL_Inject', 'notice', 'notice', 'raw log 2', 200)
            """,
            [t1, t1.isoformat()],
        )

        # ev_3: level='warning' (5: medium), cited by det_2 (severity 4) -> effective_severity = max(4, 5) = 5 (medium)
        con.execute(
            """
            INSERT INTO events (event_id, ts, timestamp, host, src_ip, dst_ip, dst_port, action, attack, level, severity, raw, source_offset)
            VALUES ('ev_3', ?, ?, 'host-02', '10.10.10.3', '10.10.20.3', 22, 'deny', NULL, 'warning', 'warning', 'raw log 3', 300)
            """,
            [t2, t2.isoformat()],
        )

        # ev_4: level='notice' (2: low), no detections -> effective_severity = 2 (low)
        con.execute(
            """
            INSERT INTO events (event_id, ts, timestamp, host, src_ip, dst_ip, dst_port, action, attack, level, severity, raw, source_offset)
            VALUES ('ev_4', ?, ?, 'host-02', '10.10.10.4', '10.10.20.4', 53, 'pass', NULL, 'notice', 'notice', 'raw log 4', 400)
            """,
            [t3, t3.isoformat()],
        )

        # ev_5: level='information' (0: info), no detections -> effective_severity = 0 (info)
        con.execute(
            """
            INSERT INTO events (event_id, ts, timestamp, host, src_ip, dst_ip, dst_port, action, attack, level, severity, raw, source_offset)
            VALUES ('ev_5', ?, ?, 'host-03', '10.10.10.5', '10.10.20.5', 8080, 'accept', NULL, 'information', 'information', 'raw log 5', 500)
            """,
            [t4, t4.isoformat()],
        )

        # ev_6: level='warning' (5: medium), cited by det_3 (severity 10: critical) -> effective_severity = 10 (critical)
        con.execute(
            """
            INSERT INTO events (event_id, ts, timestamp, host, src_ip, dst_ip, dst_port, action, attack, level, severity, raw, source_offset)
            VALUES ('ev_6', ?, ?, 'host-03', '10.10.10.6', '10.10.20.6', 445, 'drop', 'SMB_Exploit', 'warning', 'warning', 'raw log 6', 600)
            """,
            [t5, t5.isoformat()],
        )

        # 2. Insert detections
        con.execute(
            """
            INSERT INTO detections (detection_id, rule_id, rule_name, technique_id, tactic, severity, host, ts, event_ids, incident_id)
            VALUES ('det_1', 'rule-sqli', 'SQL Injection Rule', 'T1190', 'Initial Access', 8, 'host-01', ?, '["ev_2"]', 'inc_test_100')
            """,
            [t1],
        )
        con.execute(
            """
            INSERT INTO detections (detection_id, rule_id, rule_name, technique_id, tactic, severity, host, ts, event_ids, incident_id)
            VALUES ('det_2', 'rule-portscan', 'Port Scan Detection', 'T1046', 'Discovery', 4, 'host-02', ?, '["ev_3"]', 'inc_test_100')
            """,
            [t2],
        )
        con.execute(
            """
            INSERT INTO detections (detection_id, rule_id, rule_name, technique_id, tactic, severity, host, ts, event_ids, incident_id)
            VALUES ('det_3', 'rule-lateral', 'EternalBlue Exploit', 'T1210', 'Lateral Movement', 10, 'host-03', ?, '["ev_6"]', 'inc_test_100')
            """,
            [t5],
        )

        # 3. Insert detection_events
        con.execute("INSERT INTO detection_events (detection_id, event_id, technique_id, tactic) VALUES ('det_1', 'ev_2', 'T1190', 'Initial Access')")
        con.execute("INSERT INTO detection_events (detection_id, event_id, technique_id, tactic) VALUES ('det_2', 'ev_3', 'T1046', 'Discovery')")
        con.execute("INSERT INTO detection_events (detection_id, event_id, technique_id, tactic) VALUES ('det_3', 'ev_6', 'T1210', 'Lateral Movement')")

        # 4. Insert incident and incident_events
        con.execute(
            """
            INSERT INTO incidents (incident_id, title, severity, risk_score, first_seen, last_seen, detection_ids, event_count)
            VALUES ('inc_test_100', 'Test Intrusion Campaign', 9, 88.0, ?, ?, '["det_1", "det_2", "det_3"]', 6)
            """,
            [t0, t5],
        )
        for eid in ["ev_1", "ev_2", "ev_3", "ev_4", "ev_5", "ev_6"]:
            con.execute("INSERT INTO incident_events (incident_id, event_id) VALUES ('inc_test_100', ?)", [eid])


def test_event_severity_mapping_and_counts(client: TestClient):
    """Verify effective_severity formula and total severity counts across incident logs."""
    _seed_incident_with_logs()

    resp = client.get("/api/v1/incidents/inc_test_100/logs")
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] == 6
    assert data["reason"] is None
    # Counts across ALL logs:
    # ev_1: alert -> critical (1)
    # ev_2: notice(2) + det(8) -> high (1)
    # ev_3: warning(5) + det(4) -> medium (1)
    # ev_4: notice(2) -> low (1)
    # ev_5: info(0) -> info (1)
    # ev_6: warning(5) + det(10) -> critical (1)
    assert data["counts"]["critical"] == 2
    assert data["counts"]["high"] == 1
    assert data["counts"]["medium"] == 1
    assert data["counts"]["low"] == 1
    assert data["counts"]["info"] == 1

    # Verify individual item properties
    items_by_id = {it["event_id"]: it for it in data["items"]}

    # ev_1
    assert items_by_id["ev_1"]["effective_severity"] == 9
    assert items_by_id["ev_1"]["severity_label"] == "critical"
    assert items_by_id["ev_1"]["detections"] == []
    assert items_by_id["ev_1"]["src_ip"] == "10.10.10.1"
    assert items_by_id["ev_1"]["dst_ip"] == "10.10.20.1"
    assert items_by_id["ev_1"]["dst_port"] == 443
    assert items_by_id["ev_1"]["attack"] == "IPS_Alert"

    # ev_2
    assert items_by_id["ev_2"]["effective_severity"] == 8
    assert items_by_id["ev_2"]["severity_label"] == "high"
    assert len(items_by_id["ev_2"]["detections"]) == 1
    det = items_by_id["ev_2"]["detections"][0]
    assert det["rule_id"] == "rule-sqli"
    assert det["rule_name"] == "SQL Injection Rule"
    assert det["technique_id"] == "T1190"
    assert det["severity"] == 8

    # ev_3
    assert items_by_id["ev_3"]["effective_severity"] == 5
    assert items_by_id["ev_3"]["severity_label"] == "medium"

    # ev_4
    assert items_by_id["ev_4"]["effective_severity"] == 2
    assert items_by_id["ev_4"]["severity_label"] == "low"

    # ev_5
    assert items_by_id["ev_5"]["effective_severity"] == 0
    assert items_by_id["ev_5"]["severity_label"] == "info"

    # ev_6
    assert items_by_id["ev_6"]["effective_severity"] == 10
    assert items_by_id["ev_6"]["severity_label"] == "critical"


def test_pagination_limit_and_offset(client: TestClient):
    """Verify limit and offset pagination parameters on incident logs."""
    _seed_incident_with_logs()

    # First page: 2 items
    resp1 = client.get("/api/v1/incidents/inc_test_100/logs?limit=2&offset=0")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["total"] == 6
    assert len(data1["items"]) == 2
    assert [it["event_id"] for it in data1["items"]] == ["ev_1", "ev_2"]

    # Second page: 2 items
    resp2 = client.get("/api/v1/incidents/inc_test_100/logs?limit=2&offset=2")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["total"] == 6
    assert len(data2["items"]) == 2
    assert [it["event_id"] for it in data2["items"]] == ["ev_3", "ev_4"]

    # Third page: last 2 items
    resp3 = client.get("/api/v1/incidents/inc_test_100/logs?limit=2&offset=4")
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert data3["total"] == 6
    assert len(data3["items"]) == 2
    assert [it["event_id"] for it in data3["items"]] == ["ev_5", "ev_6"]

    # Offset beyond total
    resp_empty = client.get("/api/v1/incidents/inc_test_100/logs?limit=10&offset=100")
    assert resp_empty.status_code == 200
    data_empty = resp_empty.json()
    assert data_empty["total"] == 6
    assert len(data_empty["items"]) == 0


def test_severity_filter_query_param(client: TestClient):
    """Verify filtering by severity label ('critical', 'high', etc.) preserves overall counts."""
    _seed_incident_with_logs()

    # Filter critical
    resp_crit = client.get("/api/v1/incidents/inc_test_100/logs?severity=critical")
    assert resp_crit.status_code == 200
    data_crit = resp_crit.json()
    assert data_crit["total"] == 2
    assert len(data_crit["items"]) == 2
    assert [it["event_id"] for it in data_crit["items"]] == ["ev_1", "ev_6"]
    # Counts remain full incident counts
    assert data_crit["counts"]["critical"] == 2
    assert data_crit["counts"]["high"] == 1
    assert data_crit["counts"]["medium"] == 1

    # Filter high (case insensitive)
    resp_high = client.get("/api/v1/incidents/inc_test_100/logs?severity=HIGH")
    assert resp_high.status_code == 200
    data_high = resp_high.json()
    assert data_high["total"] == 1
    assert len(data_high["items"]) == 1
    assert data_high["items"][0]["event_id"] == "ev_2"
    assert data_high["items"][0]["severity_label"] == "high"

    # Filter medium
    resp_med = client.get("/api/v1/incidents/inc_test_100/logs?severity=medium")
    assert resp_med.status_code == 200
    data_med = resp_med.json()
    assert data_med["total"] == 1
    assert data_med["items"][0]["event_id"] == "ev_3"

    # Filter info
    resp_info = client.get("/api/v1/incidents/inc_test_100/logs?severity=info")
    assert resp_info.status_code == 200
    data_info = resp_info.json()
    assert data_info["total"] == 1
    assert data_info["items"][0]["event_id"] == "ev_5"


def test_fallback_via_detections_event_ids_when_no_incident_events(client: TestClient):
    """When incident_events is not populated, events are discovered via detections.event_ids."""
    t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)

    with duck.cursor() as con:
        # Event exists
        con.execute(
            """
            INSERT INTO events (event_id, ts, timestamp, host, src_ip, dst_ip, dst_port, action, attack, level, severity, raw, source_offset)
            VALUES ('ev_fallback_1', ?, ?, 'srv-01', '1.2.3.4', '10.0.0.1', 443, 'accept', 'RCE', 'critical', 'critical', 'raw fallback', 1)
            """,
            [t0, t0.isoformat()],
        )
        # Detection cites event_id via event_ids JSON array and links to incident_id
        con.execute(
            """
            INSERT INTO detections (detection_id, rule_id, rule_name, technique_id, tactic, severity, host, ts, event_ids, incident_id)
            VALUES ('det_fb', 'rule-rce', 'Remote Code Exec', 'T1203', 'Execution', 9, 'srv-01', ?, '["ev_fallback_1"]', 'inc_fallback')
            """,
            [t0],
        )

    # Note: No rows in incident_events or detection_events
    resp = client.get("/api/v1/incidents/inc_fallback/logs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["event_id"] == "ev_fallback_1"
    assert data["items"][0]["effective_severity"] == 9
    assert data["items"][0]["severity_label"] == "critical"
    assert len(data["items"][0]["detections"]) == 1
    assert data["items"][0]["detections"][0]["rule_id"] == "rule-rce"


def test_direct_route_without_prefix(client: TestClient):
    """Verify endpoint is also accessible via direct /incidents/{id}/logs."""
    _seed_incident_with_logs()
    resp = client.get("/incidents/inc_test_100/logs?limit=3")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 6
    assert len(data["items"]) == 3
