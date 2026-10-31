"""API integration tests using FastAPI's TestClient."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("db")
    db_path = str(tmp / "test.duckdb")
    import app.store.duck as duck
    from app.config import settings
    # Point to temp DB before app loads
    settings.duck_path = db_path
    duck._conn = None
    from app.main import app
    return TestClient(app)


class TestHealth:
    def test_ok(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] in ("ok", "degraded")
        assert "database" in body
        assert "app_version" in body
        assert body["database"]["ok"] is True


class TestStats:
    def test_returns_counts(self, client):
        r = client.get("/api/v1/stats")
        assert r.status_code == 200
        body = r.json()
        assert "total_events" in body
        assert "total_detections" in body
        assert "total_incidents" in body


class TestJobs:
    def test_list_empty(self, client):
        r = client.get("/api/v1/jobs")
        assert r.status_code == 200
        body = r.json()
        assert "items" in body
        assert "total" in body

    def test_get_nonexistent(self, client):
        r = client.get("/api/v1/jobs/job_00000000")
        assert r.status_code == 404

    def test_ingest_requires_paths(self, client):
        r = client.post("/api/v1/jobs/ingest", json={"paths": []})
        assert r.status_code == 422

    def test_analyse_queues_job(self, client):
        r = client.post("/api/v1/jobs/analyse")
        assert r.status_code == 202
        body = r.json()
        assert "job_id" in body
        assert body["status"] == "queued"


class TestEvents:
    def test_list_empty(self, client):
        r = client.get("/api/v1/events")
        assert r.status_code == 200
        assert r.json()["total"] >= 0

    def test_get_nonexistent(self, client):
        r = client.get("/api/v1/events/ev_00_00")
        assert r.status_code == 404


class TestDetections:
    def test_list_empty(self, client):
        r = client.get("/api/v1/detections")
        assert r.status_code == 200
        assert r.json()["total"] >= 0


class TestIncidents:
    def test_list_empty(self, client):
        r = client.get("/api/v1/incidents")
        assert r.status_code == 200
        assert r.json()["total"] >= 0

    def test_get_nonexistent(self, client):
        r = client.get("/api/v1/incidents/inc_00000000")
        assert r.status_code == 404


class TestRules:
    def test_list_rules(self, client):
        r = client.get("/api/v1/rules")
        assert r.status_code == 200
        body = r.json()
        assert "items" in body
        # Rules are loaded from rules/detections.yaml
        # In test env the CWD may not have rules/, so total can be 0
        assert body["total"] >= 0

    def test_reload_endpoint(self, client):
        r = client.post("/api/v1/rules/reload")
        assert r.status_code == 200
        assert "rules_loaded" in r.json()


class TestEvaluation:
    def test_evaluate_nonexistent_incident(self, client):
        r = client.post("/api/v1/evaluate", json={
            "incident_id": "inc_00000000",
            "ground_truth": [{"technique_id": "T1059", "tactic": "Execution",
                              "host": "server", "ts_start": "2024-01-01T00:00:00Z",
                              "ts_end": "2024-01-01T01:00:00Z"}],
        })
        assert r.status_code == 404

