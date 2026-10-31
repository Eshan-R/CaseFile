"""Integration tests for the DuckDB store."""

from __future__ import annotations

from datetime import UTC

import app.store.duck as duck
import pytest


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Each test gets its own in-memory DuckDB."""
    db_path = str(tmp_path / "test.duckdb")
    monkeypatch.setattr(duck, "_conn", None)
    # Override duck_path via settings
    from app.config import settings
    monkeypatch.setattr(settings, "duck_path", db_path)
    monkeypatch.setattr(settings, "parquet_dir", str(tmp_path / "parquet"))
    # Clear module-level connection
    duck._conn = None
    duck.init_db()
    yield
    if duck._conn:
        duck._conn.close()
        duck._conn = None


class TestNewId:
    def test_format(self):
        id_ = duck.new_id("job")
        assert id_.startswith("job_")
        # "job_" (4) + "_" (1) + 8 hex = 13, but prefix already includes underscore
        # new_id("job") → "job_" + 8hex = 12 chars
        parts = id_.split("_", 1)
        assert parts[0] == "job"
        assert len(parts[1]) == 8
        assert all(c in "0123456789abcdef" for c in parts[1])

    def test_unique(self):
        ids = {duck.new_id("x") for _ in range(100)}
        assert len(ids) == 100


class TestJobCrud:
    def test_insert_and_get(self):
        job_id = duck.new_id("job")
        duck.insert_job(job_id, "ingest", {"paths": ["/tmp/log"]})
        row = duck.get_job(job_id)
        assert row is not None
        assert row["job_id"] == job_id
        assert row["kind"] == "ingest"
        assert row["status"] == "queued"

    def test_update_status(self):
        job_id = duck.new_id("job")
        duck.insert_job(job_id, "analyse", {})
        duck.update_job(job_id, status="running", progress_pct=50.0)
        row = duck.get_job(job_id)
        assert row["status"] == "running"
        assert row["progress_pct"] == pytest.approx(50.0)

    def test_list_jobs_pagination(self):
        for _ in range(5):
            jid = duck.new_id("job")
            duck.insert_job(jid, "ingest", {})
        total, rows = duck.list_jobs(offset=0, limit=3)
        assert total == 5
        assert len(rows) == 3


class TestEventCrud:
    def test_insert_and_list(self):
        from datetime import datetime
        events = [
            {
                "event_id": f"ev_0_{i}",
                "ts": datetime.now(UTC),
                "host": "server-01",
                "source_file": "/logs/auth.log",
                "log_format": "syslog",
                "raw": f"raw line {i}",
            }
            for i in range(10)
        ]
        duck.insert_events_batch(events)
        total, rows = duck.list_events(host="server-01")
        assert total == 10
        assert all(r["host"] == "server-01" for r in rows)

    def test_get_event(self):
        from datetime import datetime
        duck.insert_events_batch([{
            "event_id": "ev_1_0",
            "ts": datetime.now(UTC),
            "host": "host-a",
            "source_file": "x.log",
            "log_format": "json",
            "raw": "{}",
        }])
        row = duck.get_event("ev_1_0")
        assert row is not None
        assert row["host"] == "host-a"

    def test_get_nonexistent(self):
        assert duck.get_event("ev_99_99") is None

    def test_count_events(self):
        assert duck.count_events() == 0
        from datetime import datetime
        duck.insert_events_batch([{
            "event_id": "ev_2_0",
            "ts": datetime.now(UTC),
            "host": "h",
            "source_file": "f",
            "log_format": "syslog",
            "raw": "r",
        }])
        assert duck.count_events() == 1


class TestIncidentCrud:
    def _sample_incident(self, iid: str) -> dict:
        from datetime import datetime
        now = datetime.now(UTC)
        return {
            "incident_id": iid,
            "title": "Test Incident",
            "severity": 7,
            "first_seen": now,
            "last_seen": now,
            "hosts": ["server-01"],
            "users": ["alice"],
            "src_ips": ["10.0.0.1"],
            "techniques": ["T1059.001", "T1053.005"],
            "steps": [],
            "detection_ids": [],
            "event_count": 5,
            "status": "open",
        }

    def test_upsert_and_get(self):
        iid = duck.new_id("inc")
        duck.upsert_incident(self._sample_incident(iid))
        row = duck.get_incident(iid)
        assert row is not None
        assert row["incident_id"] == iid
        assert row["severity"] == 7

    def test_list_incidents(self):
        for _ in range(3):
            duck.upsert_incident(self._sample_incident(duck.new_id("inc")))
        total, rows = duck.list_incidents()
        assert total == 3

    def test_set_graph(self):
        import json
        iid = duck.new_id("inc")
        duck.upsert_incident(self._sample_incident(iid))
        duck.set_incident_graph(iid, json.dumps({"nodes": [], "edges": []}))
        row = duck.get_incident(iid)
        assert row["graph_json"] is not None


class TestStatHelpers:
    def test_set_and_get(self):
        duck.set_stat("test_key", "test_value")
        assert duck.get_stat("test_key") == "test_value"

    def test_get_nonexistent(self):
        assert duck.get_stat("nonexistent") is None

    def test_overwrite(self):
        duck.set_stat("k", "v1")
        duck.set_stat("k", "v2")
        assert duck.get_stat("k") == "v2"


class TestResetAll:
    def test_reset_clears_data(self):
        from datetime import datetime
        duck.insert_events_batch([{
            "event_id": "ev_0_0",
            "ts": datetime.now(UTC),
            "host": "h",
            "source_file": "f",
            "log_format": "syslog",
            "raw": "r",
        }])
        assert duck.count_events() == 1
        duck.reset_all()
        assert duck.count_events() == 0
