"""Unit tests for SQL-based detection rules, population artifact guard, and near-miss validation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.pipeline.detect.engine import apply_population_guard, compile_rule_to_sql, execute_rule
from app.pipeline.detect.rule_loader import load_rules
from app.pipeline.link.incidents import build_incidents
from app.store import duck


@pytest.fixture(autouse=True)
def clean_test_db(tmp_path, monkeypatch):
    """Run tests in an isolated in-memory or temporary DuckDB database."""
    db_path = str(tmp_path / "test_sql_rules.duckdb")
    monkeypatch.setattr("app.config.settings.duck_path", db_path)
    monkeypatch.setattr("app.config.settings.parquet_dir", str(tmp_path / "empty_parquet"))
    duck.close()
    duck.init_db()
    yield
    duck.close()


def test_sql_rule_compilation():
    """Verify all SQL rules load from YAML and compile to SQL statements."""
    rules = load_rules("rules")
    sql_rules = [r for r in rules if r.type == "sql"]
    assert len(sql_rules) >= 20
    valid_cols = duck.get_events_columns()

    for r in sql_rules:
        sql = compile_rule_to_sql(r, valid_cols)
        assert sql is not None, f"Rule {r.id} failed to compile"
        assert "SELECT" in sql.upper()
        assert "events" in sql.lower()


def test_planted_failed_admin_burst():
    """Planted case: 500 failed admin logins in 10 minutes triggers failed-admin-burst."""
    rules = {r.id: r for r in load_rules("rules")}
    rule = rules.get("failed-admin-burst")
    assert rule is not None

    t0 = datetime(2026, 10, 27, 13, 0, 0, tzinfo=UTC)
    with duck.cursor() as con:
        rows = [
            (
                f"ev_burst_{i}",
                t0 + timedelta(seconds=i),
                t0 + timedelta(seconds=i),
                i,
                "FGT01",
                "admin",
                "15.199.16.197",
                "10.10.99.1",
                "0100032002",
                "login",
                "failure",
            )
            for i in range(500)
        ]
        con.executemany(
            "INSERT INTO events (event_id, ts, timestamp, source_offset, host, user, src_ip, dst_ip, logid, action, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    valid_cols = duck.get_events_columns()
    r, matches, duration, status = execute_rule(rule, valid_cols)
    assert status == "OK"
    assert matches == 1
    total, dets = duck.list_detections()
    assert total == 1
    assert dets[0]["rule_id"] == "failed-admin-burst"
    assert not dets[0]["suppressed"]


def test_near_miss_failed_admin_burst():
    """Near miss: 499 failed logins (threshold 500) does not trigger detection."""
    rules = {r.id: r for r in load_rules("rules")}
    rule = rules.get("failed-admin-burst")
    assert rule is not None

    t0 = datetime(2026, 10, 27, 13, 0, 0, tzinfo=UTC)
    with duck.cursor() as con:
        rows = [
            (
                f"ev_near_{i}",
                t0 + timedelta(seconds=i),
                t0 + timedelta(seconds=i),
                i,
                "FGT01",
                "admin",
                "15.199.16.197",
                "10.10.99.1",
                "0100032002",
                "login",
                "failure",
            )
            for i in range(499)
        ]
        con.executemany(
            "INSERT INTO events (event_id, ts, timestamp, source_offset, host, user, src_ip, dst_ip, logid, action, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    valid_cols = duck.get_events_columns()
    r, matches, duration, status = execute_rule(rule, valid_cols)
    assert status == "OK"
    assert matches == 0
    total, _ = duck.list_detections()
    assert total == 0


def test_planted_web_payload_sqli():
    """Planted case: SQL injection web attack payloads detected."""
    rules = {r.id: r for r in load_rules("rules")}
    rule = rules.get("web-payload-sqli")
    assert rule is not None

    t0 = datetime(2026, 10, 27, 14, 0, 0, tzinfo=UTC)
    with duck.cursor() as con:
        rows = [
            (
                f"ev_sqli_{i}",
                t0 + timedelta(seconds=i * 2),
                t0 + timedelta(seconds=i * 2),
                i,
                "FGT01",
                "203.0.113.50",
                "10.0.0.25",
                f"/index.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--%20{i}",
                "HTTP.URI.SQL.Injection",
            )
            for i in range(10)
        ]
        con.executemany(
            "INSERT INTO events (event_id, ts, timestamp, source_offset, host, src_ip, dst_ip, url, attack) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    valid_cols = duck.get_events_columns()
    r, matches, duration, status = execute_rule(rule, valid_cols)
    assert status == "OK"
    assert matches >= 1
    total, dets = duck.list_detections()
    assert total >= 1
    assert any(d["rule_id"] == "web-payload-sqli" for d in dets)


def test_near_miss_web_payload_sqli():
    """Near miss: benign web requests with normal query parameters do not trigger."""
    rules = {r.id: r for r in load_rules("rules")}
    rule = rules.get("web-payload-sqli")
    assert rule is not None

    t0 = datetime(2026, 10, 27, 14, 0, 0, tzinfo=UTC)
    with duck.cursor() as con:
        rows = [
            (
                f"ev_benign_{i}",
                t0 + timedelta(seconds=i * 2),
                t0 + timedelta(seconds=i * 2),
                i,
                "FGT01",
                "203.0.113.50",
                "10.0.0.25",
                f"/index.php?page=products&category={i}",
            )
            for i in range(10)
        ]
        con.executemany(
            "INSERT INTO events (event_id, ts, timestamp, source_offset, host, src_ip, dst_ip, url) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    valid_cols = duck.get_events_columns()
    r, matches, duration, status = execute_rule(rule, valid_cols)
    assert status == "OK"
    assert matches == 0


def test_population_guard_distinct_sources_suppression():
    """Population guard: >= 10 distinct sources in a 15-minute window are flagged suppressed."""
    t0 = datetime(2026, 10, 30, 3, 18, 0, tzinfo=UTC)
    dets = [
        {
            "detection_id": f"det_pop_{i}",
            "rule_id": "failed-admin-burst",
            "host": f"192.0.2.{i}",
            "src_ip": f"192.0.2.{i}",
            "ts": t0 + timedelta(seconds=i * 10),
            "event_ids": [f"ev_{i}"],
            "suppressed": False,
        }
        for i in range(15)  # 15 distinct sources within 150 seconds <= 15 mins
    ]

    suppressed_cnt = apply_population_guard(dets)
    assert suppressed_cnt == 15
    for d in dets:
        assert d["suppressed"] is True
        assert "distinct_sources" in d["suppress_reason"]


def test_population_guard_near_miss_distinct_sources():
    """Population guard near miss: 9 distinct sources (< 10) in 15 minutes are not suppressed."""
    t0 = datetime(2026, 10, 30, 3, 18, 0, tzinfo=UTC)
    dets = [
        {
            "detection_id": f"det_few_{i}",
            "rule_id": "failed-admin-burst",
            "host": f"192.0.2.{i}",
            "src_ip": f"192.0.2.{i}",
            "ts": t0 + timedelta(seconds=i * 30),
            "event_ids": [f"ev_{i}"],
            "suppressed": False,
        }
        for i in range(9)  # 9 distinct sources
    ]

    suppressed_cnt = apply_population_guard(dets)
    assert suppressed_cnt == 0
    for d in dets:
        assert d["suppressed"] is False
        assert d.get("suppress_reason") is None


def test_population_guard_1sec_burst_suppression():
    """Population guard: rule events in 1-second bucket holding > 200 events are suppressed."""
    t0 = datetime(2026, 10, 30, 3, 18, 25, tzinfo=UTC)
    dets = [
        {
            "detection_id": "det_burst_1s",
            "rule_id": "failed-admin-burst",
            "host": "198.51.100.1",
            "src_ip": "198.51.100.1",
            "ts": t0,
            "t_start": t0,
            "t_end": t0,  # 0 second span
            "n_events": 250,  # > 200 events
            "event_ids": ["ev_1"],
            "suppressed": False,
        }
    ]

    suppressed_cnt = apply_population_guard(dets)
    assert suppressed_cnt == 1
    assert dets[0]["suppressed"] is True
    assert "1sec_bucket" in dets[0]["suppress_reason"]


def test_suppressed_detections_excluded_from_incident_linking():
    """Suppressed detections must never be linked into incidents."""
    t0 = datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC)

    det_active = {
        "detection_id": "det_active_1",
        "rule_id": "admin-login-external",
        "rule_name": "Admin Login",
        "technique_id": "T1078.001",
        "tactic": "initial_access",
        "severity": 8,
        "host": "10.0.0.1",
        "ts": t0,
        "event_ids": ["ev_act"],
        "suppressed": False,
    }
    det_suppressed = {
        "detection_id": "det_supp_1",
        "rule_id": "failed-admin-burst",
        "rule_name": "Failed Burst",
        "technique_id": "T1110.001",
        "tactic": "credential_access",
        "severity": 8,
        "host": "10.0.0.1",
        "ts": t0 + timedelta(minutes=5),
        "event_ids": ["ev_sup"],
        "suppressed": True,
        "suppress_reason": "population_artifact",
    }

    duck.insert_detection(det_active)
    duck.insert_detection(det_suppressed)

    _ = build_incidents()
    total_incs, incs = duck.list_incidents()
    # det_suppressed is excluded; only det_active remains
    for inc in incs:
        det_ids = inc.get("detection_ids", [])
        assert "det_supp_1" not in det_ids


def test_all_rules_emit_subtechniques():
    """Verify that every rule emits a sub-technique (contains '.') where a sub-technique exists in knowledge/attack_tactics.yaml."""
    import yaml
    with open("knowledge/attack_tactics.yaml", encoding="utf-8") as f:
        tactics = yaml.safe_load(f)
    sub_techs = {k for k in tactics.keys() if "." in k}
    parent_techs_with_subs = {k.split(".")[0] for k in sub_techs}

    rules = load_rules("rules")
    for r in rules:
        t_id = r.technique_id
        # Split multi-technique e.g. T1110.001+T1078.001
        for tid in t_id.split("+"):
            tid = tid.strip()
            if tid in parent_techs_with_subs:
                pytest.fail(
                    f"Rule '{r.id}' emits parent technique '{tid}' without a sub-technique, "
                    f"but sub-techniques exist in knowledge/attack_tactics.yaml: "
                    f"{[s for s in sub_techs if s.startswith(tid + '.')]}. "
                    f"Rules must emit specific sub-techniques."
                )
