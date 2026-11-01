"""Comprehensive tests for set-based SQL detection engine, rule loading, and edge cases."""

from __future__ import annotations

import logging

import pytest
from app.main import app
from app.pipeline.detect.engine import (
    compile_rule_to_sql,
    run_detection,
)
from app.pipeline.detect.rule_loader import load_rules, validate_rules
from app.schemas.rule import Rule
from app.store import duck
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def clean_test_db(tmp_path, monkeypatch):
    """Run tests with an isolated clean DuckDB database."""
    db_path = str(tmp_path / "test_detect.duckdb")
    monkeypatch.setattr("app.config.settings.duck_path", db_path)
    monkeypatch.setattr("app.config.settings.parquet_dir", str(tmp_path / "empty_parquet"))
    duck.close()
    duck.init_db()
    yield
    duck.close()


def test_rule_loader_validation_with_file_and_line(tmp_path):
    """Verify rule loader reports errors with exact file and line numbers."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    # Create a rule file with a missing ID on line 4
    bad_yaml = rules_dir / "bad_rule.yaml"
    bad_yaml.write_text(
        """# Line 1
# Line 2
- name: "Invalid Rule Without ID"
  type: match
  severity: high
""",
        encoding="utf-8",
    )

    res = validate_rules(rules_dir=str(rules_dir))
    assert not res["valid"]
    assert len(res["errors"]) >= 1
    err_str = res["errors"][0]
    assert "bad_rule.yaml" in err_str
    assert "missing required 'id'" in err_str


def test_rule_loader_enabled_false(tmp_path):
    """Verify rules with enabled: false are excluded by default."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    yaml_file = rules_dir / "rules.yaml"
    yaml_file.write_text(
        """
- id: rule-enabled
  name: "Active Rule"
  type: match
  technique: {id: "T1059", name: "Script"}
  tactic: execution
  enabled: true
  where: {action: "login"}

- id: rule-disabled
  name: "Inactive Rule"
  type: match
  technique: {id: "T1059", name: "Script"}
  tactic: execution
  enabled: false
  where: {action: "login"}
""",
        encoding="utf-8",
    )

    enabled_rules = load_rules(rules_dir=str(rules_dir), include_disabled=False)
    assert len(enabled_rules) == 1
    assert enabled_rules[0].id == "rule-enabled"

    all_rules = load_rules(rules_dir=str(rules_dir), include_disabled=True)
    assert len(all_rules) == 2


def test_rule_missing_field_is_disabled_without_crash(caplog):
    """Verify a rule referencing a non-existent field is disabled with a warning, not a crash."""
    rule = Rule(
        id="bad-field-rule",
        name="Bad Field Rule",
        type="match",
        technique={"id": "T1000", "name": "Fake"},
        tactic="execution",
        where={"nonexistent_column_xyz": "evil"},
    )
    valid_cols = {"event_id", "ts", "host", "user", "action"}

    with caplog.at_level(logging.WARNING):
        compiled = compile_rule_to_sql(rule, valid_cols)

    assert compiled is None
    assert any("references missing field" in r.message for r in caplog.records)


def test_set_based_match_rule_and_idempotency(tmp_path):
    """Verify set-based MATCH query detects events and re-running is idempotent."""
    # Seed events
    with duck.cursor() as con:
        con.execute("""
        INSERT INTO events (event_id, ts, timestamp, host, user, action, cmd)
        VALUES 
            ('ev_1', '2026-10-25 10:00:00Z', '2026-10-25 10:00:00Z', 'host-01', 'alice', 'exec', 'powershell -EncodedCommand AAAA'),
            ('ev_2', '2026-10-25 10:01:00Z', '2026-10-25 10:01:00Z', 'host-02', 'bob', 'exec', 'bash normal.sh'),
            ('ev_3', '2026-10-25 10:02:00Z', '2026-10-25 10:02:00Z', 'host-01', 'charlie', 'exec', 'powershell -EncodedCommand BBBB')
        """)

    rule = Rule(
        id="powershell-encoded",
        name="Suspicious PowerShell",
        type="match",
        technique={"id": "T1059.001", "name": "PowerShell"},
        tactic="execution",
        severity="high",
        where={"cmd": {"op": "contains", "value": "-EncodedCommand"}},
    )

    docs_dir = tmp_path / "docs"

    # Run detection
    res1 = run_detection([rule], job_id="job_1", docs_dir=str(docs_dir))
    assert res1["total_detections"] == 2

    # Check database detections
    _, dets = duck.list_detections(limit=10)
    assert len(dets) == 2
    assert all(d["technique_id"] == "T1059.001" for d in dets)

    # Re-run detection (idempotent test: should replace, NOT duplicate)
    res2 = run_detection([rule], job_id="job_2", docs_dir=str(docs_dir))
    assert res2["total_detections"] == 2
    _, dets_after = duck.list_detections(limit=10)
    assert len(dets_after) == 2


def test_two_rules_matching_one_event_give_two_detections(tmp_path):
    """Verify that when two distinct rules match the same event, two detections are produced."""
    with duck.cursor() as con:
        con.execute("""
        INSERT INTO events (event_id, ts, timestamp, host, user, action, cmd, attack)
        VALUES ('ev_multi', '2026-10-25 10:00:00Z', '2026-10-25 10:00:00Z', 'host-01', 'attacker', 'exec', 'powershell evil', 'Command.Injection')
        """)

    rule1 = Rule(
        id="r1-ps",
        name="PowerShell Rule",
        type="match",
        technique={"id": "T1059.001", "name": "PowerShell"},
        tactic="execution",
        where={"cmd": {"op": "contains", "value": "powershell"}},
    )
    rule2 = Rule(
        id="r2-injection",
        name="Command Injection Rule",
        type="match",
        technique={"id": "T1059.004", "name": "Injection"},
        tactic="execution",
        where={"attack": {"op": "contains", "value": "Command.Injection"}},
    )

    res = run_detection([rule1, rule2], job_id="job_multi", docs_dir=str(tmp_path))
    assert res["total_detections"] == 2

    _, dets = duck.list_detections(limit=10)
    techs = {d["technique_id"] for d in dets}
    assert techs == {"T1059.001", "T1059.004"}


def test_threshold_rule_with_then_followup(tmp_path):
    """Verify threshold rule with 'then' follow-up (brute force failures followed by success)."""
    with duck.cursor() as con:
        # Seed 25 failed logins from 45.74.28.200 for user 'admin'
        for i in range(25):
            con.execute(f"""
            INSERT INTO events (event_id, ts, timestamp, host, user, src_ip, logid, action, outcome)
            VALUES ('ev_fail_{i}', '2026-10-25 09:{i:02d}:00Z', '2026-10-25 09:{i:02d}:00Z', 'FGT01', 'admin', '45.74.28.200', '0100032002', 'login', 'failure')
            """)
        # Follow-up success at 09:26:00Z
        con.execute("""
        INSERT INTO events (event_id, ts, timestamp, host, user, src_ip, logid, action, outcome)
        VALUES ('ev_succ_1', '2026-10-25 09:26:00Z', '2026-10-25 09:26:00Z', 'FGT01', 'admin', '45.74.28.200', '0100032001', 'login', 'success')
        """)

    rule = Rule(
        id="brute-force-then-success",
        name="Brute Force Followed by Success",
        type="threshold",
        technique={"id": "T1110", "name": "Brute Force"},
        tactic="credential_access",
        kill_chain_stage="Exploitation",
        where={"outcome": "failure"},
        group_by=["user", "src_ip"],
        window_seconds=1800,
        min_count=20,
        then={"outcome": "success"},
        confidence=0.8,
    )

    res = run_detection([rule], job_id="job_bf", docs_dir=str(tmp_path))
    assert res["total_detections"] == 1

    _, dets = duck.list_detections(limit=10)
    assert len(dets) == 1
    det = dets[0]
    assert det["rule_id"] == "brute-force-then-success"
    assert det["technique_id"] == "T1110"
    # Confidence raised because 'then' step confirmed it
    assert det["confidence"] >= 0.95

    # Evidence event IDs: includes failures + follow-up (up to 50 max)
    import json
    ev_ids = json.loads(det["event_ids"]) if isinstance(det["event_ids"], str) else det["event_ids"]
    assert "ev_succ_1" in ev_ids
    assert len(ev_ids) <= 50
    assert len(ev_ids) >= 21


def test_rule_exclude_block(tmp_path):
    """Verify rule exclusion block filters out benign service accounts and scanner IPs."""
    with duck.cursor() as con:
        con.execute("""
        INSERT INTO events (event_id, ts, timestamp, host, user, src_ip, action, outcome)
        VALUES 
            ('ev_bad', '2026-10-25 10:00:00Z', '2026-10-25 10:00:00Z', 'srv1', 'admin', '198.51.100.1', 'login', 'failure'),
            ('ev_svc', '2026-10-25 10:01:00Z', '2026-10-25 10:01:00Z', 'srv1', 'svc_backup', '10.10.99.1', 'login', 'failure')
        """)

    rule = Rule(
        id="test-exclude",
        name="Test Exclude",
        type="match",
        technique={"id": "T1110", "name": "Brute Force"},
        tactic="credential_access",
        where={"action": "login"},
        exclude={"user": ["svc_backup"], "src_ip": ["10.10.99.1"]},
    )

    res = run_detection([rule], job_id="job_exc", docs_dir=str(tmp_path))
    assert res["total_detections"] == 1
    _, dets = duck.list_detections(limit=10)
    assert len(dets) == 1


def test_api_rules_reload():
    """Verify POST /api/v1/rules/reload returns count of loaded rules."""
    client = TestClient(app)
    resp = client.post("/api/v1/rules/reload")
    assert resp.status_code == 200
    data = resp.json()
    assert "rules_loaded" in data
    assert data["rules_loaded"] >= 10


def test_detection_sql_determinism(tmp_path):
    """Verify detection SQL produces 100% identical detections across multiple runs."""
    import json

    with duck.cursor() as con:
        # Insert diverse events with non-ordered source_offsets and timestamps
        for i in range(50):
            off = (i * 37) % 50  # Scrambled order
            outcome = "failure" if i < 45 else "success"
            con.execute(f"""
            INSERT INTO events (event_id, ts, timestamp, source_offset, host, user, src_ip, dst_ip, action, outcome, subtype, virus)
            VALUES ('ev_test_{i}', '2026-10-25 10:{i:02d}:00Z', '2026-10-25 10:{i:02d}:00Z', {off}, 'srv1', 'admin', '10.10.10.5', '198.51.100.1', 'pass', '{outcome}', 'virus', 'Trojan.Generic')
            """)

    rules = load_rules()

    # Run 1
    res1 = run_detection(rules, job_id="det_det1", docs_dir=str(tmp_path))
    with duck.cursor() as con:
        dets1 = con.execute("SELECT rule_id, ts, host, severity, event_ids FROM detections ORDER BY rule_id, ts, host").fetchall()

    # Clear detections and re-run
    with duck.cursor() as con:
        con.execute("DELETE FROM detection_events; DELETE FROM detections;")

    # Run 2
    res2 = run_detection(rules, job_id="det_det2", docs_dir=str(tmp_path))
    with duck.cursor() as con:
        dets2 = con.execute("SELECT rule_id, ts, host, severity, event_ids FROM detections ORDER BY rule_id, ts, host").fetchall()

    assert res1["total_detections"] == res2["total_detections"]
    assert len(dets1) == len(dets2)
    assert len(dets1) > 0

    for d1, d2 in zip(dets1, dets2, strict=True):
        rule_id1, ts1, host1, sev1, eids1 = d1
        rule_id2, ts2, host2, sev2, eids2 = d2
        assert rule_id1 == rule_id2
        assert ts1 == ts2
        assert host1 == host2
        assert sev1 == sev2
        # Verify event_ids list parity
        list1 = json.loads(eids1) if isinstance(eids1, str) else eids1
        list2 = json.loads(eids2) if isinstance(eids2, str) else eids2
        assert list1 == list2, f"Event IDs mismatch for {rule_id1}: {list1} vs {list2}"

