"""Tests for Phase 4 detection rules, FortiGate signals, missing column degradation, and rule stats."""

from __future__ import annotations

import pytest
from app.pipeline.detect.engine import (
    compile_rule_to_sql,
    execute_rule,
    write_rule_stats_report,
)
from app.pipeline.detect.rule_loader import load_rules, validate_rules
from app.schemas.rule import Rule
from app.store import duck


@pytest.fixture(autouse=True)
def clean_test_db(tmp_path, monkeypatch):
    """Run tests in an isolated in-memory or temporary DuckDB database."""
    db_path = str(tmp_path / "test_phase4.duckdb")
    monkeypatch.setattr("app.config.settings.duck_path", db_path)
    monkeypatch.setattr("app.config.settings.parquet_dir", str(tmp_path / "empty_parquet"))
    duck.close()
    duck.init_db()
    yield
    duck.close()


def test_all_yaml_rules_validate():
    """Verify all YAML rules in rules/ pass schema validation."""
    val = validate_rules("rules")
    assert val["valid"] is True, f"Validation errors: {val['errors']}"
    assert val["total_rules"] >= 12


def test_all_loaded_rules_compile_to_sql():
    """Verify every enabled rule in rules/ compiles to valid DuckDB SQL."""
    rules = load_rules("rules")
    valid_cols = duck.get_events_columns()
    compiled_count = 0

    for rule in rules:
        sql = compile_rule_to_sql(rule, valid_cols)
        if rule.enabled:
            # Should either compile to SQL string or gracefully return None if required fields missing
            if sql is not None:
                assert "SELECT" in sql
                compiled_count += 1

    assert compiled_count >= 10


def test_fortigate_signals_fire_matching_rules(tmp_path):
    """Test that synthetic events representing real FortiGate signals trigger their respective rules."""
    rules = load_rules("rules")
    rule_map = {r.id: r for r in rules}
    valid_cols = duck.get_events_columns()

    # 1. Seed events for multiple rules
    with duck.cursor() as con:
        # Large outbound transfer (sentbyte > 8.99MB)
        con.execute("""
        INSERT INTO events (event_id, ts, timestamp, host, user, src_ip, dst_ip, action, sentbyte, rcvdbyte)
        VALUES ('ev_large_out', '2026-10-30 08:00:00Z', '2026-10-30 08:00:00Z', 'FGT01', 'admin', '10.10.10.15', '203.0.113.5', 'accept', 12000000, 1024)
        """)

        # Targeted Web Attack (HTTP.URI.SQL.Injection)
        con.execute("""
        INSERT INTO events (event_id, ts, timestamp, host, user, src_ip, dst_ip, action, attack)
        VALUES ('ev_sqli', '2026-10-30 08:05:00Z', '2026-10-30 08:05:00Z', 'FGT01', 'attacker', '198.51.100.99', '10.10.20.10', 'detected', 'HTTP.URI.SQL.Injection')
        """)

        # Malware detection (JS/Nemucod.A!tr.dldr)
        con.execute("""
        INSERT INTO events (event_id, ts, timestamp, host, user, src_ip, dst_ip, subtype, action, virus)
        VALUES ('ev_malware', '2026-10-30 08:10:00Z', '2026-10-30 08:10:00Z', 'FGT01', 'victim', '10.10.10.20', '198.51.100.80', 'virus', 'blocked', 'JS/Nemucod.A!tr.dldr')
        """)

        # DNS Tunneling (doqotobitum.com)
        con.execute("""
        INSERT INTO events (event_id, ts, timestamp, host, user, src_ip, dst_ip, subtype, hostname)
        VALUES ('ev_dns', '2026-10-30 08:15:00Z', '2026-10-30 08:15:00Z', 'FGT01', 'host1', '10.10.10.50', '8.8.8.8', 'dns', '9hrdz764h5lc89p2j3zaratiiom507zgsx7shogz.doqotobitum.com')
        """)

        # Remote logon between hosts (RDP / dst_port 3389)
        con.execute("""
        INSERT INTO events (event_id, ts, timestamp, host, user, src_ip, dst_ip, dst_port, service)
        VALUES ('ev_rdp', '2026-10-30 08:20:00Z', '2026-10-30 08:20:00Z', 'FGT01', 'admin', '10.10.10.25', '10.10.20.15', 3389, 'RDP')
        """)

        # Valid account misuse (admin login from external IP)
        con.execute("""
        INSERT INTO events (event_id, ts, timestamp, host, user, src_ip, action, status)
        VALUES ('ev_admin_login', '2026-10-30 08:25:00Z', '2026-10-30 08:25:00Z', 'FGT01', 'admin', '198.51.100.44', 'login', 'success')
        """)

    # 2. Test execution of each rule individually
    test_rules = [
        ("large-outbound-transfer", "ev_large_out"),
        ("targeted-web-attack", "ev_sqli"),
        ("malware-detection", "ev_malware"),
        ("dns-tunneling", "ev_dns"),
        ("remote-logon-between-hosts", "ev_rdp"),
        ("valid-account-misuse", "ev_admin_login"),
    ]

    for rule_id, expected_ev in test_rules:
        rule = rule_map.get(rule_id)
        assert rule is not None, f"Rule {rule_id} missing from detections.yaml"
        r, matches, duration, status = execute_rule(rule, valid_cols)
        assert status == "OK", f"Rule {rule_id} status {status}"
        assert matches >= 1, f"Rule {rule_id} failed to match {expected_ev}"


def test_missing_field_graceful_degradation():
    """Verify rules with missing columns degrade gracefully in OR branches or disable without crashing."""
    valid_cols = {"event_id", "ts", "timestamp", "host", "user", "action", "msg", "logid"}

    # Rule with an OR branch having a missing column ('cmd') and a valid column ('msg')
    rule_or = Rule(
        id="degrade-or-test",
        name="Degrade OR Test",
        type="match",
        technique={"id": "T1136", "name": "Create Account"},
        tactic="persistence",
        where={
            "or": [
                {"field": "cmd", "op": "contains", "value": "useradd"},
                {"field": "msg", "op": "contains", "value": "add user"},
            ]
        },
    )
    sql_or = compile_rule_to_sql(rule_or, valid_cols)
    assert sql_or is not None
    assert "FALSE" in sql_or  # cmd branch degraded to FALSE
    assert "msg" in sql_or  # msg branch remains active

    # Rule with ONLY missing columns: must return None (disabled without crash)
    rule_all_missing = Rule(
        id="all-missing-test",
        name="All Missing Test",
        type="match",
        technique={"id": "T1059", "name": "Command Execution"},
        tactic="execution",
        where={
            "and": [
                {"field": "powershell_cmd", "op": "contains", "value": "Invoke-Expression"},
                {"field": "script_path", "op": "endswith", "value": ".ps1"},
            ]
        },
    )
    sql_missing = compile_rule_to_sql(rule_all_missing, valid_cols)
    assert sql_missing is None


def test_write_rule_stats_report(tmp_path):
    """Verify write_rule_stats_report generates a valid markdown summary."""
    stats = [
        {
            "rule_id": "rule-1",
            "name": "Rule 1",
            "type": "match",
            "technique": "T1110",
            "tactic": "credential_access",
            "stage": "Exploitation",
            "runtime": 0.05,
            "matches": 42,
            "status": "OK",
        },
        {
            "rule_id": "rule-2",
            "name": "Rule 2",
            "type": "threshold",
            "technique": "T1046",
            "tactic": "discovery",
            "stage": "Discovery",
            "runtime": 0.12,
            "matches": 0,
            "status": "OK",
        },
    ]

    report_file = tmp_path / "rule_stats.md"
    write_rule_stats_report(stats, docs_path=str(report_file))

    assert report_file.exists()
    content = report_file.read_text(encoding="utf-8")
    assert "# Detection Rules Execution Statistics" in content
    assert "`rule-1`" in content
    assert "42" in content
    assert "`rule-2`" in content
