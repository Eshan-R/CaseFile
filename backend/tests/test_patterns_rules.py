"""Tests for rule candidate synthesis, SQL compilation, noise guard, and tuning advisor."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import duckdb
import pytest
from app.pipeline.detect.rule_loader import validate_rules
from app.pipeline.patterns.base import PatternCandidate
from app.pipeline.patterns.rule_gen import (
    dry_run_rule,
    export_discovered_rules,
    pattern_to_rule_candidate,
)
from app.pipeline.patterns.tune_report import generate_tuning_report
from app.schemas.rule import Rule, RuleCondition
from app.store.duck import CREATE_EVENTS_TABLE_DDL


@pytest.fixture
def mock_db():
    con = duckdb.connect(":memory:")
    con.execute(CREATE_EVENTS_TABLE_DDL)
    t0 = datetime(2026, 10, 26, 10, 0, 0, tzinfo=UTC)

    # Insert 25 events for auth burst
    events = []
    for i in range(25):
        events.append((
            f"ev_b_{i}",
            t0,
            t0.isoformat(),
            "192.168.1.50",
            "10.0.0.5",
            22,
            "0100032002",
            "deny",
            "password_invalid",
            i,
        ))

    # Insert 1,500 generic noisy events to test noise guard rejection
    for i in range(1500):
        events.append((
            f"ev_noisy_{i}",
            t0,
            t0.isoformat(),
            f"10.0.1.{i % 200}",
            "10.0.0.1",
            80,
            "0000000013",
            "accept",
            "traffic",
            100 + i,
        ))

    con.executemany(
        """
        INSERT INTO events (
            event_id, ts, timestamp, src_ip, dst_ip, dst_port, logid, action, reason, source_offset
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        events,
    )
    return con


def test_pattern_to_rule_candidate_no_hardcoded_iocs():
    # 1. Burst pattern with IP entity
    burst = PatternCandidate(
        pattern_id="pat_burst_99",
        kind="burst",
        title="Auth burst from 192.168.1.50",
        support=30,
        score=9.0,
        entities=["src_ip:192.168.1.50"],
        details_json={"event_class": "auth_failed"},
    )
    rule = pattern_to_rule_candidate(burst)
    assert rule is not None
    assert rule.id == "disc_burst_99"
    assert rule.type == "threshold"
    assert rule.group_by == ["src_ip"]

    # Verify NO specific IP is hard-coded in rule conditions!
    for cond in rule.conditions:
        assert cond.field != "src_ip"
        assert cond.value != "192.168.1.50"

    # 2. Coordinated pattern
    coord = PatternCandidate(
        pattern_id="pat_coord_12",
        kind="coordinated",
        title="Coordinated scan on 10.0.0.5",
        support=50,
        score=8.5,
        entities=["dst_ip:10.0.0.5"],
        details_json={"target_ip": "10.0.0.5", "distinct_sources": 3},
    )
    rule_coord = pattern_to_rule_candidate(coord)
    assert rule_coord is not None
    assert rule_coord.type == "threshold"
    assert rule_coord.group_by == ["dst_ip"]
    assert rule_coord.min_distinct_field == "src_ip"

    for cond in rule_coord.conditions:
        assert cond.value != "10.0.0.5"


def test_noise_guard_dry_run(mock_db):
    # Rule 1: Selective threshold rule (should pass)
    safe_rule = Rule(
        id="disc_safe_auth",
        name="Safe Auth Burst",
        type="threshold",
        technique_id="T1110",
        tactic="Credential Access",
        conditions=[
            RuleCondition(field="logid", op="eq", value="0100032002"),
        ],
        group_by=["src_ip"],
        window_seconds=300,
        min_count=20,
    )
    res_safe = dry_run_rule(safe_rule, mock_db)
    assert res_safe["passed"] is True
    assert res_safe["match_count"] >= 1

    # Rule 2: Overly noisy rule matching 1,500 events (should trigger noise guard)
    noisy_rule = Rule(
        id="disc_noisy_traffic",
        name="Noisy Accept Rule",
        type="match",
        technique_id="T1071",
        tactic="Command and Control",
        conditions=[
            RuleCondition(field="action", op="eq", value="accept"),
        ],
    )
    res_noisy = dry_run_rule(noisy_rule, mock_db)
    assert res_noisy["passed"] is False
    assert res_noisy["match_count"] == 1500
    assert "Noise guard triggered" in res_noisy["reason"]


def test_export_discovered_rules_validity(tmp_path):
    out_file = str(tmp_path / "discovered.yaml")
    rule = Rule(
        id="disc_export_001",
        name="Exported Discovered Rule",
        type="threshold",
        technique_id="T1110",
        tactic="Credential Access",
        conditions=[
            RuleCondition(field="logid", op="eq", value="0100032002"),
        ],
        group_by=["src_ip"],
        window_seconds=300,
        min_count=20,
    )
    export_discovered_rules([rule], output_path=out_file)
    assert os.path.exists(out_file)

    # Validate using the production rule_loader
    val_res = validate_rules(rules_dir=str(tmp_path))
    assert val_res["valid"] is True
    assert val_res["total_rules"] == 1
    assert val_res["rules"][0]["id"] == "disc_export_001"


def test_tuning_report(tmp_path, mock_db):
    report_file = str(tmp_path / "tune_report.json")
    safe_rule = Rule(
        id="disc_safe_auth",
        name="Safe Auth Burst",
        type="threshold",
        technique_id="T1110",
        tactic="Credential Access",
        conditions=[
            RuleCondition(field="logid", op="eq", value="0100032002"),
        ],
        group_by=["src_ip"],
        window_seconds=300,
        min_count=20,
    )
    summary = generate_tuning_report([safe_rule], con=mock_db, output_path=report_file)
    assert summary["total_rules_evaluated"] == 1
    assert summary["safe_rules"] == 1
    assert summary["noisy_rules"] == 0
    assert os.path.exists(report_file)
