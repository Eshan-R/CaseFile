"""Unit tests for attack path builder, tactic normalization, and kill-chain ordering."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from app.pipeline.path.path_builder import _TACTIC_ORDER, _tactic_rank, build_path, normalise_tactic
from app.store import duck


@pytest.fixture(autouse=True)
def clean_db():
    duck.init_db()
    with duck.cursor() as con:
        con.execute("DELETE FROM incidents")
    yield
    with duck.cursor() as con:
        con.execute("DELETE FROM incidents")


def test_normalise_tactic():
    assert normalise_tactic("credential_access") == "credential-access"
    assert normalise_tactic("CREDENTIAL_ACCESS") == "credential-access"
    assert normalise_tactic("credential-access") == "credential-access"
    assert normalise_tactic("credential access") == "credential-access"
    assert normalise_tactic("  lateral_movement  ") == "lateral-movement"
    assert normalise_tactic("") == ""
    assert normalise_tactic(None) == ""


def test_all_tactics_in_yaml_resolve_valid_rank():
    # Load all tactics from rules/detections.yaml
    yaml_path = Path("rules/detections.yaml")
    assert yaml_path.exists(), "rules/detections.yaml must exist"

    with open(yaml_path, encoding="utf-8") as f:
        rules = yaml.safe_load(f)

    max_rank = len(_TACTIC_ORDER)
    for rule in rules:
        tactic = rule.get("tactic")
        if tactic:
            rank = _tactic_rank(tactic)
            assert rank < max_rank, f"Rule '{rule.get('id')}' tactic '{tactic}' not found in _TACTIC_ORDER!"


def test_build_path_chronological_with_tie_break():
    # Test incident with steps having timestamps and simultaneous steps broken by tactic rank
    inc_id = "inc_test_path_order"
    steps = [
        {
            "step_order": 1,
            "technique_id": "T1048",
            "tactic": "exfiltration",
            "kill_chain_stage": "Exfiltration",
            "first_seen": "2026-10-23T12:00:00Z",
            "last_seen": "2026-10-23T12:00:00Z",
            "hosts": ["host1"],
        },
        {
            "step_order": 2,
            "technique_id": "T1078",
            "tactic": "initial_access",
            "kill_chain_stage": "Initial Access",
            "first_seen": "2026-10-23T10:00:00Z",
            "last_seen": "2026-10-23T10:00:00Z",
            "hosts": ["host1"],
        },
        # Two simultaneous steps at 11:00:00: Credential Access should rank before Lateral Movement
        {
            "step_order": 3,
            "technique_id": "T1021",
            "tactic": "lateral_movement",
            "kill_chain_stage": "Lateral Movement",
            "first_seen": "2026-10-23T11:00:00Z",
            "last_seen": "2026-10-23T11:00:00Z",
            "hosts": ["host1"],
        },
        {
            "step_order": 4,
            "technique_id": "T1110",
            "tactic": "credential_access",
            "kill_chain_stage": "Exploitation",
            "first_seen": "2026-10-23T11:00:00Z",
            "last_seen": "2026-10-23T11:00:00Z",
            "hosts": ["host1"],
        },
    ]

    inc = {
        "incident_id": inc_id,
        "title": "Path Order Test",
        "severity": 8,
        "first_seen": "2026-10-23T10:00:00Z",
        "last_seen": "2026-10-23T12:00:00Z",
        "hosts": ["host1"],
        "techniques": ["T1078", "T1110", "T1021", "T1048"],
        "steps": steps,
        "detection_ids": ["d1", "d2", "d3", "d4"],
        "status": "open",
    }
    duck.upsert_incident(inc)

    ordered = build_path(inc_id)
    assert len(ordered) == 4

    # 1. Step at 10:00: Initial Access
    assert ordered[0]["technique_id"] == "T1078"
    assert ordered[0]["tactic"] == "initial-access"
    assert ordered[0]["kill_chain_stage"] == "Initial Access"
    assert ordered[0]["step_order"] == 1

    # 2. Step at 11:00: Credential Access (rank 7) before Lateral Movement (rank 9)
    assert ordered[1]["technique_id"] == "T1110"
    assert ordered[1]["tactic"] == "credential-access"
    assert ordered[1]["kill_chain_stage"] == "Exploitation"
    assert ordered[1]["step_order"] == 2

    # 3. Step at 11:00: Lateral Movement
    assert ordered[2]["technique_id"] == "T1021"
    assert ordered[2]["tactic"] == "lateral-movement"
    assert ordered[2]["kill_chain_stage"] == "Lateral Movement"
    assert ordered[2]["step_order"] == 3

    # 4. Step at 12:00: Exfiltration
    assert ordered[3]["technique_id"] == "T1048"
    assert ordered[3]["tactic"] == "exfiltration"
    assert ordered[3]["kill_chain_stage"] == "Exfiltration"
    assert ordered[3]["step_order"] == 4

