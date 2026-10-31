"""Tests for the CaseFile evaluator and manifest scoring subsystem."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.pipeline.evaluate.evaluator import (
    evaluate_manifest,
    is_family_match,
    parse_attack_techniques,
)
from app.store import duck


def test_manifest_isolation_boundary():
    """Ensure that the ground truth manifest is loaded ONLY by the evaluator.
    
    Ingest, detect, link, path, and report must never import or read ground-truth manifests.
    """
    repo_root = Path(__file__).resolve().parents[2]
    app_dir = repo_root / "backend" / "app"
    pipeline_dir = app_dir / "pipeline"

    forbidden_dirs = [
        pipeline_dir / "ingest",
        pipeline_dir / "detect",
        pipeline_dir / "link",
        pipeline_dir / "path",
        pipeline_dir / "report",
    ]

    for d in forbidden_dirs:
        for py_file in d.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            # Must not load *.manifest.json
            assert ".manifest.json" not in content, f"Forbidden manifest reference in {py_file}"
            # Must not import evaluator
            assert "pipeline.evaluate" not in content, f"Forbidden evaluate import in {py_file}"


def test_manifest_size_mismatch_aborts(tmp_path: Path, capsys):
    """When manifest bytes do not match log file size, exit with code 3."""
    log_file = tmp_path / "test.log"
    log_file.write_bytes(b"test data 12345")
    actual_size = log_file.stat().st_size

    manifest_file = tmp_path / "test.manifest.json"
    manifest_data = {
        "bytes": actual_size + 999999,  # Mismatched size
        "incidents": [],
    }
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        evaluate_manifest(str(manifest_file), log_file_path=str(log_file))

    assert exc_info.value.code == 3
    captured = capsys.readouterr()
    assert "MANIFEST DOES NOT MATCH THIS FILE" in captured.out


def test_technique_helpers():
    """Test technique parsing and family matching."""
    techs = parse_attack_techniques("T1595.002 -> T1190 -> T1059.001")
    assert techs == ["T1595.002", "T1190", "T1059.001"]

    techs2 = parse_attack_techniques("T1110.001, T1078")
    assert techs2 == ["T1110.001", "T1078"]

    assert is_family_match("T1110.001", "T1110") is True
    assert is_family_match("T1110", "T1110.001") is True
    assert is_family_match("T1110.001", "T1110.001") is True
    assert is_family_match("T1110.001", "T1078") is False


def test_hand_made_manifest_scoring(tmp_path: Path):
    """Score detections against a tiny hand-made manifest."""
    duck.reset_all()

    # Hand-made manifest with 2 incidents:
    # 1. Non-chain brute-force (2 planted steps: T1110.001, T1078)
    # 2. Chain web attack (2 stages: stage 1 T1595, stage 2 T1190)
    manifest_data = {
        "bytes": 500,
        "streams": {"0": "firewall", "1": "windows"},
        "incidents": [
            {
                "id": 1,
                "class": "easy",
                "name": "brute-force",
                "attack": "T1110.001, T1078",
                "tactic": "Credential Access",
                "at": [[10, 100, 0], [20, 200, 0]],
            },
            {
                "id": 2,
                "class": "medium",
                "name": "web-chain",
                "attack": "T1595 -> T1190",
                "tactic": "Initial Access",
                "at": [[30, 300, 0], [40, 400, 0]],
                "stages": [
                    {
                        "n": 1,
                        "stage": "scan",
                        "attack": "T1595",
                        "tactic": "Reconnaissance",
                        "at": "2026-10-28 14:00:00",
                    },
                    {
                        "n": 2,
                        "stage": "exploit",
                        "attack": "T1190",
                        "tactic": "Initial Access",
                        "at": "2026-10-28 15:00:00",
                    },
                ],
                "to": "2026-10-28 16:00:00",
            },
        ],
    }

    manifest_file = tmp_path / "tiny.manifest.json"
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    # Insert detections into DuckDB
    # Det 1 hits Incident 1 Step 1 with exact technique T1110.001
    duck.insert_detection({
        "detection_id": "det_001",
        "rule_id": "R1",
        "rule_name": "Brute Force",
        "technique_id": "T1110.001",
        "tactic": "Credential Access",
        "severity": 8,
        "host": "srv1",
        "ts": "2026-10-28T09:00:00Z",
        "event_ids": ["ev_0_100"],
        "incident_id": "inc_001",
    })

    # Det 2 hits Incident 1 Step 2 with family match T1078.001 (planted is T1078)
    duck.insert_detection({
        "detection_id": "det_002",
        "rule_id": "R2",
        "rule_name": "Valid Accounts",
        "technique_id": "T1078.001",
        "tactic": "Defense Evasion",
        "severity": 6,
        "host": "srv1",
        "ts": "2026-10-28T09:05:00Z",
        "event_ids": ["ev_0_200"],
        "incident_id": "inc_001",
    })

    # Det 3 is a false alarm (doesn't hit any planted event)
    duck.insert_detection({
        "detection_id": "det_003",
        "rule_id": "R3",
        "rule_name": "Noisy Rule",
        "technique_id": "T1059",
        "tactic": "Execution",
        "severity": 4,
        "host": "srv2",
        "ts": "2026-10-28T10:00:00Z",
        "event_ids": ["ev_0_9999"],
        "incident_id": "inc_002",
    })

    # Insert our incidents
    duck.upsert_incident({
        "incident_id": "inc_001",
        "title": "Incident 1",
        "severity": 8,
        "first_seen": "2026-10-28T09:00:00Z",
        "last_seen": "2026-10-28T09:05:00Z",
        "detection_ids": ["det_001", "det_002"],
    })
    duck.upsert_incident({
        "incident_id": "inc_002",
        "title": "False Alarm Incident",
        "severity": 4,
        "first_seen": "2026-10-28T10:00:00Z",
        "last_seen": "2026-10-28T10:00:00Z",
        "detection_ids": ["det_003"],
    })

    res = evaluate_manifest(str(manifest_file))

    # Planted incidents: 2 total (1 hit, 1 missed)
    assert res["total_planted_incidents"] == 2
    assert res["total_hit_incidents"] == 1
    assert res["incident_detection_rate"] == 0.50

    # Planted steps: 2 in incident 1 + 2 in incident 2 = 4 total
    assert res["total_planted_steps"] == 4
    # Steps hit: 2 in incident 1
    assert res["total_hit_steps"] == 2
    assert res["detection_rate"] == 0.50

    # Label accuracy: 1 exact match (T1110.001) / 2 steps hit = 0.50
    assert res["label_accuracy_exact"] == 0.50
    # Family accuracy: 2 matches (T1110.001 exact + T1078.001 family) / 2 steps hit = 1.00
    assert res["label_accuracy_family"] == 1.00

    # False alarm rate: 1 unhit incident out of 2 total incidents = 0.50
    assert res["false_alarm_rate"] == 0.50
    assert res["false_alarm_count"] == 1

    # Missed incident list contains Incident 2
    missed = res["missed_incidents"]
    assert len(missed) == 1
    assert missed[0]["id"] == 2

    # Rule stats: R1 hit=1 fa=0, R2 hit=1 fa=0, R3 hit=0 fa=1
    rule_stats = res["rule_stats"]
    assert rule_stats["R1"]["hits"] == 1
    assert rule_stats["R3"]["false_alarms"] == 1
