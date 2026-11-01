"""Tests for dynamic risk scoring and Markdown incident report rendering."""

from __future__ import annotations

import pytest
from app.pipeline.path.risk import score_incident
from app.pipeline.report.template import render
from app.store import duck


@pytest.fixture(autouse=True)
def clean_test_db(tmp_path, monkeypatch):
    """Run tests with an isolated clean DuckDB database."""
    db_path = str(tmp_path / "test_risk.duckdb")
    monkeypatch.setattr("app.config.settings.duck_path", db_path)
    monkeypatch.setattr("app.config.settings.parquet_dir", str(tmp_path / "empty_parquet"))
    duck.close()
    duck.init_db()
    yield
    duck.close()


def test_risk_score_progression_depth():
    """Verify incidents with later kill chain tactics receive higher risk scores."""
    inc_early = {
        "incident_id": "inc_early",
        "severity": 3,
        "techniques": ["T1082"],
        "steps": [{"tactic": "discovery", "technique_id": "T1082"}],
        "hosts": ["workstation-10"],
        "detection_count": 1,
    }
    inc_late = {
        "incident_id": "inc_late",
        "severity": 3,
        "techniques": ["T1048"],
        "steps": [{"tactic": "exfiltration", "technique_id": "T1048"}],
        "hosts": ["workstation-10"],
        "detection_count": 1,
    }

    score_early = score_incident(inc_early)
    score_late = score_incident(inc_late)

    assert score_late > score_early, f"Late score {score_late} not > early score {score_early}"


def test_risk_score_tactic_breadth_and_critical_asset():
    """Verify tactic breadth across multiple stages and critical assets boost score."""
    inc_single = {
        "incident_id": "inc_single",
        "severity": 5,
        "techniques": ["T1110"],
        "steps": [{"tactic": "credential_access", "technique_id": "T1110"}],
        "hosts": ["pc-01"],
        "detection_count": 2,
    }
    inc_multi = {
        "incident_id": "inc_multi",
        "severity": 5,
        "techniques": ["T1110", "T1021", "T1048"],
        "steps": [
            {"tactic": "credential_access", "technique_id": "T1110"},
            {"tactic": "lateral_movement", "technique_id": "T1021"},
            {"tactic": "exfiltration", "technique_id": "T1048"},
        ],
        "hosts": ["pc-01", "DC-01"],  # Contains critical Domain Controller
        "detection_count": 5,
    }

    score_single = score_incident(inc_single)
    score_multi = score_incident(inc_multi)

    assert score_multi > score_single
    assert 1.0 <= score_multi <= 10.0
    assert 1.0 <= score_single <= 10.0


def test_markdown_report_rendering_with_reach_and_metrics():
    """Verify render() outputs risk score, raw event counts, and next reach section."""
    incident_id = "inc_rep_01"

    # Seed incident
    duck.upsert_incident({
        "incident_id": incident_id,
        "title": "Credential Access and Lateral Spread",
        "severity": 8,
        "risk_score": 9.2,
        "detection_count": 4,
        "event_count": 4850,
        "status": "open",
        "first_seen": "2026-10-30T08:00:00Z",
        "last_seen": "2026-10-30T08:45:00Z",
        "hosts": ["10.10.10.15", "DC-01"],
        "users": ["admin"],
        "src_ips": ["198.51.100.44"],
        "techniques": ["T1110", "T1021"],
        "steps": [
            {
                "step_order": 1,
                "technique_id": "T1110",
                "tactic": "credential_access",
                "kill_chain_stage": "Exploitation",
                "first_seen": "2026-10-30T08:00:00Z",
                "last_seen": "2026-10-30T08:10:00Z",
                "hosts": ["10.10.10.15"],
            },
            {
                "step_order": 2,
                "technique_id": "T1021",
                "tactic": "lateral_movement",
                "kill_chain_stage": "Lateral Movement",
                "first_seen": "2026-10-30T08:20:00Z",
                "last_seen": "2026-10-30T08:45:00Z",
                "hosts": ["DC-01"],
            },
        ],
        "detection_ids": ["det_1", "det_2", "det_3", "det_4"],
    })

    # Seed precomputed next reach
    reach_data = {
        "incident_id": incident_id,
        "blast_radius": {
            "hosts_count": 3,
            "users_count": 1,
            "total_nodes": 4,
            "critical_assets_reached": ["SQL-PROD", "FS-01"],
        },
        "reachable_targets": [
            {
                "target_id": "SQL-PROD",
                "target_label": "SQL-PROD",
                "target_kind": "host",
                "hops": 1,
                "reason": "allowed on tcp/1433 seen 18 times",
                "priority": "critical",
                "score": 0.95,
                "is_critical": True,
            }
        ],
        "disclaimer": "Probabilistic risk assessment based on observed network access.",
    }
    duck.set_incident_next(
        incident_id=incident_id,
        data=reach_data,
        blast_hosts=3,
        blast_users=1,
        critical_assets=["SQL-PROD", "FS-01"],
    )

    report = render(incident_id)

    # Assertions on rendered Markdown
    assert "# Incident Report: Credential Access and Lateral Spread" in report
    assert "**Risk Score:** 9.2/10.0" in report
    assert "**Detections Merged:** 4" in report
    assert "**Raw Events Merged:** 4850" in report
    assert "## Kill Chain Progression" in report
    assert "Step 1: `T1110` – credential_access (Exploitation)" in report
    assert "Step 2: `T1021` – lateral_movement (Lateral Movement)" in report
    assert "## Blast Radius & Potential Next Reach" in report
    assert "Potentially Reachable Hosts:** 3" in report
    assert "Critical Assets Exposed:** SQL-PROD, FS-01" in report
    assert "allowed on tcp/1433 seen 18 times" in report
    assert "Probabilistic risk assessment" in report
