"""Tests for deterministic incident fact extraction and grounding schema."""

import pytest
from app.pipeline.report.facts import build_incident_facts, sample_evidence_event_ids
from app.schemas.facts import FactStep, IncidentFacts, ReachFacts, ReachFactTarget


def test_sample_evidence_event_ids():
    # Empty
    assert sample_evidence_event_ids([]) == []

    # Under limit (4 items)
    eids_4 = ["ev_1", "ev_2", "ev_3", "ev_4"]
    assert sample_evidence_event_ids(eids_4, max_sample=8) == eids_4

    # Exactly 8 items
    eids_8 = [f"ev_{i}" for i in range(1, 9)]
    assert sample_evidence_event_ids(eids_8, max_sample=8) == eids_8

    # 20 items: first 4 and last 4
    eids_20 = [f"ev_{i}" for i in range(1, 21)]
    sampled = sample_evidence_event_ids(eids_20, max_sample=8)
    assert len(sampled) == 8
    assert sampled[:4] == ["ev_1", "ev_2", "ev_3", "ev_4"]
    assert sampled[-4:] == ["ev_17", "ev_18", "ev_19", "ev_20"]


def test_build_incident_facts_synthetic():
    inc_dict = {
        "incident_id": "inc_test_123",
        "title": "Credential Access Campaign",
        "severity": 8,
        "risk_score": 7.5,
        "status": "open",
        "first_seen": "2026-10-23 08:00:00",
        "last_seen": "2026-10-23 09:30:00",
        "hosts": ["10.10.20.50"],
        "users": ["admin"],
        "src_ips": ["198.51.100.2"],
        "detection_count": 5,
        "event_count": 120,
        "steps": [
            {
                "step_order": 2,
                "technique_id": "T1003",
                "tactic": "credential_access",
                "kill_chain_stage": "Credential Access",
                "first_seen": "2026-10-23 08:30:00",
                "last_seen": "2026-10-23 09:30:00",
                "hosts": ["10.10.20.50"],
                "count": 4,
                "evidence_event_ids": [f"ev_{i}" for i in range(1, 15)],
            },
            {
                "step_order": 1,
                "technique_id": "T1110",
                "tactic": "credential_access",
                "kill_chain_stage": "Exploitation",
                "first_seen": "2026-10-23 08:00:00",
                "last_seen": "2026-10-23 08:20:00",
                "hosts": ["10.10.20.50"],
                "count": 100,
                "evidence_event_ids": ["ev_init_1", "ev_init_2"],
            },
        ],
    }

    reach_dict = {
        "compromised_nodes": ["10.10.20.50"],
        "blast_radius": {
            "hosts_count": 10,
            "users_count": 2,
            "critical_assets_reached": ["dc01.corp.internal"],
        },
        "reachable_targets": [
            {
                "target_label": "10.10.20.60",
                "target_kind": "host",
                "hops": 1,
                "priority": "high",
                "reason": "allowed on smb/445 seen 10 times",
                "evidence_event_ids": ["ev_reach_1"],
            }
        ],
    }

    facts = build_incident_facts(
        incident_id="inc_test_123",
        incident_dict=inc_dict,
        reach_dict=reach_dict,
    )

    # Validate top-level facts
    assert facts.incident_id == "inc_test_123"
    assert facts.severity == 8
    assert facts.risk_score == 7.5
    assert facts.detection_count == 5
    assert facts.event_count == 120

    # Validate step ordering (step 1 must come before step 2 despite input order)
    assert len(facts.steps) == 2
    assert facts.steps[0].step_order == 1
    assert facts.steps[0].technique_id == "T1110"
    assert facts.steps[0].technique_name == "Brute Force"
    assert facts.steps[0].occurrence_count == 100
    assert facts.steps[0].evidence_event_ids == ["ev_init_1", "ev_init_2"]

    assert facts.steps[1].step_order == 2
    assert facts.steps[1].technique_id == "T1003"
    assert facts.steps[1].technique_name == "OS Credential Dumping"
    assert facts.steps[1].occurrence_count == 4
    # Max 8 sampled evidence IDs for step 2
    assert len(facts.steps[1].evidence_event_ids) == 8

    # Validate reach integration
    assert facts.reach is not None
    assert facts.reach.hosts_count == 10
    assert facts.reach.critical_assets == ["dc01.corp.internal"]
    assert len(facts.reach.reachable_targets) == 1
    assert facts.reach.reachable_targets[0].target == "10.10.20.60"
    assert facts.reach.reachable_targets[0].priority == "high"

    # Validate known entities whitelist
    expected_entities = {
        "10.10.20.50",
        "10.10.20.60",
        "198.51.100.2",
        "admin",
        "dc01.corp.internal",
    }
    assert set(facts.known_entities) == expected_entities

    # Validate deterministic SHA256
    sha1 = facts.facts_sha256
    assert len(sha1) == 64
    # Re-computing hash returns same value
    assert facts.compute_sha256() == sha1


def test_facts_hash_determinism():
    step = FactStep(
        step_order=1,
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="credential_access",
        kill_chain_stage="Exploitation",
        first_seen="2026-10-23 08:00:00",
        last_seen="2026-10-23 08:15:00",
        hosts=["10.10.20.50"],
        occurrence_count=20,
        event_count=20,
        evidence_event_ids=["ev_1", "ev_2"],
    )

    facts1 = IncidentFacts(
        incident_id="inc_det_1",
        title="Brute Force Incident",
        severity=6,
        risk_score=5.5,
        status="open",
        detection_count=1,
        event_count=20,
        first_seen="2026-10-23 08:00:00",
        last_seen="2026-10-23 08:15:00",
        known_entities=["10.10.20.50", "192.168.1.1"],
        hosts=["10.10.20.50"],
        users=[],
        src_ips=["192.168.1.1"],
        steps=[step],
        reach=ReachFacts(
            seed_hosts=["10.10.20.50"],
            hosts_count=1,
            users_count=0,
            critical_assets=[],
            reachable_targets=[
                ReachFactTarget(target="10.10.20.99", kind="host", hops=1, priority="low", reason="test")
            ],
        ),
        all_event_ids=["ev_1", "ev_2"],
    )

    facts2 = IncidentFacts(
        incident_id="inc_det_1",
        title="Brute Force Incident",
        severity=6,
        risk_score=5.5,
        status="open",
        detection_count=1,
        event_count=20,
        first_seen="2026-10-23 08:00:00",
        last_seen="2026-10-23 08:15:00",
        known_entities=["10.10.20.50", "192.168.1.1"],
        hosts=["10.10.20.50"],
        users=[],
        src_ips=["192.168.1.1"],
        steps=[step],
        reach=ReachFacts(
            seed_hosts=["10.10.20.50"],
            hosts_count=1,
            users_count=0,
            critical_assets=[],
            reachable_targets=[
                ReachFactTarget(target="10.10.20.99", kind="host", hops=1, priority="low", reason="test")
            ],
        ),
        all_event_ids=["ev_1", "ev_2"],
    )

    assert facts1.facts_sha256 == facts2.facts_sha256


def test_build_incident_facts_from_db():
    from app.store import duck

    incs = duck.list_incidents()
    # list_incidents returns (items, total) or (total, items)
    inc_list = incs[0] if isinstance(incs[0], list) else incs[1]
    if not inc_list:
        pytest.skip("No incidents in test database")

    first_inc = inc_list[0]
    facts = build_incident_facts(first_inc["incident_id"])
    assert facts.incident_id == first_inc["incident_id"]
    assert facts.title == first_inc["title"]
    assert len(facts.facts_sha256) == 64
    assert isinstance(facts.known_entities, list)
    if facts.steps:
        for s in facts.steps:
            assert len(s.evidence_event_ids) <= 8

