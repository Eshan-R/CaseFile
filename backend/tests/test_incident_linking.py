"""Unit tests for incident linking, Union-Find clustering, hub capping, and promotion filter."""

from __future__ import annotations

import unittest.mock as mock
from datetime import UTC, datetime, timedelta

import pytest
from app.config import settings
from app.pipeline.link.incidents import DisjointSet, build_incidents
from app.store import duck


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_link.duckdb")
    monkeypatch.setattr(settings, "duck_path", test_db)
    duck.close()
    duck.init_db()
    yield
    duck.close()


def test_disjoint_set_union_and_find():
    ds = DisjointSet(5)
    assert ds.find(0) == 0
    ds.union(0, 1)
    assert ds.find(0) == ds.find(1)
    ds.union(1, 2)
    assert ds.find(0) == ds.find(2)
    assert ds.find(3) == 3


def test_two_detections_sharing_ip_within_window_merge():
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(minutes=10)  # 600s <= 1800s window

    det1 = {
        "detection_id": "det_link_1",
        "rule_id": "r1",
        "rule_name": "R1",
        "technique_id": "T1110",
        "tactic": "credential-access",
        "severity": 8,
        "host": "srv1",
        "ts": t0,
        "event_ids": ["ev1", "ev2"],
    }
    det2 = {
        "detection_id": "det_link_2",
        "rule_id": "r2",
        "rule_name": "R2",
        "technique_id": "T1078",
        "tactic": "initial-access",
        "severity": 7,
        "host": "srv1",
        "ts": t1,
        "event_ids": ["ev3"],
    }
    duck.insert_detection(det1)
    duck.insert_detection(det2)

    # Mock bulk entities so det1 and det2 share 192.168.1.100
    mock_bulk = {
        "det_link_1": {"src_ips": ["192.168.1.100"], "dst_ips": ["10.0.0.1"], "users": ["alice"], "hosts": ["srv1"], "event_count": 2},
        "det_link_2": {"src_ips": ["192.168.1.100"], "dst_ips": ["10.0.0.2"], "users": ["bob"], "hosts": ["srv1"], "event_count": 1},
    }
    with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
        res = build_incidents()

    assert res["incidents_created"] == 1
    total, incs = duck.list_incidents()
    assert total == 1
    inc = incs[0]
    assert inc["detection_count"] == 2
    assert inc["event_count"] == 3
    assert inc["status"] == "open"  # 2 distinct tactics -> promoted


def test_two_detections_sharing_ip_outside_window_stay_separate():
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(minutes=45)  # 2700s > 1800s window

    det1 = {
        "detection_id": "det_time_1",
        "rule_id": "r1",
        "rule_name": "R1",
        "technique_id": "T1110",
        "tactic": "credential-access",
        "severity": 5,
        "host": "srv1",
        "ts": t0,
        "event_ids": ["ev1", "ev2"],
    }
    det2 = {
        "detection_id": "det_time_2",
        "rule_id": "r2",
        "rule_name": "R2",
        "technique_id": "T1110",
        "tactic": "credential-access",
        "severity": 5,
        "host": "srv1",
        "ts": t1,
        "event_ids": ["ev3", "ev4"],
    }
    duck.insert_detection(det1)
    duck.insert_detection(det2)

    mock_bulk = {
        "det_time_1": {"src_ips": ["192.168.1.100"], "dst_ips": [], "users": [], "hosts": ["srv1"], "event_count": 2},
        "det_time_2": {"src_ips": ["192.168.1.100"], "dst_ips": [], "users": [], "hosts": ["srv1"], "event_count": 2},
    }
    with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
        res = build_incidents()

    # Outside window → two separate clusters; each has 1 detection, same tactic, so neither is promoted
    assert res["incidents_created"] == 0
    assert res["alerts_created"] == 2
    total, incs = duck.list_incidents(show_leads=True)
    assert total == 2
    for inc in incs:
        assert inc["status"] in ("alert", "lead")


def test_disjoint_entities_stay_separate():
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)

    det1 = {
        "detection_id": "det_disjoint_1",
        "rule_id": "r1",
        "rule_name": "R1",
        "technique_id": "T1110",
        "tactic": "credential-access",
        "severity": 5,
        "host": "srv1",
        "ts": t0,
        "event_ids": ["ev1", "ev2"],
    }
    det2 = {
        "detection_id": "det_disjoint_2",
        "rule_id": "r2",
        "rule_name": "R2",
        "technique_id": "T1046",
        "tactic": "discovery",
        "severity": 5,
        "host": "srv2",
        "ts": t0,
        "event_ids": ["ev3", "ev4"],
    }
    duck.insert_detection(det1)
    duck.insert_detection(det2)

    mock_bulk = {
        "det_disjoint_1": {"src_ips": ["192.168.1.10"], "dst_ips": [], "users": ["user1"], "hosts": ["srv1"], "event_count": 2},
        "det_disjoint_2": {"src_ips": ["10.0.0.50"], "dst_ips": [], "users": ["user2"], "hosts": ["srv2"], "event_count": 2},
    }
    with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
        res = build_incidents()

    # Disjoint entities → 2 separate clusters; each has 1 detection with 1 tactic → not promoted
    assert res["alerts_created"] == 2
    assert res["incidents_created"] == 0


def test_transitive_chain_merges_all_three():
    # A (IP 1) links with B (IP 1 + User X), B links with C (User X)
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(minutes=5)
    t2 = t1 + timedelta(minutes=5)

    det_a = {
        "detection_id": "det_chain_A", "rule_id": "r1", "rule_name": "R1",
        "technique_id": "T1110", "tactic": "credential-access", "severity": 8,
        "host": "srv1", "ts": t0, "event_ids": ["ev1"],
    }
    det_b = {
        "detection_id": "det_chain_B", "rule_id": "r2", "rule_name": "R2",
        "technique_id": "T1078", "tactic": "initial-access", "severity": 7,
        "host": "srv1", "ts": t1, "event_ids": ["ev2"],
    }
    det_c = {
        "detection_id": "det_chain_C", "rule_id": "r3", "rule_name": "R3",
        "technique_id": "T1021", "tactic": "lateral-movement", "severity": 6,
        "host": "srv2", "ts": t2, "event_ids": ["ev3"],
    }
    duck.insert_detection(det_a)
    duck.insert_detection(det_b)
    duck.insert_detection(det_c)

    mock_bulk = {
        "det_chain_A": {"src_ips": ["192.168.1.100"], "dst_ips": [], "users": [], "hosts": ["srv1"], "event_count": 1},
        "det_chain_B": {"src_ips": ["192.168.1.100"], "dst_ips": [], "users": ["admin_alice"], "hosts": ["srv1"], "event_count": 1},
        "det_chain_C": {"src_ips": ["10.0.0.5"], "dst_ips": [], "users": ["admin_alice"], "hosts": ["srv2"], "event_count": 1},
    }
    with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
        res = build_incidents()

    assert res["incidents_created"] == 1
    total, incs = duck.list_incidents()
    assert total == 1
    assert incs[0]["detection_count"] == 3
    assert incs[0]["event_count"] == 3


def test_firewall_host_excluded_from_linking():
    # Two detections sharing ONLY the firewall devname FGT60FTK00000000 must NOT merge
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)

    det1 = {
        "detection_id": "det_fw_1", "rule_id": "r1", "rule_name": "R1",
        "technique_id": "T1110", "tactic": "credential-access", "severity": 5,
        "host": "FGT60FTK00000000", "ts": t0, "event_ids": ["ev1", "ev2"],
    }
    det2 = {
        "detection_id": "det_fw_2", "rule_id": "r2", "rule_name": "R2",
        "technique_id": "T1048", "tactic": "exfiltration", "severity": 5,
        "host": "FGT60FTK00000000", "ts": t0, "event_ids": ["ev3", "ev4"],
    }
    duck.insert_detection(det1)
    duck.insert_detection(det2)

    mock_bulk = {
        "det_fw_1": {"src_ips": ["1.1.1.1"], "dst_ips": [], "users": [], "hosts": ["FGT60FTK00000000"], "event_count": 2},
        "det_fw_2": {"src_ips": ["2.2.2.2"], "dst_ips": [], "users": [], "hosts": ["FGT60FTK00000000"], "event_count": 2},
    }
    with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
        res = build_incidents()

    assert res["incidents_created"] == 0
    assert res["alerts_created"] == 2


def test_hub_capping_excludes_frequent_entity():
    # An entity appearing in > hub_threshold detections must not merge all detections
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    mock_bulk = {}
    dets = []
    with mock.patch.object(settings, "incident_link_hub_threshold", 2):
        # 3 detections sharing hub IP "10.10.10.10" (> threshold 2) but having disjoint other IPs
        for i in range(3):
            d_id = f"det_hub_{i}"
            dets.append({
                "detection_id": d_id, "rule_id": f"r{i}", "rule_name": f"R{i}",
                "technique_id": "T1110", "tactic": "credential-access", "severity": 5,
                "host": f"srv{i}", "ts": t0, "event_ids": [f"ev{i}", f"ev{i}_b"],
            })
            duck.insert_detection(dets[-1])
            mock_bulk[d_id] = {
                "src_ips": ["10.10.10.10", f"192.168.1.{i+1}"],
                "dst_ips": [], "users": [], "hosts": [], "event_count": 2,
            }

        with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
            res = build_incidents()

        # Because "10.10.10.10" appeared 3 times (> threshold 2), it is barred from merging
        # The unique IPs 192.168.1.1, 192.168.1.2, 192.168.1.3 keep them separate
        # Each cluster has 1 detection with 1 tactic → not promoted under new filter
        assert res["incidents_created"] == 0
        assert res["alerts_created"] == 3


def test_promotion_filter_marks_low_priority_alert():
    # Single-tactic, low-severity detection with 1 event should NOT be promoted to incident
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    det = {
        "detection_id": "det_low_1", "rule_id": "r1", "rule_name": "R1",
        "technique_id": "T1087", "tactic": "discovery", "severity": 4,
        "host": "srv1", "ts": t0, "event_ids": ["ev1"],
    }
    duck.insert_detection(det)

    mock_bulk = {
        "det_low_1": {"src_ips": ["192.168.1.50"], "dst_ips": [], "users": [], "hosts": ["srv1"], "event_count": 1},
    }
    with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
        res = build_incidents()

    assert res["incidents_created"] == 0
    assert res["alerts_created"] == 1
    total, incs = duck.list_incidents(show_leads=True)
    assert total == 1
    assert incs[0]["status"] in ("alert", "lead")


def test_single_high_severity_detection_not_promoted():
    """Under single-stage attack visibility policy, a single detection with severity >= 7 is promoted to 'open'."""
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    det = {
        "detection_id": "det_highsev_1", "rule_id": "r1", "rule_name": "R1",
        "technique_id": "T1110", "tactic": "credential-access", "severity": 10,
        "host": "srv1", "ts": t0, "event_ids": ["ev1", "ev2", "ev3"],
    }
    duck.insert_detection(det)

    mock_bulk = {
        "det_highsev_1": {"src_ips": ["1.2.3.4"], "dst_ips": [], "users": ["admin"], "hosts": ["srv1"], "event_count": 100},
    }
    with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
        res = build_incidents()

    # Single detection with severity >= 7 is promoted to open
    assert res["incidents_created"] == 1
    assert res["alerts_created"] == 0
    total, incs = duck.list_incidents(show_leads=True)
    assert total == 1
    assert incs[0]["status"] == "open"


def test_two_different_rule_detections_in_same_cluster_promoted():
    """Two detections with distinct techniques in the same cluster are promoted to 'open'."""
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(minutes=5)

    det1 = {
        "detection_id": "det_multirule_1", "rule_id": "brute-force-burst", "rule_name": "Brute Force",
        "technique_id": "T1110", "tactic": "credential-access", "severity": 8,
        "host": "srv1", "ts": t0, "event_ids": ["ev1", "ev2"],
    }
    det2 = {
        "detection_id": "det_multirule_2", "rule_id": "valid-account-misuse", "rule_name": "Valid Account Misuse",
        "technique_id": "T1078", "tactic": "initial-access", "severity": 5,
        "host": "srv1", "ts": t1, "event_ids": ["ev3"],
    }
    duck.insert_detection(det1)
    duck.insert_detection(det2)

    # Same src_ip causes them to merge into one cluster
    mock_bulk = {
        "det_multirule_1": {"src_ips": ["1.2.3.4"], "dst_ips": [], "users": [], "hosts": ["srv1"], "event_count": 2},
        "det_multirule_2": {"src_ips": ["1.2.3.4"], "dst_ips": [], "users": [], "hosts": ["srv1"], "event_count": 1},
    }
    with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
        res = build_incidents()

    # Two distinct techniques (T1110 and T1078) → promoted to open
    assert res["incidents_created"] == 1
    total, incs = duck.list_incidents()
    assert total == 1
    assert incs[0]["status"] == "open"
    assert incs[0]["detection_count"] == 2


def test_same_technique_different_rules_not_promoted():
    """brute-force-burst and brute-force-then-success (both T1110, severity < 7) count as ONE technique and do not promote alone."""
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(minutes=5)

    det1 = {
        "detection_id": "det_bf_1", "rule_id": "brute-force-burst", "rule_name": "Burst",
        "technique_id": "T1110", "tactic": "credential-access", "severity": 5,
        "host": "srv1", "ts": t0, "event_ids": ["ev1"],
    }
    det2 = {
        "detection_id": "det_bf_2", "rule_id": "brute-force-then-success", "rule_name": "Success",
        "technique_id": "T1110", "tactic": "credential-access", "severity": 5,
        "host": "srv1", "ts": t1, "event_ids": ["ev2"],
    }
    duck.insert_detection(det1)
    duck.insert_detection(det2)

    mock_bulk = {
        "det_bf_1": {"src_ips": ["1.2.3.4"], "dst_ips": [], "users": [], "hosts": ["srv1"], "event_count": 1},
        "det_bf_2": {"src_ips": ["1.2.3.4"], "dst_ips": [], "users": [], "hosts": ["srv1"], "event_count": 1},
    }
    with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
        res = build_incidents()

    # Both are T1110 and credential-access → distinct_techniques=1, distinct_tactics=1 → stays alert/lead
    assert res["incidents_created"] == 0
    assert res["alerts_created"] == 1
    total, incs = duck.list_incidents(show_leads=True)
    assert total == 1
    assert incs[0]["status"] in ("alert", "lead")


def test_persistent_attacker_many_detections_not_hub():
    """An attacker IP with 200 detections against the same victim is not a hub and still links."""
    import json
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    mock_bulk = {}
    dets = []
    with mock.patch.object(settings, "incident_link_hub_threshold", 50):
        for i in range(200):
            d_id = f"det_attk_{i}"
            dets.append({
                "detection_id": d_id,
                "rule_id": "r_attack",
                "rule_name": "Attack",
                "technique_id": "T1110" if i % 2 == 0 else "T1078",
                "tactic": "credential-access" if i % 2 == 0 else "initial-access",
                "severity": 7,
                "host": "target_server",
                "ts": t0 + timedelta(minutes=i * 2),
                "event_ids": [f"ev_{i}"],
            })
            mock_bulk[d_id] = {
                "src_ips": ["203.0.113.99"],
                "dst_ips": ["10.10.20.10"],
                "users": [],
                "hosts": ["target_server"],
                "event_count": 1,
            }

        duck.insert_detections_batch(dets)

        with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
            with mock.patch("app.pipeline.path.reach.service.precompute_reach_for_incident"):
                res = build_incidents()

        # Attacker co-occurs only with 10.10.20.10 and target_server (2 entities <= 50)
        # All 200 detections link together into 1 incident
        assert res["incidents_created"] == 1
        total, incs = duck.list_incidents()
        assert total == 1
        assert incs[0]["detection_count"] == 200
        assert incs[0]["status"] == "open"
        # Attack steps should be collapsed: T1110 and T1078 on target_server = 2 steps
        steps = incs[0]["steps"]
        if isinstance(steps, str):
            steps = json.loads(steps)
        assert len(steps) == 2
        for step in steps:
            assert step["count"] == 100


def test_reach_precompute_failure_logs_and_still_saves_incident():
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
    # Two detections from different rules → multi-rule corroboration → promoted to "open"
    det1 = {
        "detection_id": "det_reach_fail_1", "rule_id": "r1", "rule_name": "R1",
        "technique_id": "T1110", "tactic": "credential-access", "severity": 8,
        "host": "srv1", "ts": t0, "event_ids": ["ev1", "ev2"],
    }
    det2 = {
        "detection_id": "det_reach_fail_2", "rule_id": "r2", "rule_name": "R2",
        "technique_id": "T1078", "tactic": "initial-access", "severity": 7,
        "host": "srv1", "ts": t0, "event_ids": ["ev3"],
    }
    duck.insert_detection(det1)
    duck.insert_detection(det2)

    mock_bulk = {
        "det_reach_fail_1": {"src_ips": ["192.168.1.100"], "dst_ips": [], "users": [], "hosts": ["srv1"], "event_count": 2},
        "det_reach_fail_2": {"src_ips": ["192.168.1.100"], "dst_ips": [], "users": [], "hosts": ["srv1"], "event_count": 1},
    }
    with mock.patch("app.store.duck.get_detection_entities_bulk", return_value=mock_bulk):
        with mock.patch("app.pipeline.path.reach.service.precompute_reach_for_incident", side_effect=RuntimeError("Reach crash")):
            res = build_incidents()

    assert res["incidents_created"] == 1
    total, incs = duck.list_incidents()
    assert total == 1
    assert incs[0]["status"] == "open"

