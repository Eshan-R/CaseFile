"""Unit tests for the 5 automated pattern discovery miners and orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import duckdb
import pytest
from app.pipeline.patterns.base import generate_pattern_id, shannon_entropy
from app.pipeline.patterns.burst import mine_bursts
from app.pipeline.patterns.coordinated import mine_coordinated
from app.pipeline.patterns.novel_edges import mine_novel_edges
from app.pipeline.patterns.rarity import mine_rarity
from app.pipeline.patterns.runner import run_pattern_mining
from app.pipeline.patterns.sequences import mine_sequences
from app.store.duck import CREATE_EVENTS_TABLE_DDL


@pytest.fixture
def mock_db():
    """In-memory DuckDB connection populated with synthetic security event telemetry."""
    con = duckdb.connect(":memory:")
    con.execute(CREATE_EVENTS_TABLE_DDL)

    t0 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=UTC)

    events: list[dict] = []

    # 1. Burst events: 25 rapid auth failure events from 192.168.1.50
    for i in range(25):
        ts = t0 + timedelta(seconds=i * 2)
        events.append({
            "event_id": f"ev_burst_{i}",
            "ts": ts,
            "timestamp": ts.isoformat(),
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.5",
            "dst_port": 22,
            "logid": "0100032002",
            "action": "deny",
            "reason": "password_invalid",
            "source_offset": i,
        })

    # Baseline quiet events from other sources to allow MAD calculation
    for i in range(5):
        ts = t0 + timedelta(seconds=i * 10)
        events.append({
            "event_id": f"ev_quiet_{i}",
            "ts": ts,
            "timestamp": ts.isoformat(),
            "src_ip": f"192.168.1.{60 + i}",
            "dst_ip": "10.0.0.5",
            "dst_port": 22,
            "logid": "0100032002",
            "action": "deny",
            "reason": "password_invalid",
            "source_offset": 100 + i,
        })

    # 2. Rarity events: Rare malware identifier + blocked action
    events.append({
        "event_id": "ev_rare_virus_1",
        "ts": t0 + timedelta(minutes=5),
        "timestamp": (t0 + timedelta(minutes=5)).isoformat(),
        "src_ip": "192.168.1.80",
        "dst_ip": "10.0.0.12",
        "dst_port": 443,
        "virus": "Trojan.Win32.CobaltStrike",
        "action": "block",
        "severity": "critical",
        "source_offset": 201,
    })

    # High entropy DGA domain
    events.append({
        "event_id": "ev_dga_1",
        "ts": t0 + timedelta(minutes=6),
        "timestamp": (t0 + timedelta(minutes=6)).isoformat(),
        "src_ip": "192.168.1.81",
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "hostname": "vx9z1q8m2p5k7w4t0r3y6u8b1n4m.malware-c2.net",
        "action": "deny",
        "severity": "high",
        "source_offset": 202,
    })

    # 3. Novel edges: rare lateral SMB connection (Port 445)
    for i in range(2):
        ts = t0 + timedelta(minutes=10, seconds=i * 5)
        events.append({
            "event_id": f"ev_edge_smb_{i}",
            "ts": ts,
            "timestamp": ts.isoformat(),
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.20",
            "dst_port": 445,
            "action": "accept",
            "source_offset": 300 + i,
        })

    # 4. Multi-stage sequence: Host 10.0.0.55 executes auth failure -> lateral SMB -> exfiltration
    seq_t0 = t0 + timedelta(minutes=15)
    events.append({
        "event_id": "ev_seq_stage1",
        "ts": seq_t0,
        "timestamp": seq_t0.isoformat(),
        "src_ip": "10.0.0.55",
        "dst_ip": "10.0.0.1",
        "dst_port": 22,
        "logid": "0100032002",
        "action": "deny",
        "reason": "auth_failure",
        "source_offset": 401,
    })
    events.append({
        "event_id": "ev_seq_stage2",
        "ts": seq_t0 + timedelta(minutes=5),
        "timestamp": (seq_t0 + timedelta(minutes=5)).isoformat(),
        "src_ip": "10.0.0.55",
        "dst_ip": "10.0.0.2",
        "dst_port": 445,
        "action": "accept",
        "source_offset": 402,
    })

    # 5. Coordinated activity: 2 distinct sources attacking same destination
    coord_t0 = t0 + timedelta(minutes=25)
    for src in ["192.168.1.101", "192.168.1.102"]:
        for j in range(3):
            ts = coord_t0 + timedelta(seconds=j * 3)
            events.append({
                "event_id": f"ev_coord_{src}_{j}",
                "ts": ts,
                "timestamp": ts.isoformat(),
                "src_ip": src,
                "dst_ip": "10.0.0.99",
                "dst_port": 8080,
                "attack": "Spring4Shell_RCE",
                "action": "deny",
                "source_offset": 500 + len(events),
            })

    # Bulk insert synthetic events with union of all keys
    all_keys: set[str] = set()
    for e in events:
        all_keys.update(e.keys())
    keys = sorted(list(all_keys))
    val_placeholders = ", ".join(["?" for _ in keys])
    rows = [[e.get(k) for k in keys] for e in events]
    con.executemany(f"INSERT INTO events ({', '.join(keys)}) VALUES ({val_placeholders})", rows)

    return con


def test_base_utilities():
    pid1 = generate_pattern_id("burst", "192.168.1.1:ssh")
    pid2 = generate_pattern_id("burst", "192.168.1.1:ssh")
    pid3 = generate_pattern_id("burst", "192.168.1.2:ssh")
    assert pid1 == pid2
    assert pid1 != pid3
    assert pid1.startswith("pat_")

    ent_high = shannon_entropy("vx9z1q8m2p5k7w4t0r3y6u8b1n4m")
    ent_low = shannon_entropy("aaaaaaaaaaaa")
    assert ent_high >= 3.8
    assert ent_low == 0.0


def test_burst_miner(mock_db):
    candidates = mine_bursts(mock_db, min_count=20, min_z=2.0)
    assert len(candidates) >= 1
    burst = candidates[0]
    assert burst.kind == "burst"
    assert "192.168.1.50" in burst.title
    assert burst.support >= 20
    assert burst.score >= 3.0
    assert len(burst.example_event_ids) <= 8
    assert burst.suggested_technique == "T1110"


def test_rarity_miner(mock_db):
    candidates = mine_rarity(mock_db, max_frequency=5)
    assert len(candidates) >= 1

    # Check that virus or high-entropy domain is detected
    kinds = [c.details_json.get("dimension") for c in candidates]
    assert "virus" in kinds or "hostname" in kinds

    for c in candidates:
        assert c.kind == "rarity"
        assert c.support <= 5
        assert c.score >= 3.0
        assert len(c.example_event_ids) >= 1


def test_novel_edges_miner(mock_db):
    candidates = mine_novel_edges(mock_db, max_seen=5)
    assert len(candidates) >= 1
    ports = [e.details_json["dst_port"] for e in candidates]
    assert 445 in ports
    smb_edge = next(e for e in candidates if e.details_json["dst_port"] == 445)
    assert smb_edge.kind == "novel_edges"
    assert smb_edge.details_json["is_lateral"] is True
    assert smb_edge.suggested_technique == "T1021"


def test_sequences_miner(mock_db):
    candidates = mine_sequences(mock_db, min_support=1)
    assert len(candidates) >= 1
    seq = candidates[0]
    assert seq.kind == "sequence"
    assert seq.details_json["stage_count"] >= 2
    assert "Credential Access" in seq.title or "Lateral Movement" in seq.title


def test_coordinated_miner(mock_db):
    candidates = mine_coordinated(mock_db, min_sources=2)
    assert len(candidates) >= 1
    targets = [c.details_json["target_ip"] for c in candidates]
    assert "10.0.0.99" in targets
    target_coord = next(c for c in candidates if c.details_json["target_ip"] == "10.0.0.99")
    assert target_coord.kind == "coordinated"
    assert target_coord.details_json["distinct_sources"] >= 2
    assert "10.0.0.99" in target_coord.title


def test_runner_orchestrator_determinism(mock_db):
    # Run twice and verify 100% identical outputs
    res1, t1 = run_pattern_mining(mock_db, min_score=3.0)
    res2, t2 = run_pattern_mining(mock_db, min_score=3.0)

    assert len(res1) > 0
    assert len(res1) == len(res2)

    for p1, p2 in zip(res1, res2, strict=True):
        assert p1.pattern_id == p2.pattern_id
        assert p1.kind == p2.kind
        assert p1.score == p2.score
        assert p1.support == p2.support
        assert p1.example_event_ids == p2.example_event_ids
