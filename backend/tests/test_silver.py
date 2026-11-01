"""Unit tests for silver-standard independent SQL evaluation.

Uses a synthetic in-memory DuckDB fixture with one planted case per oracle plus noise,
asserting that each oracle finds exactly its planted case and agreement metrics are calculated correctly.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import duckdb
import pytest
from app.pipeline.evaluate.silver import (
    BANNER,
    _mine_admin_success,
    _mine_beacon,
    _mine_config_change,
    _mine_dns_tunnel,
    _mine_failed_admin_burst,
    _mine_flood,
    _mine_lateral_fanout,
    _mine_port_scan,
    _mine_slow_stuffing_24,
    _mine_staged_exfil,
    _mine_virus_detected_not_blocked,
    _mine_vpn_impossible_travel,
    _mine_web_payload,
    run_silver_eval,
)


@pytest.fixture
def silver_con(tmp_path) -> duckdb.DuckDBPyConnection:
    """Create an in-memory DuckDB connection with an events view and planted cases."""
    db_file = str(tmp_path / "silver_test.duckdb")
    con = duckdb.connect(db_file)

    con.execute(
        """
        CREATE TABLE events (
            event_id      VARCHAR PRIMARY KEY,
            ts            TIMESTAMP WITH TIME ZONE,
            source_offset BIGINT,
            logid         VARCHAR,
            action        VARCHAR,
            status        VARCHAR,
            src_ip        VARCHAR,
            dst_ip        VARCHAR,
            src_port      BIGINT,
            dst_port      BIGINT,
            user          VARCHAR,
            srccountry    VARCHAR,
            virus         VARCHAR,
            hostname      VARCHAR,
            url           VARCHAR,
            msg           VARCHAR,
            subtype       VARCHAR,
            proto         BIGINT,
            sentbyte      BIGINT,
            rcvdbyte      BIGINT,
            sentpkt       BIGINT,
            rcvdpkt       BIGINT,
            service       VARCHAR
        );

        CREATE TABLE detections (
            detection_id TEXT PRIMARY KEY,
            rule_id TEXT,
            rule_name TEXT,
            technique_id TEXT,
            tactic TEXT,
            severity INTEGER,
            host TEXT,
            ts TIMESTAMPTZ,
            event_ids TEXT,
            incident_id TEXT,
            confidence DOUBLE,
            kill_chain_stage TEXT
        );

        CREATE TABLE detection_events (
            detection_id TEXT,
            event_id TEXT,
            PRIMARY KEY (detection_id, event_id)
        );

        CREATE TABLE incidents (
            incident_id TEXT PRIMARY KEY
        );
        """
    )

    t_base = datetime(2026, 10, 25, 12, 0, 0, tzinfo=UTC)
    ev_rows = []
    e_idx = 0

    def add_event(**kwargs):
        nonlocal e_idx
        e_idx += 1
        eid = f"ev_test_{e_idx}"
        row = (
            eid,
            kwargs.get("ts", t_base),
            kwargs.get("source_offset", 1000 + e_idx),
            kwargs.get("logid"),
            kwargs.get("action"),
            kwargs.get("status"),
            kwargs.get("src_ip"),
            kwargs.get("dst_ip"),
            kwargs.get("src_port", 12345),
            kwargs.get("dst_port", 80),
            kwargs.get("user"),
            kwargs.get("srccountry"),
            kwargs.get("virus"),
            kwargs.get("hostname"),
            kwargs.get("url"),
            kwargs.get("msg"),
            kwargs.get("subtype"),
            kwargs.get("proto", 6),
            kwargs.get("sentbyte", 500),
            kwargs.get("rcvdbyte", 500),
            kwargs.get("sentpkt", 5),
            kwargs.get("rcvdpkt", 5),
            kwargs.get("service", "http"),
        )
        ev_rows.append(row)
        return eid

    # 1. Planted: failed_admin_burst (505 failures from 198.51.100.1 within 5 minutes)
    burst_eids = []
    for i in range(505):
        t = t_base + timedelta(seconds=i * 0.5)
        eid = add_event(
            ts=t,
            logid="0100032002",
            src_ip="198.51.100.1",
            dst_ip="10.0.0.1",
            user="admin",
            action="login",
        )
        burst_eids.append(eid)

    # 2. Planted: slow_stuffing_24 (25 distinct IPs in 203.0.113.0/24, 75 distinct users, ~180s delta)
    t_stuff = t_base + timedelta(hours=1)
    for ip_i in range(25):
        ip = f"203.0.113.{ip_i + 1}"
        for u_i in range(3):
            user = f"user_{ip_i}_{u_i}"
            add_event(
                ts=t_stuff + timedelta(seconds=(ip_i * 3 + u_i) * 180),
                logid="0100032002",
                src_ip=ip,
                dst_ip="10.0.0.1",
                user=user,
                action="login",
            )

    # 3. Planted: admin_success (logid 0100032001, local hour 2 AM, after 6 failures)
    t_adm_succ = datetime(2026, 10, 24, 20, 30, 0, tzinfo=UTC)  # UTC 20:30 + 5.5h = 02:00 next day (odd hour)
    for i in range(6):
        add_event(
            ts=t_adm_succ - timedelta(minutes=15 - i),
            logid="0100032002",
            src_ip="198.51.100.42",
            dst_ip="10.0.0.1",
            user="root",
        )
    adm_succ_eid = add_event(
        ts=t_adm_succ,
        logid="0100032001",
        src_ip="198.51.100.42",
        dst_ip="10.0.0.1",
        user="root",
        action="login",
    )

    # 4. Planted: vpn_impossible_travel (alice from Japan then Germany within 20 mins)
    t_vpn = t_base + timedelta(hours=3)
    add_event(
        ts=t_vpn,
        action="ssl-login",
        subtype="vpn",
        user="alice",
        src_ip="198.51.100.80",
        srccountry="Japan",
    )
    add_event(
        ts=t_vpn + timedelta(minutes=20),
        action="tunnel-up",
        subtype="vpn",
        user="alice",
        src_ip="198.51.100.81",
        srccountry="Germany",
    )

    # 5. Planted: config_change (log disable edit)
    t_cfg = t_base + timedelta(hours=4)
    add_event(
        ts=t_cfg,
        logid="0100044546",
        action="Edit",
        user="sysadmin",
        src_ip="10.0.0.5",
        msg="Attribute 'status' of setting 'log disk setting' changed from 'enable' to 'disable'",
    )

    # 6. Planted: virus_detected_not_blocked (action = 'detected')
    t_vir = t_base + timedelta(hours=5)
    add_event(
        ts=t_vir,
        subtype="virus",
        virus="Trojan.Agent.Planted",
        action="detected",
        src_ip="198.51.100.99",
        dst_ip="10.0.0.2",
    )

    # 7. Planted: port_scan (198.51.100.55 -> 10.0.0.20 on 220 distinct ports within 3 mins)
    t_scan = t_base + timedelta(hours=6)
    for p in range(1, 221):
        add_event(
            ts=t_scan + timedelta(seconds=p * 0.5),
            src_ip="198.51.100.55",
            dst_ip="10.0.0.20",
            dst_port=p,
            action="deny",
        )

    # 8. Planted: lateral_fanout (internal 10.0.0.50 connecting to 15 internal hosts on port 445 in 30 mins)
    t_lat = t_base + timedelta(hours=7)
    for dst_idx in range(15):
        add_event(
            ts=t_lat + timedelta(minutes=dst_idx),
            src_ip="10.0.0.50",
            dst_ip=f"10.0.0.{100 + dst_idx}",
            dst_port=445,
            action="accept",
        )

    # 9. Planted: dns_tunnel (10.0.0.50 querying 60 distinct hostnames with 35-char first label under tunnel.org)
    t_dns = t_base + timedelta(hours=8)
    for d_idx in range(60):
        h = f"abcdefghijklmnopqrstuvwxyz123456789{d_idx:03d}.sub.tunnel.org"
        add_event(
            ts=t_dns + timedelta(seconds=d_idx),
            src_ip="10.0.0.50",
            dst_ip="10.0.0.2",
            hostname=h,
            subtype="dns",
        )

    # 10. Planted: beacon (10.0.0.60 -> 203.0.113.88:443 every 300s for 110 events, constant 500 bytes)
    t_bcn = t_base + timedelta(hours=10)
    for b_idx in range(110):
        add_event(
            ts=t_bcn + timedelta(seconds=b_idx * 300),
            src_ip="10.0.0.60",
            dst_ip="203.0.113.88",
            dst_port=443,
            sentbyte=500,
            rcvdbyte=200,
        )

    # 11. Planted: staged_exfil (10.0.0.70 -> 203.0.113.99 over 25 hours, 550 events, variable sentbyte vs 100 rcvd)
    t_exfil = t_base + timedelta(hours=1)
    for ex_idx in range(550):
        jitter = (ex_idx % 13) * 60
        s_bytes = 10000 + (ex_idx % 7) * 3000
        add_event(
            ts=t_exfil + timedelta(seconds=ex_idx * 170 + jitter),  # ~26 hours
            src_ip="10.0.0.70",
            dst_ip="203.0.113.99",
            dst_port=443,
            sentbyte=s_bytes,
            rcvdbyte=100,
        )

    # 12. Planted: web_payload (15 SQL injection requests from 198.51.100.77 to 10.0.0.2 within 5 mins)
    t_web = t_base + timedelta(hours=12)
    for w_idx in range(15):
        add_event(
            ts=t_web + timedelta(seconds=w_idx * 10),
            src_ip="198.51.100.77",
            dst_ip="10.0.0.2",
            url=f"/search?id={w_idx}%20UNION%20SELECT%20null%2Cusername%2Cpassword%20FROM%20users--",
        )

    # 13. Planted: flood (2100 SYN packets in 1 minute from 198.51.0.0/16 to 10.0.0.30:80)
    t_flood = t_base + timedelta(hours=14)
    for f_idx in range(2100):
        add_event(
            ts=t_flood + timedelta(seconds=(f_idx % 50)),
            src_ip=f"198.51.{(f_idx // 256) % 10}.{(f_idx % 250) + 1}",
            dst_ip="10.0.0.30",
            dst_port=80,
            sentpkt=1,
            rcvdpkt=0,
        )

    # Noise: Benign background events
    for n_idx in range(50):
        add_event(
            ts=t_base + timedelta(minutes=n_idx * 10),
            src_ip="10.0.0.10",
            dst_ip="8.8.8.8",
            dst_port=53,
            hostname="google.com",
            sentbyte=100,
            rcvdbyte=200,
        )
        add_event(
            ts=t_base + timedelta(minutes=n_idx * 10),
            src_ip="198.51.100.200",
            dst_ip="10.0.0.1",
            logid="0100032002",  # Only 1 failure, well below 500 burst
            user="test",
        )

    # Insert events into table
    con.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ev_rows)

    # Insert sample detections matching planted burst and admin success
    con.execute(
        """
        INSERT INTO detections VALUES
        ('det_burst_1', 'R_BURST', 'Brute Force Burst', 'T1110.001', 'Credential Access', 8, 'host1', ?, ?, 'inc_1', 0.95, 'Credential Access'),
        ('det_succ_1', 'R_SUCC', 'Admin Login Success', 'T1078.001', 'Initial Access', 8, 'host1', ?, ?, 'inc_1', 0.90, 'Initial Access')
        """,
        [t_base, json.dumps(burst_eids[:5]), t_adm_succ, json.dumps([adm_succ_eid])],
    )
    con.execute("INSERT INTO incidents VALUES ('inc_1')")

    for eid in burst_eids[:5]:
        con.execute("INSERT INTO detection_events VALUES ('det_burst_1', ?)", [eid])
    con.execute("INSERT INTO detection_events VALUES ('det_succ_1', ?)", [adm_succ_eid])

    return con


def test_silver_miners_planted_cases(silver_con):
    """Assert that each independent SQL oracle finds exactly its planted case."""
    # 1. failed_admin_burst
    r1, d1, sup1 = _mine_failed_admin_burst(silver_con, min_count=500)
    assert len(r1) == 1
    assert r1[0].src_ip == "198.51.100.1"
    assert r1[0].expected_technique == "T1110.001"
    assert r1[0].metric >= 500

    # 2. slow_stuffing_24
    r2, d2 = _mine_slow_stuffing_24(silver_con, min_ips=10, max_events=200, min_delta_seconds=120, max_delta_seconds=480)
    assert len(r2) == 1
    assert "203.0.113" in r2[0].src_ip
    assert r2[0].expected_technique == "T1110.004"

    # 3. admin_success
    r3, d3 = _mine_admin_success(silver_con)
    assert len(r3) == 1
    assert r3[0].user == "root"
    assert r3[0].sub_flags["after_failures"] is True
    assert r3[0].sub_flags["odd_hour"] is True

    # 4. vpn_impossible_travel
    r4, d4 = _mine_vpn_impossible_travel(silver_con, window_minutes=60)
    assert len(r4) == 1
    assert r4[0].user == "alice"
    assert r4[0].expected_technique == "T1078.004"
    assert r4[0].sub_flags["country_a"] != r4[0].sub_flags["country_b"]

    # 5. config_change
    r5, d5 = _mine_config_change(silver_con)
    assert len(r5) == 1
    assert r5[0].expected_technique == "T1562.002"
    assert "disable" in r5[0].sub_flags["msg"].lower()

    # 6. virus_detected_not_blocked
    r6, d6 = _mine_virus_detected_not_blocked(silver_con)
    assert len(r6) == 1
    assert r6[0].sub_flags["virus"] == "Trojan.Agent.Planted"
    assert r6[0].expected_technique == "T1105"

    # 7. port_scan
    r7, d7, sup7 = _mine_port_scan(silver_con, min_distinct_ports=200)
    assert len(r7) == 1
    assert r7[0].src_ip == "198.51.100.55"
    assert r7[0].metric >= 200

    # 8. lateral_fanout
    r8, d8 = _mine_lateral_fanout(silver_con, min_distinct_targets=10)
    assert len(r8) == 1
    assert r8[0].src_ip == "10.0.0.50"
    assert r8[0].metric >= 10

    # 9. dns_tunnel
    r9, d9 = _mine_dns_tunnel(silver_con, min_distinct_names=50, min_label_len=32)
    assert len(r9) == 1
    assert r9[0].src_ip == "10.0.0.50"
    assert "tunnel.org" in r9[0].sub_flags["registered_domain"]

    # 10. beacon
    r10, d10 = _mine_beacon(silver_con, min_count=100, min_duration_sec=21600, max_cv=0.15)
    assert len(r10) == 1
    assert r10[0].src_ip == "10.0.0.60"
    assert r10[0].dst_ip == "203.0.113.88"
    assert r10[0].metric <= 0.15

    # 11. staged_exfil
    r11, d11 = _mine_staged_exfil(silver_con, min_count=500, min_duration_sec=86400, min_ratio=1.5)
    assert len(r11) == 1
    assert r11[0].src_ip == "10.0.0.70"
    assert r11[0].metric >= 1.5

    # 12. web_payload
    r12, d12 = _mine_web_payload(silver_con, min_count=10)
    assert len(r12) == 1
    assert r12[0].src_ip == "198.51.100.77"
    assert r12[0].sub_flags["payload_class"] == "sqli"

    # 13. flood
    r13, d13, sup13 = _mine_flood(silver_con)
    assert len(r13) == 1
    assert r13[0].dst_ip == "10.0.0.30"
    assert r13[0].sub_flags["flood_type"] == "syn"


def test_silver_eval_scoring(silver_con):
    """Test full silver standard agreement scoring pipeline on synthetic database."""
    res = run_silver_eval(con=silver_con)

    assert res["banner"] == BANNER
    assert res["total_oracle_rows"] == 13
    assert res["matched_oracle_rows"] >= 2  # burst and admin_success matched our planted detections
    assert res["silver_recall"] > 0.0
    assert res["label_accuracy_exact"] == 1.0  # both matched detections have exact technique match
    assert res["incident_multi_class_coverage"] == 1  # inc_1 contains burst + admin_success sharing entity
    assert res["incident_ordered_coverage"] == 1  # Credential Access (7) -> Initial Access (2) or ordered

