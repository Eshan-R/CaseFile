"""Unit tests for FortiGate KV parser."""

from __future__ import annotations

import json

from app.pipeline.ingest.parsers import fortigate_kv


def test_time_rule_utc_conversion():
    """Verify TIME RULE: eventtime is local wall clock stored as UTC.
    
    True UTC = date + time converted from tz (tz="+0530" means subtract 5h30m).
    """
    line = 'date=2026-10-23 time=08:48:26 tz="+0530" eventtime=1792745306000000000 logid="0000000013" devname="FGT60"'
    ev = fortigate_kv.parse_line(line, "firex.log", 1000)
    assert ev is not None
    assert ev["timestamp"] == "2026-10-23T03:18:26Z"
    assert ev["eventtime_ns"] == 1792745306000000000
    assert ev["source_offset"] == 1000
    assert ev["event_id"] == "ev_0_1000"


def test_malformed_lines():
    """Lines without date= or logid= return None and count as malformed."""
    assert fortigate_kv.parse_line("just some text", "f.log", 0) is None
    assert fortigate_kv.parse_line("date=2026-10-23 time=12:00:00", "f.log", 0) is None  # no logid
    assert fortigate_kv.parse_line("logid=12345 type=traffic", "f.log", 0) is None  # no date
    assert fortigate_kv.parse_line("", "f.log", 0) is None


def test_quoted_values_escaped_quotes_and_empty():
    """Test values with spaces, escaped quotes, and empty values."""
    line = (
        r'date=2026-10-23 time=10:00:00 logid="100" tz="-0400" '
        r'msg="User \"admin\" login failed" empty_val="" bare_empty= '
        r'custom_key="some extra data" srcip=10.0.0.1 dstip=8.8.8.8 '
        r'user="CORP\Administrator"'
    )
    ev = fortigate_kv.parse_line(line, "f.log", 42)
    assert ev is not None
    assert ev["timestamp"] == "2026-10-23T14:00:00Z"  # -0400 -> +4 hours
    assert ev["msg"] == 'User "admin" login failed'
    assert ev["host"] == "10.0.0.1"
    assert ev["user"] == "administrator"
    assert ev["user_raw"] == r"CORP\Administrator"
    assert ev["event_id"] == "ev_0_42"
    
    # Check extra JSON
    assert ev["extra"] is not None
    extra = json.loads(ev["extra"])
    assert extra.get("custom_key") == "some extra data"
    assert extra.get("empty_val") == ""
    assert extra.get("bare_empty") == ""


def test_rfc1918_host_determination():
    """Host should be private srcip, else private dstip, else None."""
    # Private src, public dst
    line1 = 'date=2026-10-23 time=00:00:00 logid="1" tz="+0000" srcip=192.168.1.50 dstip=1.1.1.1'
    ev1 = fortigate_kv.parse_line(line1, "f.log", 0)
    assert ev1["host"] == "192.168.1.50"

    # Public src, private dst
    line2 = 'date=2026-10-23 time=00:00:00 logid="1" tz="+0000" srcip=200.200.200.1 dstip=172.20.10.5'
    ev2 = fortigate_kv.parse_line(line2, "f.log", 0)
    assert ev2["host"] == "172.20.10.5"

    # Both public
    line3 = 'date=2026-10-23 time=00:00:00 logid="1" tz="+0000" srcip=200.200.200.1 dstip=8.8.8.8'
    ev3 = fortigate_kv.parse_line(line3, "f.log", 0)
    assert ev3["host"] is None


def test_real_log_line():
    """Parse real line from FortiGate dataset."""
    line = (
        'date=2026-10-23 time=08:48:26 eventtime=1792745306564464000 tz="+0530" '
        'devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" '
        'type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" '
        'user="admin" ui="https(209.50.167.232)" method="https" srcip=209.50.167.232 '
        'srcintf="wan1" srcintfrole="wan" dstip=10.10.99.1 dstintf="mgmt" dstintfrole="lan" '
        'proto=6 action="login" srccountry="India" dstcountry="Reserved" status="failed" '
        'reason="name_invalid" msg="Administrator admin login failed from https(209.50.167.232)"'
    )
    ev = fortigate_kv.parse_line(line, "firex-10G.log", 500)
    assert ev is not None
    assert ev["timestamp"] == "2026-10-23T03:18:26Z"
    assert ev["host"] == "10.10.99.1"
    assert ev["user"] == "admin"
    assert ev["outcome"] == "failure"
    assert ev["event_type"] == "event/system"
    assert ev["event_id"] == "ev_0_500"
