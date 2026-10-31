"""Tests for the FortiGate parser and chunked Parquet ingest pipeline."""

from __future__ import annotations

import json
from pathlib import Path

from app.pipeline.ingest.parsers import fortigate_kv
from app.pipeline.ingest.runner import compute_chunk_ranges, run_ingest
from app.store import duck


def test_parser_quoted_values_escaped_quotes_and_empty():
    """Test quoted values with spaces, escaped quotes, bare/quoted empty values."""
    line = (
        r'date=2026-10-23 time=10:00:00 logid="0100032002" tz="+0530" '
        r'msg="User \"john doe\" logged in" empty_bare= empty_quoted="" '
        r'custom_field="extra value" srcip=10.0.0.5 dstip=8.8.8.8'
    )
    res = fortigate_kv.parse_line(line, "test.log", 123)
    assert res is not None
    assert res["msg"] == 'User "john doe" logged in'
    assert res["timestamp"] == "2026-10-23T04:30:00Z"
    assert res["event_id"] == "ev_0_123"
    assert res["host"] == "10.0.0.5"

    extra = json.loads(res["extra"])
    assert extra["empty_bare"] == ""
    assert extra["empty_quoted"] == ""
    assert extra["custom_field"] == "extra value"


def test_parser_crlf_and_binary_garbage():
    """Parser handles CRLF line endings and rejects binary garbage."""
    line_crlf = (
        'date=2026-10-23 time=08:48:26 tz="+0530" logid="0000000013" '
        'srcip=10.10.10.1 dstip=1.1.1.1\r\n'
    )
    res = fortigate_kv.parse_line(line_crlf, "test.log", 0)
    assert res is not None
    assert res["timestamp"] == "2026-10-23T03:18:26Z"

    # Binary garbage
    garbage1 = "\x00\x01\x02\xff\xfe random binary data without date"
    assert fortigate_kv.parse_line(garbage1, "test.log", 10) is None

    garbage2 = "date=invalid-date time=invalid logid=123"
    assert fortigate_kv.parse_line(garbage2, "test.log", 20) is None


def test_time_rule_exact_utc():
    """TIME RULE: eventtime is local wall-clock time stored as if it were UTC.
    
    True UTC = date + time converted from tz (tz="+0530" means subtract 5h30m).
    """
    line = 'date=2026-10-23 time=08:48:26 tz="+0530" eventtime=1792745306000000000 logid="100"'
    ev = fortigate_kv.parse_line(line, "firex.log", 500)
    assert ev is not None
    assert ev["timestamp"] == "2026-10-23T03:18:26Z"
    assert ev["eventtime_ns"] == 1792745306000000000


def test_offset_round_trip(tmp_path: Path):
    """Offset round trip: seek to source_offset and get the exact same line back."""
    lines = [
        'date=2026-10-23 time=08:48:26 tz="+0530" logid="101" srcip=10.0.0.1 dstip=1.1.1.1 msg="line 1"\n',
        'date=2026-10-23 time=08:48:27 tz="+0530" logid="102" srcip=10.0.0.2 dstip=1.1.1.1 msg="line 2"\n',
        'date=2026-10-23 time=08:48:28 tz="+0530" logid="103" srcip=10.0.0.3 dstip=1.1.1.1 msg="line 3 with more text"\n',
    ]
    log_file = tmp_path / "round_trip.log"
    content = "".join(lines)
    log_file.write_bytes(content.encode("utf-8"))

    # Ingest file
    out_dir = tmp_path / "parquet"
    res = run_ingest(
        job_id="test_offset",
        paths=[str(log_file)],
        chunk_size=100,
        out_base_dir=str(out_dir),
    )
    assert res["total_events"] == 3

    # Load manifest to get chunks and verify offsets
    manifest_file = out_dir / "_manifest.json"
    assert manifest_file.exists()

    with open(log_file, "rb") as f:
        # Seek to offset of line 2 and line 3
        expected_line2 = lines[1].encode("utf-8")
        expected_line3 = lines[2].encode("utf-8")

        offset_line2 = len(lines[0].encode("utf-8"))
        offset_line3 = offset_line2 + len(lines[1].encode("utf-8"))

        f.seek(offset_line2)
        actual_line2 = f.readline()
        assert actual_line2 == expected_line2

        f.seek(offset_line3)
        actual_line3 = f.readline()
        assert actual_line3 == expected_line3


def test_chunk_boundary_no_straddling_or_duplicates(tmp_path: Path):
    """Ensure a line straddling nominal chunk boundaries is parsed exactly once."""
    log_file = tmp_path / "boundary.log"
    # Create 20 lines, each ~100 bytes
    lines = [
        f'date=2026-10-23 time=08:48:{i:02d} tz="+0530" logid="000{i:03d}" srcip=10.0.0.{i} dstip=1.1.1.1 msg="Event number {i} padding extra text here"\n'
        for i in range(20)
    ]
    log_file.write_bytes("".join(lines).encode("utf-8"))

    # Use small chunk size (150 bytes) so lines fall across boundaries
    ranges = compute_chunk_ranges(str(log_file), chunk_size=150)
    assert len(ranges) > 1

    out_dir = tmp_path / "parquet_boundary"
    res = run_ingest(
        job_id="test_boundary",
        paths=[str(log_file)],
        chunk_size=150,
        out_base_dir=str(out_dir),
    )

    # All 20 lines must be parsed, 0 malformed, exactly once
    assert res["total_lines"] == 20
    assert res["total_events"] == 20
    assert res["malformed_lines"] == 0

    # Verify via DuckDB view
    duck.ensure_events_view(str(out_dir))
    total_events = duck.count_events()
    assert total_events == 20


def test_malformed_counts_and_skip_bad(tmp_path: Path):
    """Test reporting of malformed lines and skip-bad handling."""
    log_file = tmp_path / "mixed.log"
    valid_line = 'date=2026-10-23 time=08:48:00 tz="+0530" logid="1" srcip=10.0.0.1 dstip=1.1.1.1\n'
    bad_line1 = "Not a log line at all\n"
    bad_line2 = "date=2026-10-23 time=12:00:00 missing_logid=1\n"
    content = valid_line + bad_line1 + valid_line + bad_line2

    log_file.write_text(content, encoding="utf-8")
    out_dir = tmp_path / "parquet_mixed"
    res = run_ingest(
        job_id="test_mixed",
        paths=[str(log_file)],
        chunk_size=1000,
        out_base_dir=str(out_dir),
    )
    assert res["total_lines"] == 4
    assert res["total_events"] == 2
    assert res["malformed_lines"] == 2
