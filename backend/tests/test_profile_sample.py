"""Unit tests for CaseFile log profiler (scripts/profile_sample.py).

Tests format classification, seeking sampling, chunk plan validity,
and label hint detection on a 5 MB synthetic mixed-format dataset.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.profile_sample import (  # noqa: E402
    check_manifest_offsets,
    check_timezone_and_timestamps,
    detect_format,
    profile_file_mode1,
    profile_windows_stream,
    verify_chunk_plan,
    verify_manifest_sizes,
    write_reports,
)


def create_mixed_format_file(target_path: Path, target_size_bytes: int = 5 * 1024 * 1024) -> None:
    """Generate a synthetic mixed-format security log file (~5 MB)."""
    line_templates = [
        # 1. JSON / NDJSON
        (
            b'{"event_time": "2026-03-31T10:00:00Z", "host": "web-srv-01", "user": "admin", '
            b'"src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "action": "login_success", '
            b'"technique": "T1078"}\n'
        ),
        # 2. CEF
        (
            b"CEF:0|Fortinet|FortiGate|7.0|1000|IPS Alert|8|src=192.168.1.50 dst=10.0.0.2 "
            b"msg=Exploit attempt attack=T1190 rt=1672531199000 proto=tcp\n"
        ),
        # 3. Syslog (RFC 3164)
        (
            b"<34>Oct 11 22:14:15 host-app-02 sshd[4012]: Failed password for invalid user root "
            b"from 192.168.1.200 port 22 ssh2\n"
        ),
        # 4. Key=Value
        (
            b'date=2026-03-31 time=12:00:01 devname="FW-CORP-01" srcip=192.168.1.20 dstip=172.16.0.4 '
            b'action=deny attack="Citrix.Gateway.Traversal" attackid=49201 severity=high subtype=ips\n'
        ),
        # 5. Broken / Other binary garbage
        b"corrupted binary packet sequence \x00\x01\x02\x03\xff\xfe\x00\x08 not printable bytes\n",
    ]

    bytes_written = 0
    idx = 0
    with open(target_path, "wb") as f:
        while bytes_written < target_size_bytes:
            sample = line_templates[idx % len(line_templates)]
            f.write(sample)
            bytes_written += len(sample)
            idx += 1


def test_format_detector_individual_lines() -> None:
    """Test format classifier against representative samples of each format."""
    assert detect_format('{"msg": "test", "status": "ok"}') == "JSON / NDJSON"
    assert (
        detect_format('{"ecs": {"version": "1.0"}, "host": {"name": "srv"}}')
        == "ECS-style nested JSON"
    )
    assert (
        detect_format("CEF:0|Vendor|Product|1.0|100|Event Name|5|src=1.1.1.1")
        == 'CEF ("CEF:0|...")'
    )
    assert (
        detect_format("<34>Oct 11 22:14:15 myhost sshd[123]: Accepted publickey")
        == "syslog"
    )
    assert (
        detect_format('date=2026-01-01 time=10:00:00 devname="FGT" srcip=10.0.0.1 action=allow')
        == "CSV or key=value"
    )
    assert detect_format("\x00\x01\x02 corrupted raw binary \xff\xfe") == "other"
    assert detect_format("   \n") == "blank"


def test_profile_sample_mode1_mixed_5mb(tmp_path: Path) -> None:
    """End-to-end test of Mode 1 on a 5 MB mixed-format dataset.

    Asserts:
    1. Format percentages sum to 100% within 0.1%.
    2. Each format's sample count > 0 (JSON, CEF, syslog, key=value, other).
    3. The chunk plan self-check passes (contiguous, non-overlapping, covers file).
    4. At least one label hint is detected (e.g. technique T1078 or T1190 or attack field).
    5. Required artifacts (data_profile.md, format_samples.json, chunk_plan.json) are written.
    """
    test_log = tmp_path / "mixed_sample_5mb.log"
    create_mixed_format_file(test_log, target_size_bytes=5 * 1024 * 1024)
    file_size = test_log.stat().st_size
    assert file_size >= 5 * 1024 * 1024

    output_dir = tmp_path / "docs"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run profiler Mode 1
    data = profile_file_mode1(str(test_log), output_dir=str(output_dir))

    # 1. Total sampled lines and format percentages sum to 100% within 0.1%
    total_sampled = data["total_sampled_lines"]
    assert total_sampled > 0
    format_counts = data["format_counts"]

    total_format_lines = sum(format_counts.values())
    assert total_format_lines == total_sampled

    total_pct = sum((cnt / total_sampled) * 100.0 for cnt in format_counts.values())
    assert abs(total_pct - 100.0) < 0.1, f"Percentages sum to {total_pct}, expected 100.0 ± 0.1"

    # 2. Each format's sample count > 0
    # Note: JSON lines could be classified as "JSON / NDJSON" or "ECS-style nested JSON"
    json_count = format_counts.get("JSON / NDJSON", 0) + format_counts.get("ECS-style nested JSON", 0)
    assert json_count > 0, "Expected JSON lines in sample"
    assert format_counts.get('CEF ("CEF:0|...")', 0) > 0, "Expected CEF lines in sample"
    assert format_counts.get("syslog", 0) > 0, "Expected syslog lines in sample"
    assert format_counts.get("CSV or key=value", 0) > 0, "Expected key=value lines in sample"
    assert format_counts.get("other", 0) > 0, "Expected other/corrupted lines in sample"

    # 3. Chunk plan self-check passes
    assert data["chunk_plan_valid"] is True
    chunk_ranges = data["chunk_ranges"]
    assert len(chunk_ranges) > 0
    assert verify_chunk_plan(chunk_ranges, file_size) is True

    # Check boundaries of chunk plan
    assert chunk_ranges[0][0] == 0
    assert chunk_ranges[-1][1] == file_size

    # 4. At least one label hint is detected
    label_field_counts = data["label_field_counts"]
    assert len(label_field_counts) > 0, "Expected attack/label fields to be detected"
    # Check that 'attack' or 'technique' was found
    assert any(k in label_field_counts for k in ("attack", "technique", "attackid", "severity"))

    # Attack candidates / pre-tagged examples
    assert len(data["tagged_examples"]) > 0 or len(data["attack_candidates"]) > 0

    # 5. Verify write_reports generates valid output files
    md_path, json_path, chunk_path = write_reports(data, output_dir=str(output_dir))
    assert Path(md_path).is_file()
    assert Path(json_path).is_file()
    assert Path(chunk_path).is_file()

    # Verify JSON files are valid and parseable
    with open(chunk_path, encoding="utf-8") as f:
        loaded_chunks = json.load(f)
        assert len(loaded_chunks) == len(chunk_ranges)

    with open(json_path, encoding="utf-8") as f:
        loaded_fmt = json.load(f)
        assert len(loaded_fmt) >= 4  # JSON, CEF, syslog, key=value

    # Verify markdown report contains essential sections
    with open(md_path, encoding="utf-8") as f:
        md_text = f.read()
        assert "# CaseFile Data Profile:" in md_text
        assert "## 1. File Overview & Line Estimates" in md_text
        assert "## 2. Formats & Distribution" in md_text
        assert "## 6. Label Hints & Ground Truth Assessment" in md_text
        assert "## 10. Chunk Plan for Parallel Ingest" in md_text


def test_nonexistent_path_exit_2() -> None:
    """Non-existent path must print error and exit with code 2."""
    import pytest

    from scripts.profile_sample import profile_target

    with pytest.raises(SystemExit) as exc_info:
        profile_target("non_existent_file_1234567.log", is_full=False, workers=None)
    assert exc_info.value.code == 2


def test_windows_stream_profiling(tmp_path: Path) -> None:
    """Test Windows .jsonl stream profiling and EventID extraction."""
    win_file = tmp_path / "test_win.jsonl"
    events = [
        {"EventID": 4624, "Computer": "DC01.corp.local", "TargetUserName": "admin", "IpAddress": "10.10.10.50"},
        {"EventID": 4625, "Computer": "DC01.corp.local", "TargetUserName": "guest", "IpAddress": "10.10.10.50"},
        {"EventID": 4624, "Computer": "WEB01.corp.local", "TargetUserName": "svc_iis95", "IpAddress": "10.10.20.20"},
        {"EventID": 4769, "Computer": "DC01.corp.local", "TargetUserName": "kunal.sinha", "ServiceName": "MSSQLSvc"},
        {"EventID": 7045, "Computer": "DC01.corp.local", "ServiceName": "psexesvc"},
    ]
    with open(win_file, "w", encoding="utf-8") as f:
        for ev in events * 20:
            f.write(json.dumps(ev) + "\n")

    profile_res = profile_windows_stream(str(win_file))
    assert profile_res["exists"] is True
    assert profile_res["total_sampled_lines"] == 100
    assert "4624" in profile_res["event_id_counter"]
    assert "4625" in profile_res["event_id_counter"]
    assert "4769" in profile_res["event_id_counter"]
    assert "7045" in profile_res["event_id_counter"]
    assert len(profile_res["event_id_examples"]["4624"]) > 0


def test_manifest_size_verification_and_mismatch(tmp_path: Path) -> None:
    """Test manifest size verification logic when matching vs mismatching."""
    fw_file = tmp_path / "fw.log"
    fw_file.write_text("sample firewall line 1\nsample firewall line 2\n", encoding="utf-8")
    fw_size = fw_file.stat().st_size

    # 1. Matching manifest
    matching_manifest = {
        "bytes": fw_size,
        "windows_bytes": None,
        "incidents": [],
    }
    is_match, _msg, mismatches = verify_manifest_sizes(matching_manifest, str(fw_file), None)
    assert is_match is True
    assert len(mismatches) == 0

    # 2. Mismatch manifest
    mismatch_manifest = {
        "bytes": fw_size + 99999,
        "windows_bytes": 50000,
        "incidents": [],
    }
    is_match, msg, mismatches = verify_manifest_sizes(mismatch_manifest, str(fw_file), None)
    assert is_match is False
    assert len(mismatches) >= 1
    assert "MISMATCH" in msg


def test_manifest_offset_check_and_timezone(tmp_path: Path) -> None:
    """Test seeking to byte offsets, checking newline boundary, and timezone formatting."""
    fw_file = tmp_path / "firewall.log"
    line1 = "date=2026-10-24 time=10:00:00 devname=FW srcip=168.168.208.87 action=deny msg=Failed\n"
    line2 = "date=2026-10-24 time=10:01:00 devname=FW srcip=168.168.208.87 action=deny msg=Failed\n"
    line3 = "date=2026-10-24 time=10:02:00 devname=FW srcip=168.168.208.87 action=deny msg=Failed\n"

    with open(fw_file, "w", encoding="utf-8") as f:
        offset0 = f.tell()
        f.write(line1)
        offset1 = f.tell()
        f.write(line2)
        offset2 = f.tell()
        f.write(line3)

    manifest = {
        "bytes": fw_file.stat().st_size,
        "covers": "2026-10-23 08:48:37 .. 2026-10-30 08:48:37 +0530",
        "incidents": [
            {
                "id": 1,
                "class": "easy",
                "name": "brute-force-burst",
                "attack": "T1110.001",
                "tactic": "Credential Access",
                "src": "168.168.208.87",
                "indicator": "source 168.168.208.87",
                "from": "2026-10-24 10:00:00",
                "to": "2026-10-24 10:02:00",
                "at": [
                    [1, offset0, 0],
                    [2, offset1, 0],
                    [3, offset2, 0],
                ],
            }
        ],
    }

    # Offset check
    res = check_manifest_offsets(manifest, str(fw_file), None)
    assert res["total_checks"] == 3
    assert res["newline_aligned_count"] == 3
    assert res["indicator_matches"] == 3
    assert res["indicator_rate"] == 100.0

    # Timezone check
    tz_str = check_timezone_and_timestamps(manifest, res)
    assert "+0530" in tz_str
    assert "Indian Standard Time" in tz_str

