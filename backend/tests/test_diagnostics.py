"""Tests for diagnostics and integrity reporting."""

from __future__ import annotations

from pathlib import Path

from app.pipeline.diagnose.diagnostics import compute_file_sha256, read_raw_line, run_diagnostics


def test_sha256_and_read_raw_line(tmp_path: Path):
    test_file = tmp_path / "sample.log"
    line1 = b"first line of log\n"
    line2 = b"second line with some details\n"
    test_file.write_bytes(line1 + line2)

    digest = compute_file_sha256(str(test_file))
    assert len(digest) == 64

    # Offset 0 is line 1
    read_line1 = read_raw_line(str(test_file), 0)
    assert read_line1 == "first line of log"

    # Offset of line 2
    offset_line2 = len(line1)
    read_line2 = read_raw_line(str(test_file), offset_line2)
    assert read_line2 == "second line with some details"


def test_run_diagnostics_mock(tmp_path: Path):
    docs_dir = tmp_path / "docs"
    # Create small log file
    log_file = tmp_path / "small.log"
    log_file.write_bytes(
        b'date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530" logid="1" devname="FGT"\n',
    )

    res = run_diagnostics(log_path=str(log_file), docs_dir=str(docs_dir))
    assert Path(res["integrity_report"]).exists()
    assert Path(res["full_line_examples"]).exists()
    assert Path(res["noise_profile"]).exists()
    assert res["time_offset_seconds"] == 19800
