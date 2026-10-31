"""Tests for log parsers and the chunker."""

from __future__ import annotations

import pytest
from app.pipeline.ingest.chunker import stream_events
from app.pipeline.ingest.parsers import cef, csv_parser, json_parser, syslog

# ---------------------------------------------------------------------------
# Syslog parser
# ---------------------------------------------------------------------------

class TestSyslogParser:
    def test_valid_rfc3164(self):
        line = "<34>Oct 31 12:00:00 web-server sshd[1234]: Accepted password for alice"
        ev = syslog.parse_line(line, "auth.log", "ev_0_0")
        assert ev is not None
        assert ev["host"] == "web-server"
        assert ev["process_name"] == "sshd"
        assert ev["pid"] == 1234
        assert ev["log_format"] == "syslog"
        assert ev["event_id"] == "ev_0_0"
        assert ev["ts"].tzinfo is not None

    def test_empty_line(self):
        assert syslog.parse_line("", "auth.log", "ev_0_0") is None

    def test_non_syslog(self):
        assert syslog.parse_line("just plain text without syslog format", "f", "e") is None


# ---------------------------------------------------------------------------
# JSON parser
# ---------------------------------------------------------------------------

class TestJsonParser:
    def test_wazuh_style(self):
        import json
        obj = {
            "timestamp": "2024-01-15T10:30:00Z",
            "agent": {"name": "server-01"},
            "data": {"srcip": "10.0.0.1", "command": "whoami"},
            "rule": {"id": 5503},
        }
        ev = json_parser.parse_line(json.dumps(obj), "wazuh.json", "ev_1_0")
        assert ev is not None
        assert ev["host"] == "server-01"
        assert ev["src_ip"] == "10.0.0.1"
        assert "5503" in ev["rule_ids"]
        assert ev["ts"].tzinfo is not None

    def test_flat_json(self):
        import json
        obj = {"ts": "2024-01-15T10:30:00Z", "host": "db01", "cmd": "select * from users"}
        ev = json_parser.parse_line(json.dumps(obj), "db.json", "ev_2_0")
        assert ev is not None
        assert ev["host"] == "db01"

    def test_invalid_json(self):
        assert json_parser.parse_line("{not valid}", "f", "e") is None

    def test_empty_line(self):
        assert json_parser.parse_line("", "f", "e") is None


# ---------------------------------------------------------------------------
# CEF parser
# ---------------------------------------------------------------------------

class TestCefParser:
    def test_basic_cef(self):
        line = (
            "CEF:0|Vendor|Product|1.0|100|Port scan detected|7|"
            "src=192.168.1.5 dst=10.0.0.2 dpt=8080 suser=attacker"
        )
        ev = cef.parse_line(line, "ids.cef", "ev_3_0")
        assert ev is not None
        assert ev["src_ip"] == "192.168.1.5"
        assert ev["dst_ip"] == "10.0.0.2"
        assert ev["dst_port"] == 8080
        assert ev["log_format"] == "cef"

    def test_empty_line(self):
        assert cef.parse_line("", "f", "e") is None

    def test_non_cef(self):
        assert cef.parse_line("just a syslog line", "f", "e") is None


# ---------------------------------------------------------------------------
# CSV parser
# ---------------------------------------------------------------------------

class TestCsvParser:
    def test_basic_csv(self):
        header = ["timestamp", "host", "user", "cmd"]
        ev = csv_parser.parse_line(
            "2024-01-15T10:30:00Z,web01,alice,ls -la",
            "access.csv",
            "ev_4_0",
            header=header,
        )
        assert ev is not None
        assert ev["host"] == "web01"
        assert ev["user_name"] == "alice"

    def test_no_header_returns_none(self):
        # No header → row treated as header definition
        result = csv_parser.parse_line("ts,host,user", "f.csv", "ev_0_0", header=None)
        assert result is None


# ---------------------------------------------------------------------------
# Chunker integration
# ---------------------------------------------------------------------------

class TestChunker:
    def test_streams_syslog(self, tmp_path):
        log = tmp_path / "test.log"
        lines = [
            "<34>Oct 31 12:00:00 host1 prog[100]: message one\n",
            "<34>Oct 31 12:00:01 host1 prog[101]: message two\n",
            "this is a malformed line\n",
        ]
        log.write_text("".join(lines))
        chunks = list(stream_events(str(log), file_index=0, chunk_size=100))
        assert len(chunks) == 1
        events, malformed, total = chunks[0]
        assert len(events) == 2
        assert malformed == 1
        assert total == 3

    def test_streams_json(self, tmp_path):
        import json
        log = tmp_path / "events.json"
        entries = [
            {"timestamp": "2024-01-15T10:00:00Z", "host": {"hostname": "srv"}, "data": {}},
            {"timestamp": "2024-01-15T10:00:01Z", "host": {"hostname": "srv"}, "data": {}},
            "NOT JSON",
        ]
        log.write_text("\n".join(
            json.dumps(e) if isinstance(e, dict) else e for e in entries
        ) + "\n")
        chunks = list(stream_events(str(log), file_index=1, chunk_size=100))
        total_events = sum(len(c[0]) for c in chunks)
        total_malformed = sum(c[1] for c in chunks)
        assert total_events == 2
        assert total_malformed == 1

    def test_chunk_size_respected(self, tmp_path):
        log = tmp_path / "big.jsonl"
        import json
        lines = [json.dumps({"timestamp": "2024-01-15T10:00:00Z", "hostname": "h", "data": {}})
                 for _ in range(250)]
        log.write_text("\n".join(lines) + "\n")
        chunks = list(stream_events(str(log), file_index=2, chunk_size=100))
        # 250 events ÷ 100 = 3 chunks (100 + 100 + 50)
        assert len(chunks) == 3
        assert len(chunks[0][0]) == 100
        assert len(chunks[2][0]) == 50

    def test_nonexistent_file(self):
        """stream_events on a missing file yields nothing and does not crash."""
        # File doesn't exist → open raises, caller (runner) skips it
        with pytest.raises(FileNotFoundError):
            list(stream_events("/no/such/file.log", file_index=0))
