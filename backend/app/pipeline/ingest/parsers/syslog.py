"""Log format parsers – syslog (RFC 3164/5424)."""

from __future__ import annotations

import re
from datetime import UTC, datetime

_SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<ts>\w{3}\s+\d+\s[\d:]+|\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s"
    r"(?P<host>\S+)\s(?P<prog>\S+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

_MONTHS = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], 1
)}


def _parse_ts(ts_str: str) -> datetime:
    """Parse RFC 3164 or ISO 8601 timestamp → UTC datetime."""
    ts_str = ts_str.strip()
    if "T" in ts_str:
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            pass
    # RFC 3164: "Oct 31 12:34:56"
    parts = ts_str.split()
    if len(parts) == 3:
        month = _MONTHS.get(parts[0])
        if month:
            now = datetime.now(UTC)
            try:
                h, m, s = map(int, parts[2].split(":"))
                return datetime(now.year, month, int(parts[1]), h, m, s, tzinfo=UTC)
            except ValueError:
                pass
    return datetime.now(UTC)


def parse_line(line: str, source_file: str, event_id: str) -> dict | None:
    """Return a normalised event dict or None if the line cannot be parsed."""
    line = line.strip()
    if not line:
        return None
    m = _SYSLOG_RE.match(line)
    if not m:
        return None
    ts = _parse_ts(m.group("ts"))
    return {
        "event_id": event_id,
        "ts": ts,
        "host": m.group("host"),
        "source_file": source_file,
        "log_format": "syslog",
        "raw": line,
        "process_name": m.group("prog"),
        "pid": int(m.group("pid")) if m.group("pid") else None,
        "cmd": m.group("msg"),
        "rule_ids": [],
    }

