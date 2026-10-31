"""CSV log parser – generic delimiter-separated files with a header row."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

_TS_FIELDS = ("timestamp", "ts", "@timestamp", "time", "datetime", "date")
_HOST_FIELDS = ("host", "hostname", "computer", "device", "machine")


def _parse_ts(val: str) -> datetime:
    val = val.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(val, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            continue
    return datetime.now(UTC)


def _find(row: dict, fields: tuple) -> str | None:
    for f in fields:
        v = row.get(f)
        if v:
            return v
    return None


def parse_line(line: str, source_file: str, event_id: str,
               header: list[str] | None = None) -> dict | None:
    """Parse one CSV data row. header must be provided for non-header rows."""
    line = line.strip()
    if not line:
        return None
    reader = csv.reader(io.StringIO(line))
    try:
        values = next(reader)
    except StopIteration:
        return None
    if not header:
        # Treat as header – return None (caller stores the header)
        return None

    row = dict(zip(header, values))
    ts_raw = _find(row, _TS_FIELDS)

    return {
        "event_id": event_id,
        "ts": _parse_ts(ts_raw) if ts_raw else datetime.now(UTC),
        "host": _find(row, _HOST_FIELDS) or "unknown",
        "source_file": source_file,
        "log_format": "csv",
        "raw": line,
        "user_name": row.get("user") or row.get("username"),
        "src_ip": row.get("src_ip") or row.get("srcip"),
        "dst_ip": row.get("dst_ip") or row.get("dstip"),
        "process_name": row.get("process") or row.get("process_name"),
        "cmd": row.get("command") or row.get("cmd"),
        "file_path": row.get("file") or row.get("file_path"),
        "rule_ids": [],
    }

