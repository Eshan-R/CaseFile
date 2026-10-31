"""JSON log parser (one JSON object per line, e.g. Wazuh alerts)."""

from __future__ import annotations

import json
from datetime import UTC, datetime


def _parse_ts(val: str | None) -> datetime:
    if not val:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)


def parse_line(line: str, source_file: str, event_id: str) -> dict | None:
    """Parse a single JSON log line."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    # Support Wazuh-style nested and flat JSON
    ts_val = (
        obj.get("timestamp")
        or obj.get("@timestamp")
        or obj.get("ts")
    )
    raw_host = obj.get("host")
    if isinstance(raw_host, dict):
        host = (
            raw_host.get("hostname")
            or raw_host.get("name")
            or "unknown"
        )
    elif isinstance(raw_host, str) and raw_host:
        host = raw_host
    else:
        host = (
            obj.get("agent", {}).get("name")
            or obj.get("hostname")
            or "unknown"
        )

    data = obj.get("data", {}) or {}
    syscheck = obj.get("syscheck", {}) or {}
    rule = obj.get("rule", {}) or {}

    return {
        "event_id": event_id,
        "ts": _parse_ts(ts_val),
        "host": str(host),
        "source_file": source_file,
        "log_format": "json",
        "raw": line,
        "user_name": data.get("srcuser") or data.get("dstuser") or obj.get("user"),
        "process_name": data.get("process") or obj.get("process_name"),
        "src_ip": data.get("srcip") or obj.get("src_ip"),
        "dst_ip": data.get("dstip") or obj.get("dst_ip"),
        "file_path": syscheck.get("path") or data.get("file"),
        "cmd": data.get("command"),
        "rule_ids": [str(rule["id"])] if rule.get("id") else [],
    }
