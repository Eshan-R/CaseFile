"""CEF (Common Event Format) log parser."""

from __future__ import annotations

import re
from datetime import UTC, datetime

# CEF header: CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extensions
_CEF_HDR = re.compile(
    r"^(?:.*?)?CEF:(?P<ver>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<devver>[^|]*)\|(?P<sigid>[^|]*)\|(?P<name>[^|]*)\|(?P<sev>[^|]*)\|(?P<ext>.*)$"
)
_TS_RE = re.compile(r"rt=(\d+)")


def _parse_ext(ext: str) -> dict:
    """Parse CEF extension key=value pairs (handles quoted values and spaces)."""
    result: dict = {}
    # Split on space followed by a word= pattern
    tokens = re.split(r" (?=\w+=)", ext)
    for t in tokens:
        if "=" in t:
            k, _, v = t.partition("=")
            result[k.strip()] = v.strip()
    return result


def parse_line(line: str, source_file: str, event_id: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    m = _CEF_HDR.match(line)
    if not m:
        return None
    ext = _parse_ext(m.group("ext"))

    # Timestamp from rt (epoch ms) or start
    ts = datetime.now(UTC)
    rt = ext.get("rt") or ext.get("start")
    if rt:
        try:
            ts = datetime.fromtimestamp(int(rt) / 1000, tz=UTC)
        except (ValueError, OSError):
            pass

    host = ext.get("dhost") or ext.get("shost") or "unknown"

    return {
        "event_id": event_id,
        "ts": ts,
        "host": host,
        "source_file": source_file,
        "log_format": "cef",
        "raw": line,
        "user_name": ext.get("duser") or ext.get("suser"),
        "src_ip": ext.get("src"),
        "dst_ip": ext.get("dst"),
        "dst_port": int(ext["dpt"]) if ext.get("dpt", "").isdigit() else None,
        "process_name": ext.get("app"),
        "cmd": ext.get("cs1") or m.group("name"),
        "rule_ids": [m.group("sigid")] if m.group("sigid") else [],
    }

