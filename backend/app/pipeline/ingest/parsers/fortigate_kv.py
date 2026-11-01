"""FortiGate key=value log parser.

Single-pass tokenizer for lines like:
date=2026-10-23 time=08:48:26 eventtime=1792745306564464000 tz="+0530" devname="FGT60FTK00000000" ...
"""

from __future__ import annotations

import functools
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Load knowledge map
_FORTIGATE_MAP_PATH = Path(__file__).resolve().parents[4] / "knowledge" / "fortigate_map.yaml"
_STATUS_MAP: dict[str, str] = {
    "failed": "failure",
    "failure": "failure",
    "success": "success",
    "successful": "success",
    "passthrough": "allowed",
    "timeout": "failure",
}
_ACTION_MAP: dict[str, str] = {
    "deny": "blocked",
    "block": "blocked",
    "blocked": "blocked",
    "drop": "blocked",
    "dropped": "blocked",
    "reset": "blocked",
    "reset-both": "blocked",
    "reset-client": "blocked",
    "reset-server": "blocked",
    "client-rst": "blocked",
    "server-rst": "blocked",
    "accept": "allowed",
    "pass": "allowed",
    "permit": "allowed",
    "allow": "allowed",
    "ip-conn": "allowed",
    "start": "allowed",
    "dns": "allowed",
}
_REASON_MAP: dict[str, str] = {
    "name_invalid": "failure",
    "password_invalid": "failure",
    "auth_failure": "failure",
    "timeout": "failure",
}
_LOGID_MAP: dict[str, str] = {
    "0100032002": "failure",
    "0100032001": "success",
    "0100032003": "failure",
    "0000000013": "allowed",
    "0000000020": "blocked",
}

if _FORTIGATE_MAP_PATH.exists():
    try:
        import yaml
        with open(_FORTIGATE_MAP_PATH, encoding="utf-8") as f:
            _map_data = yaml.safe_load(f) or {}
            _STATUS_MAP.update(_map_data.get("status_map", {}))
            _ACTION_MAP.update(_map_data.get("action_map", {}))
            _REASON_MAP.update(_map_data.get("reason_map", {}))
            _LOGID_MAP.update(_map_data.get("logid_map", {}))
    except Exception:
        pass


KNOWN_FIELDS = {
    "action", "app", "appcat", "apprisk", "attack", "attackid", "catdesc",
    "devid", "devname", "dstcountry", "dstintf", "dstintfrole", "dstip",
    "dstport", "duration", "hostname", "level", "logdesc", "logid", "method",
    "msg", "policyid", "proto", "rcvdbyte", "rcvdpkt", "reason", "sentbyte",
    "sentpkt", "service", "sessionid", "severity", "srccountry", "srcintf",
    "srcintfrole", "srcip", "srcport", "status", "subtype", "type", "ui",
    "url", "user", "vd", "virus",
}

METADATA_FIELDS = {"date", "time", "eventtime", "tz"}


def is_rfc1918(ip: str | None) -> bool:
    """Return True if ip is a private RFC1918 IPv4 address."""
    if not ip:
        return False
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        dot2 = ip.find(".", 4)
        if dot2 != -1:
            octet = ip[4:dot2]
            if octet.isdigit():
                val = int(octet)
                return 16 <= val <= 31
    return False


def parse_tz_offset_seconds(tz_str: str) -> int:
    """Parse timezone string (+hhmm / -hhmm / +hh:mm / -hh:mm) to seconds offset."""
    s = tz_str.strip('"\'')
    if not s:
        return 0
    sign = -1 if s[0] == "-" else 1
    digits = s.lstrip("+-").replace(":", "")
    if len(digits) >= 4:
        hh = int(digits[:2])
        mm = int(digits[2:4])
        return sign * (hh * 3600 + mm * 60)
    elif len(digits) >= 1:
        hh = int(digits[:2])
        return sign * hh * 3600
    return 0


@functools.lru_cache(maxsize=8192)
def format_iso8601(date_str: str, time_str: str | None, tz_str: str) -> str | None:
    """Parse date, time, and timezone offset into UTC ISO-8601 string, cached via LRU."""
    try:
        offset_sec = parse_tz_offset_seconds(tz_str)
        y = int(date_str[:4])
        m = int(date_str[5:7])
        d = int(date_str[8:10])
        t_str = time_str or "00:00:00"
        hh = int(t_str[:2])
        mm = int(t_str[3:5])
        ss = int(t_str[6:8])
        dt_local = datetime(y, m, d, hh, mm, ss)
        dt_utc = dt_local - timedelta(seconds=offset_sec)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def determine_outcome(kv: dict[str, str]) -> str:
    """Determine outcome from status, reason, action, or logid."""
    status = kv.get("status")
    if status and status in _STATUS_MAP:
        return _STATUS_MAP[status]

    reason = kv.get("reason")
    if reason and reason in _REASON_MAP:
        return _REASON_MAP[reason]

    action = kv.get("action")
    if action:
        act_res = _ACTION_MAP.get(action)
        if act_res and act_res != "check_status":
            return act_res

    logid = kv.get("logid")
    if logid and logid in _LOGID_MAP:
        return _LOGID_MAP[logid]

    return action or "unknown"


def parse_kv(line: str) -> dict[str, str]:
    """Single-pass tokenizer for FortiGate key=value pairs."""
    i = 0
    n = len(line)
    kv: dict[str, str] = {}
    has_tab = "\t" in line

    while i < n:
        while i < n and line[i] in " \t\r\n":
            i += 1
        if i >= n:
            break

        eq_pos = line.find("=", i)
        if eq_pos == -1:
            break

        key = line[i:eq_pos].strip()
        val_start = eq_pos + 1

        if val_start >= n:
            kv[key] = ""
            break

        if line[val_start] == '"':
            val_start += 1
            val_end = line.find('"', val_start)
            while val_end != -1 and line[val_end - 1] == "\\":
                val_end = line.find('"', val_end + 1)

            if val_end == -1:
                val = line[val_start:]
                i = n
            else:
                val = line[val_start:val_end]
                i = val_end + 1
            if "\\" in val:
                val = val.replace('\\"', '"').replace("\\\\", "\\")
        else:
            space_pos = line.find(" ", val_start)
            if has_tab:
                tab_pos = line.find("\t", val_start)
                if space_pos != -1 and tab_pos != -1:
                    delim = min(space_pos, tab_pos)
                elif space_pos != -1:
                    delim = space_pos
                elif tab_pos != -1:
                    delim = tab_pos
                else:
                    delim = -1
            else:
                delim = space_pos

            if delim == -1:
                val = line[val_start:].rstrip("\r\n")
                i = n
            else:
                val = line[val_start:delim]
                i = delim + 1

        kv[key] = val
    return kv


def parse_line(
    line: str,
    source_file: str,
    source_offset: int,
    stream: int = 0,
) -> dict[str, Any] | None:
    """Parse one FortiGate log line into a normalized dictionary.
    
    Returns None if line lacks 'date=' or 'logid=', marking it malformed.
    """
    if "date=" not in line or "logid=" not in line:
        return None

    kv = parse_kv(line)

    date_val = kv.get("date")
    time_val = kv.get("time")
    logid_val = kv.get("logid")

    if not date_val or not logid_val:
        return None

    tz_val = kv.get("tz", "+0000")
    timestamp_str = format_iso8601(date_val, time_val, tz_val)
    if timestamp_str is None:
        return None

    eventtime_ns: int | None = None
    if "eventtime" in kv:
        ev_str = kv["eventtime"]
        if ev_str.isdigit():
            eventtime_ns = int(ev_str)

    srcip = kv.get("srcip")
    dstip = kv.get("dstip")

    if is_rfc1918(srcip):
        host = srcip
    elif is_rfc1918(dstip):
        host = dstip
    else:
        host = None

    user_raw = kv.get("user")
    user: str | None = None
    if user_raw:
        u_clean = user_raw
        if "\\" in u_clean:
            u_clean = u_clean.split("\\", 1)[1]
        user = u_clean.lower() if u_clean else None

    srcport_val = kv.get("srcport")
    dstport_val = kv.get("dstport")
    src_port = int(srcport_val) if srcport_val and srcport_val.isdigit() else None
    dst_port = int(dstport_val) if dstport_val and dstport_val.isdigit() else None

    sentbyte_val = kv.get("sentbyte")
    rcvdbyte_val = kv.get("rcvdbyte")
    bytes_out = int(sentbyte_val) if sentbyte_val and sentbyte_val.isdigit() else None
    bytes_in = int(rcvdbyte_val) if rcvdbyte_val and rcvdbyte_val.isdigit() else None

    duration_val = kv.get("duration")
    duration = int(duration_val) if duration_val and duration_val.isdigit() else None

    proto_val = kv.get("proto")
    proto = int(proto_val) if proto_val and proto_val.isdigit() else None

    rcvdpkt_val = kv.get("rcvdpkt")
    rcvdpkt = int(rcvdpkt_val) if rcvdpkt_val and rcvdpkt_val.isdigit() else None

    sentpkt_val = kv.get("sentpkt")
    sentpkt = int(sentpkt_val) if sentpkt_val and sentpkt_val.isdigit() else None

    sessionid_val = kv.get("sessionid")
    sessionid = int(sessionid_val) if sessionid_val and sessionid_val.isdigit() else None

    typ = kv.get("type", "")
    subtyp = kv.get("subtype", "")
    if typ and subtyp:
        event_type = f"{typ}/{subtyp}"
    else:
        event_type = typ or subtyp or "traffic"

    action = kv.get("action")
    outcome = determine_outcome(kv)

    record: dict[str, Any] = {
        "event_id": f"ev_{stream}_{source_offset}",
        "timestamp": timestamp_str,
        "eventtime_ns": eventtime_ns,
        "host": host,
        "sensor": kv.get("devname"),
        "user": user,
        "user_raw": user_raw,
        "src_ip": srcip,
        "dst_ip": dstip,
        "src_port": src_port,
        "dst_port": dst_port,
        "event_type": event_type,
        "action": action,
        "outcome": outcome,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "url": kv.get("url"),
        "hostname": kv.get("hostname"),
        "attack": kv.get("attack"),
        "attackid": kv.get("attackid"),
        "severity": kv.get("severity") or kv.get("level"),
        "log_format": "fortigate_kv",
        "stream": stream,
        "source_file": source_file,
        "source_offset": source_offset,
        # typed known fields
        "app": kv.get("app"),
        "appcat": kv.get("appcat"),
        "apprisk": kv.get("apprisk"),
        "catdesc": kv.get("catdesc"),
        "devid": kv.get("devid"),
        "devname": kv.get("devname"),
        "dstcountry": kv.get("dstcountry"),
        "dstintf": kv.get("dstintf"),
        "dstintfrole": kv.get("dstintfrole"),
        "dstip": dstip,
        "dstport": dst_port,
        "duration": duration,
        "level": kv.get("level"),
        "logdesc": kv.get("logdesc"),
        "logid": logid_val,
        "method": kv.get("method"),
        "msg": kv.get("msg"),
        "policyid": kv.get("policyid"),
        "proto": proto,
        "rcvdbyte": bytes_in,
        "rcvdpkt": rcvdpkt,
        "reason": kv.get("reason"),
        "sentbyte": bytes_out,
        "sentpkt": sentpkt,
        "service": kv.get("service"),
        "sessionid": sessionid,
        "srccountry": kv.get("srccountry"),
        "srcintf": kv.get("srcintf"),
        "srcintfrole": kv.get("srcintfrole"),
        "srcip": srcip,
        "srcport": src_port,
        "status": kv.get("status"),
        "subtype": subtyp or None,
        "type": typ or None,
        "ui": kv.get("ui"),
        "vd": kv.get("vd"),
        "virus": kv.get("virus"),
    }

    extra_dict: dict[str, str] = {}
    for k, v in kv.items():
        if k not in KNOWN_FIELDS and k not in METADATA_FIELDS and k not in record:
            extra_dict[k] = v

    record["extra"] = json.dumps(extra_dict) if extra_dict else None
    return record
