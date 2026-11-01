"""Export utilities for discovered threat patterns and extracted IOCs."""

from __future__ import annotations

import csv
import json
import logging
import os
from dataclasses import asdict, is_dataclass
from typing import Any

import yaml

from app.store import duck

logger = logging.getLogger(__name__)


def _datetime_handler(obj: Any) -> Any:
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if is_dataclass(obj):
        return asdict(obj)
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def _normalize_patterns(patterns: list[Any] | None) -> list[dict]:
    if patterns is None:
        _, raw = duck.list_patterns(limit=None)
        return raw
    res = []
    for p in patterns:
        if is_dataclass(p):
            res.append(asdict(p))
        elif isinstance(p, dict):
            res.append(p)
        elif hasattr(p, "__dict__"):
            res.append(p.__dict__)
        else:
            res.append(dict(p))
    return res


def export_patterns_json(patterns: list[Any] | None = None, output_path: str = "data/patterns.json") -> str:
    """Export patterns list to formatted JSON."""
    normalized = _normalize_patterns(patterns)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, default=_datetime_handler)
    return output_path


def export_patterns_yaml(patterns: list[Any] | None = None, output_path: str = "data/patterns.yaml") -> str:
    """Export patterns list to YAML."""
    normalized = _normalize_patterns(patterns)
    # Convert datetimes to isoformat strings for safe YAML dumping
    clean_patterns = json.loads(json.dumps(normalized, default=_datetime_handler))
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(clean_patterns, f, sort_keys=False)
    return output_path


def extract_iocs_from_patterns(patterns: list[Any] | None = None) -> list[dict]:
    """Extract distinct indicators of compromise (IOCs) from patterns."""
    normalized = _normalize_patterns(patterns)
    iocs_map: dict[tuple[str, str], dict] = {}

    for p in normalized:
        pid = p.get("pattern_id", "")
        tech = p.get("suggested_technique", "")
        support = int(p.get("support", 1))
        f_seen = p.get("first_seen")
        l_seen = p.get("last_seen")
        details = p.get("details_json", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}

        # 1. Entities (src_ip, dst_ip)
        entities = p.get("entities", [])
        if isinstance(entities, str):
            try:
                entities = json.loads(entities)
            except Exception:
                entities = []

        for ent in entities:
            if ":" in ent:
                etype, evalue = ent.split(":", 1)
                etype_clean = "ip" if "ip" in etype else etype
                key = (etype_clean, evalue)
                if key not in iocs_map:
                    iocs_map[key] = {
                        "ioc_type": etype_clean,
                        "ioc_value": evalue,
                        "count": support,
                        "first_seen": f_seen,
                        "last_seen": l_seen,
                        "source_patterns": [pid],
                        "suggested_technique": tech,
                    }
                else:
                    existing = iocs_map[key]
                    existing["count"] = max(existing["count"], support)
                    if pid not in existing["source_patterns"]:
                        existing["source_patterns"].append(pid)

        # 2. Dimension specific values (hostname, virus, attack)
        dim = details.get("dimension")
        val = details.get("value")
        if dim and val:
            itype = "domain" if dim == "hostname" else dim
            key = (itype, val)
            if key not in iocs_map:
                iocs_map[key] = {
                    "ioc_type": itype,
                    "ioc_value": val,
                    "count": support,
                    "first_seen": f_seen,
                    "last_seen": l_seen,
                    "source_patterns": [pid],
                    "suggested_technique": tech,
                }
            else:
                existing = iocs_map[key]
                existing["count"] = max(existing["count"], support)
                if pid not in existing["source_patterns"]:
                    existing["source_patterns"].append(pid)

    return sorted(iocs_map.values(), key=lambda x: (-x["count"], x["ioc_type"], x["ioc_value"]))


def export_iocs_csv(patterns: list[dict] | None = None, output_path: str = "data/iocs.csv") -> str:
    """Export extracted IOCs to CSV format."""
    iocs = extract_iocs_from_patterns(patterns)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    fieldnames = ["ioc_type", "ioc_value", "count", "first_seen", "last_seen", "source_patterns", "suggested_technique"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ioc in iocs:
            row = dict(ioc)
            row["source_patterns"] = ";".join(ioc.get("source_patterns", []))
            row["first_seen"] = str(ioc.get("first_seen") or "")
            row["last_seen"] = str(ioc.get("last_seen") or "")
            writer.writerow(row)
    return output_path
