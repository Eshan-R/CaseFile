"""Population Guard for Automated Pattern Miners.

Protects top-ranked mined patterns from mass-firing artifacts,
specifically global 1-second volumetric bursts (> 200 events/sec) and
15-minute population-wide windows where >= 10 distinct sources trip simultaneously
(such as the known end-of-file artifact at 2026-10-30 03:18 UTC where 231 sources trip).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

from app.pipeline.patterns.base import PatternCandidate

if TYPE_CHECKING:
    import duckdb

logger = logging.getLogger(__name__)

KNOWN_POPULATION_ARTIFACT_WINDOW = "2026-10-30 03:18"


def _to_epoch(val: Any) -> float:
    """Safely convert a timestamp object or string to epoch seconds."""
    if val is None:
        return 0.0
    if isinstance(val, int | float):
        return float(val)
    if isinstance(val, datetime):
        return val.timestamp()
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00")).timestamp()
        except Exception:
            pass
    return 0.0


def get_global_burst_seconds(con: duckdb.DuckDBPyConnection) -> set[str]:
    """Pre-query 1-second buckets holding > 200 events from the events table/view."""
    burst_seconds: set[str] = set()
    try:
        rows = con.execute("""
            SELECT strftime(ts, '%Y-%m-%d %H:%M:%S') AS sec, COUNT(*)
            FROM events
            WHERE ts IS NOT NULL
            GROUP BY 1
            HAVING COUNT(*) > 200
        """).fetchall()
        burst_seconds = {str(r[0])[:19] for r in rows}
    except Exception as exc:
        logger.debug("Could not query global 1-second burst buckets: %s", exc)
    return burst_seconds


def is_in_burst_second(ts_val: Any, burst_seconds: set[str] | None = None) -> bool:
    """Return True if ts falls into a global 1-second burst or known population artifact."""
    if ts_val is None:
        return False
    ts_str = str(ts_val).replace("T", " ")[:19]
    if KNOWN_POPULATION_ARTIFACT_WINDOW in ts_str:
        return True
    if burst_seconds:
        if ts_str in burst_seconds:
            return True
        for b in burst_seconds:
            if b in ts_str or ts_str in b:
                return True
    return False


def _extract_source_entities(cand: PatternCandidate) -> list[str]:
    """Extract source IP/host identifiers from pattern candidate."""
    sources: list[str] = []
    for ent in cand.entities:
        if ent.startswith("src_ip:"):
            sources.append(ent.split(":", 1)[1].strip())
        elif ent.startswith("entity:"):
            sources.append(ent.split(":", 1)[1].strip())
        elif not ent.startswith("dst_ip:"):
            sources.append(ent.strip())
    
    # Also check details_json
    src = cand.details_json.get("src_ip")
    if src and str(src).strip() not in sources:
        sources.append(str(src).strip())
    
    sample_srcs = cand.details_json.get("sample_srcs") or cand.details_json.get("sample_src_ips")
    if isinstance(sample_srcs, list):
        for s in sample_srcs:
            s_clean = str(s).strip()
            if s_clean and s_clean not in sources:
                sources.append(s_clean)

    return [s for s in sources if s]


def apply_population_guard_to_candidates(
    candidates: list[PatternCandidate],
    burst_seconds: set[str] | None = None,
    window_seconds: float = 900.0,
    max_distinct_sources: int = 10,
    exclude: bool = True,
) -> list[PatternCandidate]:
    """Apply population guard to candidate patterns:
    
    1. Flag 1-second global burst buckets (> 200 events/sec or known artifact).
    2. Flag 15-minute sliding windows where >= 10 distinct sources trip the same burst/signature.
    3. Flag coordinated patterns reporting >= 10 distinct sources in a single window.
    
    Flagged patterns are downweighted (score = 1.0) and marked with details_json['population_artifact']=True.
    If exclude=True, flagged patterns are excluded completely so they do not dominate top rankings.
    """
    if not candidates:
        return []

    # 1. Check 1-second burst & coordinated source threshold
    for cand in candidates:
        is_burst = (
            is_in_burst_second(cand.first_seen, burst_seconds)
            or is_in_burst_second(cand.last_seen, burst_seconds)
        )
        if is_burst and not cand.details_json.get("population_artifact"):
            cand.details_json["population_artifact"] = True
            cand.details_json["suppress_reason"] = "population-burst-1s (1sec_bucket)"
            cand.score = min(cand.score, 1.0)

        # Coordinated group with >= 10 distinct sources
        if cand.kind == "coordinated":
            distinct_cnt = int(cand.details_json.get("distinct_sources", 0))
            if distinct_cnt >= max_distinct_sources and not cand.details_json.get("population_artifact"):
                cand.details_json["population_artifact"] = True
                cand.details_json["suppress_reason"] = (
                    f"population-window-artifact (distinct_sources={distinct_cnt} >= {max_distinct_sources})"
                )
                cand.score = min(cand.score, 1.0)

    # 2. Check 15-minute sliding window with >= 10 distinct sources per group
    # Group by signature / event_class
    groups: dict[str, list[tuple[int, PatternCandidate]]] = {}
    for idx, cand in enumerate(candidates):
        if cand.kind == "burst":
            sig = str(cand.details_json.get("event_class", "burst"))
        elif cand.kind == "novel_edges":
            sig = f"port_{cand.details_json.get('dst_port', '')}"
        elif cand.kind == "rarity":
            sig = f"rarity_{cand.details_json.get('dimension', '')}"
        elif cand.kind == "sequence":
            sig = str(cand.details_json.get("chain", "sequence"))
        else:
            sig = cand.kind
        
        group_key = f"{cand.kind}:{sig}"
        groups.setdefault(group_key, []).append((idx, cand))

    for group_key, items in groups.items():
        if len(items) < max_distinct_sources:
            continue

        # Sort items by epoch
        indexed = sorted(items, key=lambda x: _to_epoch(x[1].first_seen or x[1].last_seen))
        n = len(indexed)
        left = 0
        current_sources: dict[str, int] = {}

        for right in range(n):
            _, cand_r = indexed[right]
            srcs_r = _extract_source_entities(cand_r)
            for s in srcs_r:
                current_sources[s] = current_sources.get(s, 0) + 1

            t_r = _to_epoch(cand_r.first_seen or cand_r.last_seen)
            while left < right:
                t_l = _to_epoch(indexed[left][1].first_seen or indexed[left][1].last_seen)
                if t_r - t_l > window_seconds:
                    _, cand_l = indexed[left]
                    for s in _extract_source_entities(cand_l):
                        if s in current_sources:
                            current_sources[s] -= 1
                            if current_sources[s] == 0:
                                del current_sources[s]
                    left += 1
                else:
                    break

            if len(current_sources) >= max_distinct_sources:
                for k in range(left, right + 1):
                    _, cand_k = indexed[k]
                    if not cand_k.details_json.get("population_artifact"):
                        cand_k.details_json["population_artifact"] = True
                        cand_k.details_json["suppress_reason"] = (
                            f"population-window-artifact (distinct_sources={len(current_sources)} >= {max_distinct_sources})"
                        )
                        cand_k.score = min(cand_k.score, 1.0)

    if exclude:
        return [c for c in candidates if not c.details_json.get("population_artifact")]
    return candidates

