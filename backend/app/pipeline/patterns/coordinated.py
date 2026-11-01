"""Coordinated Multi-Source Burst Miner: detects distributed attacks and coordinated campaigns."""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING

from app.pipeline.patterns.base import (
    PatternCandidate,
    generate_pattern_id,
)
from app.pipeline.patterns.population_guard import (
    apply_population_guard_to_candidates,
    get_global_burst_seconds,
)

if TYPE_CHECKING:
    import duckdb

logger = logging.getLogger(__name__)


def mine_coordinated(
    con: duckdb.DuckDBPyConnection,
    min_sources: int = 2,
    limit: int = 50,
    burst_seconds: set[str] | None = None,
    exclude_artifacts: bool = True,
) -> list[PatternCandidate]:
    """Mine coordinated activity where >= 2 distinct sources target the same asset within a 10-minute window.
    
    Applies population guard to suppress/exclude windows with >= 10 distinct sources (mass-population artifacts)
    and global 1-second volumetric bursts.
    """
    query = f"""
    WITH windowed_events AS (
        SELECT
            to_timestamp(floor(epoch(ts) / 600) * 600) AS time_window,
            dst_ip,
            dst_port,
            COALESCE(
                NULLIF(trim(attack), ''),
                NULLIF(trim(url), ''),
                'port_' || CAST(dst_port AS TEXT) || '_' || COALESCE(action, 'unknown')
            ) AS signature,
            src_ip,
            event_id,
            ts,
            source_offset
        FROM events
        WHERE dst_ip IS NOT NULL
          AND src_ip IS NOT NULL
          AND length(trim(src_ip)) > 0
          AND (
              (attack IS NOT NULL AND length(trim(attack)) > 0)
              OR (url IS NOT NULL AND length(trim(url)) > 0)
              OR action IN ('deny', 'block', 'drop')
              OR dst_port IN (22, 88, 389, 445, 1433, 3306, 3389, 5432, 5985, 5986, 8080)
          )
    ),
    signature_groups AS (
        SELECT
            time_window,
            dst_ip,
            signature,
            COUNT(DISTINCT src_ip) AS distinct_sources,
            COUNT(*) AS total_events,
            MIN(ts) AS first_ts,
            MAX(ts) AS last_ts,
            LIST(DISTINCT src_ip)[1:6] AS sample_srcs,
            LIST(event_id ORDER BY ts, source_offset)[1:8] AS sample_events
        FROM windowed_events
        GROUP BY time_window, dst_ip, signature
        HAVING COUNT(DISTINCT src_ip) >= {min_sources}
           AND COUNT(*) >= 4
    )
    SELECT
        time_window,
        dst_ip,
        signature,
        distinct_sources,
        total_events,
        first_ts,
        last_ts,
        sample_srcs,
        sample_events
    FROM signature_groups
    ORDER BY distinct_sources DESC, total_events DESC
    LIMIT {limit};
    """

    try:
        rows = con.execute(query).fetchall()
    except Exception as exc:
        logger.warning("Coordinated mining query failed: %s", exc)
        return []

    if burst_seconds is None:
        burst_seconds = get_global_burst_seconds(con)

    results: list[PatternCandidate] = []
    for row in rows:
        (
            time_window,
            dst_ip,
            signature,
            distinct_sources,
            total_events,
            first_ts,
            last_ts,
            sample_srcs,
            sample_events,
        ) = row

        # ATT&CK Mapping
        sig_lower = signature.lower()
        if "login" in sig_lower or "auth" in sig_lower or "22" in sig_lower or "3389" in sig_lower:
            tech = "T1110.003"
            tactic = "Credential Access"
            title = f"Distributed Password Spraying ({distinct_sources} sources -> {dst_ip})"
        elif total_events >= 100:
            tech = "T1498"
            tactic = "Impact"
            title = f"Distributed Traffic Surge / DoS ({distinct_sources} sources -> {dst_ip})"
        else:
            tech = "T1190"
            tactic = "Initial Access"
            title = f"Coordinated Attack Campaign: '{signature}' ({distinct_sources} sources -> {dst_ip})"

        # S = distinct_sources * ln(total_events)
        s_metric = distinct_sources * math.log(max(total_events, 2))
        score = round(min(10.0, 3.5 + s_metric * 0.35), 2)

        key = f"coord:{time_window}:{dst_ip}:{signature}"
        pid = generate_pattern_id("coordinated", key)

        entities = [f"dst_ip:{dst_ip}"]
        if sample_srcs:
            entities.extend([f"src_ip:{s}" for s in sample_srcs if s])

        results.append(
            PatternCandidate(
                pattern_id=pid,
                kind="coordinated",
                title=title,
                support=int(total_events),
                score=score,
                first_seen=first_ts,
                last_seen=last_ts,
                entities=entities,
                example_event_ids=list(sample_events) if sample_events else [],
                suggested_technique=tech,
                suggested_tactic=tactic,
                details_json={
                    "signature": signature,
                    "target_ip": dst_ip,
                    "distinct_sources": int(distinct_sources),
                    "total_events": int(total_events),
                    "window": str(time_window),
                },
            )
        )

    return apply_population_guard_to_candidates(
        results,
        burst_seconds=burst_seconds,
        window_seconds=900.0,
        max_distinct_sources=10,
        exclude=exclude_artifacts,
    )

