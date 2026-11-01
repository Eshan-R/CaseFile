"""Novel Edges Miner: detects rare lateral movement and unconventional inbound communication edges."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.pipeline.patterns.base import (
    PUBLIC_WEB_PORTS,
    SENSITIVE_PORTS,
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

RFC1918_PREDICATE = """
(
    {col} LIKE '10.%'
    OR {col} LIKE '192.168.%'
    OR {col} LIKE '127.%'
    OR ({col} LIKE '172.%' AND TRY_CAST(split_part({col}, '.', 2) AS INTEGER) BETWEEN 16 AND 31)
)
"""


def mine_novel_edges(
    con: duckdb.DuckDBPyConnection,
    max_seen: int = 10,
    limit: int = 100,
    burst_seconds: set[str] | None = None,
    exclude_artifacts: bool = True,
) -> list[PatternCandidate]:
    """Mine rare network communication edges on high-value lateral or non-public ingress ports.
    
    Applies population guard to suppress/exclude global 1-second bursts and 15-minute mass artifacts.
    """
    sensitive_ports_str = ", ".join(str(p) for p in SENSITIVE_PORTS.keys())
    public_ports_str = ", ".join(str(p) for p in PUBLIC_WEB_PORTS)

    is_src_rfc1918 = RFC1918_PREDICATE.format(col="src_ip")
    is_dst_rfc1918 = RFC1918_PREDICATE.format(col="dst_ip")

    query = f"""
    WITH edge_counts AS (
        SELECT
            src_ip,
            dst_ip,
            dst_port,
            COUNT(*) AS edge_count,
            MIN(ts) AS first_ts,
            MAX(ts) AS last_ts,
            LIST(DISTINCT action)[1:3] AS actions,
            LIST(event_id ORDER BY ts, source_offset)[1:8] AS sample_events,
            FIRST({is_src_rfc1918}) AS is_internal_src,
            FIRST({is_dst_rfc1918}) AS is_internal_dst
        FROM events
        WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL AND dst_port IS NOT NULL
          AND (
              dst_port IN ({sensitive_ports_str})
              OR (dst_port NOT IN ({public_ports_str}) AND ({is_dst_rfc1918}))
          )
        GROUP BY src_ip, dst_ip, dst_port
        HAVING COUNT(*) <= {max_seen}
    ),
    filtered_edges AS (
        SELECT *
        FROM edge_counts
        WHERE (
            -- Case 1: Internal-to-Internal Lateral Movement on Sensitive Ports
            (is_internal_src AND is_internal_dst AND dst_port IN ({sensitive_ports_str}))
            -- Case 2: External-to-Internal Ingress on Non-Public Ports
            OR ((NOT is_internal_src) AND is_internal_dst AND dst_port NOT IN ({public_ports_str}))
        )
    )
    SELECT
        src_ip,
        dst_ip,
        dst_port,
        edge_count,
        first_ts,
        last_ts,
        actions,
        sample_events,
        is_internal_src,
        is_internal_dst
    FROM filtered_edges
    ORDER BY edge_count ASC, dst_port ASC
    LIMIT {limit};
    """

    try:
        rows = con.execute(query).fetchall()
    except Exception as exc:
        logger.warning("Novel edges mining failed: %s", exc)
        return []

    if burst_seconds is None:
        burst_seconds = get_global_burst_seconds(con)

    results: list[PatternCandidate] = []
    for row in rows:
        (
            src_ip,
            dst_ip,
            dst_port,
            edge_count,
            first_ts,
            last_ts,
            actions,
            sample_events,
            is_internal_src,
            is_internal_dst,
        ) = row

        port_desc = SENSITIVE_PORTS.get(dst_port, f"Port {dst_port}")

        if is_internal_src and is_internal_dst:
            tech = "T1021"
            tactic = "Lateral Movement"
            title = f"Rare Internal Lateral Connection: {src_ip} -> {dst_ip}:{dst_port} ({port_desc})"
            base_score = 5.5
            weight_boost = 2.0 if dst_port in SENSITIVE_PORTS else 0.0
        else:
            tech = "T1190"
            tactic = "Initial Access"
            title = f"Unconventional Inbound Ingress: {src_ip} -> {dst_ip}:{dst_port} ({port_desc})"
            base_score = 5.0
            weight_boost = 1.5

        # Score formula incorporates low count and weight boosts
        rarity_bonus = max(0.5, (max_seen - edge_count + 1) * 0.3)
        score = round(min(10.0, base_score + rarity_bonus + weight_boost), 2)

        key = f"edge:{src_ip}:{dst_ip}:{dst_port}"
        pid = generate_pattern_id("novel_edges", key)

        results.append(
            PatternCandidate(
                pattern_id=pid,
                kind="novel_edges",
                title=title,
                support=int(edge_count),
                score=score,
                first_seen=first_ts,
                last_seen=last_ts,
                entities=[f"src_ip:{src_ip}", f"dst_ip:{dst_ip}"],
                example_event_ids=list(sample_events) if sample_events else [],
                suggested_technique=tech,
                suggested_tactic=tactic,
                details_json={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": int(dst_port),
                    "port_description": port_desc,
                    "edge_count": int(edge_count),
                    "actions": list(actions) if actions else [],
                    "is_lateral": bool(is_internal_src and is_internal_dst),
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

