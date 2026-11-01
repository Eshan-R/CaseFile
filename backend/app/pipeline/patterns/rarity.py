"""Rarity & Entropy Miner: identifies rare dimensions co-occurring with suspicious indicators and high-entropy domains."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.pipeline.patterns.base import (
    PatternCandidate,
    generate_pattern_id,
    shannon_entropy,
)
from app.pipeline.patterns.population_guard import (
    apply_population_guard_to_candidates,
    get_global_burst_seconds,
)

if TYPE_CHECKING:
    import duckdb

logger = logging.getLogger(__name__)

SUSPICIOUS_PREDICATE = """
(
    action IN ('deny', 'block', 'drop', 'blocked', 'dropped', 'reset', 'client-rst', 'server-rst')
    OR (
        src_ip IS NOT NULL AND NOT (
            src_ip LIKE '10.%'
            OR src_ip LIKE '192.168.%'
            OR src_ip LIKE '127.%'
            OR (src_ip LIKE '172.%' AND TRY_CAST(split_part(src_ip, '.', 2) AS INTEGER) BETWEEN 16 AND 31)
        )
    )
    OR severity IN ('high', 'critical', 'alert')
    OR TRY_CAST(severity AS INTEGER) >= 4
)
"""


def mine_rarity(
    con: duckdb.DuckDBPyConnection,
    max_frequency: int = 10,
    top_k_per_dim: int = 15,
    burst_seconds: set[str] | None = None,
    exclude_artifacts: bool = True,
) -> list[PatternCandidate]:
    """Mine rare values across attack, virus, hostname, user, and service co-occurring with suspicious events.
    
    Applies population guard to suppress/exclude global 1-second bursts and 15-minute mass artifacts.
    """
    dimensions = [
        ("attack", "Rare Attack Signature", "T1190", "Initial Access"),
        ("virus", "Rare Malware / Virus Identifier", "T1204", "Execution"),
        ("user", "Rare Suspicious Account", "T1078", "Initial Access"),
        ("service", "Rare Unconventional Service", "T1071", "Command and Control"),
        ("hostname", "Suspicious / Anomalous Hostname", "T1568", "Command and Control"),
    ]

    if burst_seconds is None:
        burst_seconds = get_global_burst_seconds(con)

    results: list[PatternCandidate] = []

    for dim_col, title_prefix, default_tech, default_tactic in dimensions:
        query = f"""
        SELECT
            {dim_col} AS dim_value,
            COUNT(*) AS total_count,
            MIN(ts) AS first_ts,
            MAX(ts) AS last_ts,
            LIST(DISTINCT src_ip)[1:5] AS sample_src_ips,
            LIST(DISTINCT dst_ip)[1:5] AS sample_dst_ips,
            LIST(event_id ORDER BY ts, source_offset)[1:8] AS sample_events,
            SUM(CASE WHEN {SUSPICIOUS_PREDICATE} THEN 1 ELSE 0 END) AS suspicious_count
        FROM events
        WHERE {dim_col} IS NOT NULL
          AND length(trim({dim_col})) > 0
        GROUP BY {dim_col}
        HAVING COUNT(*) <= {max_frequency}
           AND SUM(CASE WHEN {SUSPICIOUS_PREDICATE} THEN 1 ELSE 0 END) >= 1
        ORDER BY total_count ASC, suspicious_count DESC
        LIMIT {top_k_per_dim};
        """
        try:
            rows = con.execute(query).fetchall()
        except Exception as exc:
            logger.debug("Rarity query for %s failed: %s", dim_col, exc)
            continue

        for row in rows:
            (
                dim_val,
                total_count,
                first_ts,
                last_ts,
                sample_srcs,
                sample_dsts,
                sample_events,
                suspicious_count,
            ) = row

            entropy = 0.0
            tech = default_tech
            tactic = default_tactic
            title = f"{title_prefix}: '{dim_val}' ({total_count} occurrences)"

            # Check for high-entropy domain if column is hostname
            if dim_col == "hostname":
                entropy = shannon_entropy(dim_val)
                if len(dim_val) >= 20 and entropy >= 3.8:
                    title = f"High-Entropy DGA/Tunneling Hostname: '{dim_val}' (Entropy: {entropy})"
                    tech = "T1568"
                    tactic = "Command and Control"

            # Compute score based on rarity and suspicious ratio
            susp_ratio = suspicious_count / max(total_count, 1)
            rarity_factor = max(1.0, 10.0 - float(total_count))
            score = round(min(10.0, 4.0 + rarity_factor * 0.4 + susp_ratio * 2.0 + (entropy if entropy >= 3.8 else 0.0) * 0.5), 2)

            entities = []
            if sample_srcs:
                entities.extend([f"src_ip:{s}" for s in sample_srcs if s])
            if sample_dsts:
                entities.extend([f"dst_ip:{d}" for d in sample_dsts if d])

            key = f"rarity:{dim_col}:{dim_val}"
            pid = generate_pattern_id("rarity", key)

            results.append(
                PatternCandidate(
                    pattern_id=pid,
                    kind="rarity",
                    title=title,
                    support=int(total_count),
                    score=score,
                    first_seen=first_ts,
                    last_seen=last_ts,
                    entities=entities[:6],
                    example_event_ids=list(sample_events) if sample_events else [],
                    suggested_technique=tech,
                    suggested_tactic=tactic,
                    details_json={
                        "dimension": dim_col,
                        "value": dim_val,
                        "total_count": int(total_count),
                        "suspicious_count": int(suspicious_count),
                        "entropy": entropy if entropy > 0.0 else None,
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
