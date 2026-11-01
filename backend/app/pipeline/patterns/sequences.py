"""Multi-Tactic Ordered Sequences Miner: mines multi-stage event-class attack progression chains."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.pipeline.patterns.base import (
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

# Sensitive ports SQL string
SENSITIVE_PORTS_STR = ", ".join(str(p) for p in SENSITIVE_PORTS.keys())

# Tactic classification SQL expression
TACTIC_CLASSIFIER_SQL = f"""
CASE
    WHEN attack IS NOT NULL AND length(trim(attack)) > 0 THEN 'Initial Access'
    WHEN logid IN ('0100032002', 'auth_failure') OR reason IN ('password_invalid', 'auth_failure', 'name_invalid') THEN 'Credential Access'
    WHEN virus IS NOT NULL AND length(trim(virus)) > 0 THEN 'Execution'
    WHEN dst_port IN ({SENSITIVE_PORTS_STR}) AND action IN ('accept', 'allow', 'pass', 'ip-conn') THEN 'Lateral Movement'
    WHEN dst_port IN ({SENSITIVE_PORTS_STR}) AND action IN ('deny', 'block', 'drop') THEN 'Discovery'
    WHEN (sentbyte > 5000000 OR bytes_out > 5000000) THEN 'Exfiltration'
    WHEN action IN ('deny', 'block', 'drop') AND (dst_port NOT IN (80, 443, 8080, 8443) OR dst_port IS NULL) THEN 'Discovery'
    ELSE NULL
END
"""

EVENT_CLASS_SQL = """
CASE
    WHEN attack IS NOT NULL AND length(trim(attack)) > 0 THEN 'exploit_attempt'
    WHEN logid IN ('0100032002', 'auth_failure') OR reason IN ('password_invalid', 'auth_failure', 'name_invalid') THEN 'auth_failed'
    WHEN virus IS NOT NULL AND length(trim(virus)) > 0 THEN 'malware_signature'
    WHEN action IN ('accept', 'allow', 'pass') THEN 'accepted_conn'
    WHEN action IN ('deny', 'block', 'drop') THEN 'blocked_conn'
    ELSE 'other'
END
"""


def mine_sequences(
    con: duckdb.DuckDBPyConnection,
    min_support: int = 1,
    limit: int = 50,
    burst_seconds: set[str] | None = None,
    exclude_artifacts: bool = True,
) -> list[PatternCandidate]:
    """Mine multi-stage attack sequence patterns across 2-4 distinct tactics within 30-min windows.
    
    Applies population guard to suppress/exclude global 1-second bursts and 15-minute mass artifacts.
    """
    query = f"""
    WITH classified_events AS (
        SELECT
            event_id,
            ts,
            source_offset,
            COALESCE(NULLIF(src_ip, ''), NULLIF(host, 'unknown')) AS entity,
            ({TACTIC_CLASSIFIER_SQL}) AS stage_tactic,
            ({EVENT_CLASS_SQL}) AS event_class
        FROM events
        WHERE ((src_ip IS NOT NULL AND length(trim(src_ip)) > 0) OR (host IS NOT NULL AND length(trim(host)) > 0))
          AND (
              (attack IS NOT NULL AND length(trim(attack)) > 0)
              OR logid IN ('0100032002', 'auth_failure')
              OR reason IN ('password_invalid', 'auth_failure', 'name_invalid')
              OR (virus IS NOT NULL AND length(trim(virus)) > 0)
              OR (dst_port IN ({SENSITIVE_PORTS_STR}))
              OR (sentbyte > 5000000 OR bytes_out > 5000000)
              OR (action IN ('deny', 'block', 'drop') AND (dst_port NOT IN (80, 443, 8080, 8443) OR dst_port IS NULL))
          )
    ),
    valid_tactics AS (
        SELECT *
        FROM classified_events
        WHERE stage_tactic IS NOT NULL
    ),
    deduped_stages AS (
        -- Collapse immediate sequential duplicates of the same tactic for the same entity
        SELECT
            *,
            LAG(stage_tactic) OVER (PARTITION BY entity ORDER BY ts, source_offset) AS prev_tactic,
            LAG(ts) OVER (PARTITION BY entity ORDER BY ts, source_offset) AS prev_ts
        FROM valid_tactics
    ),
    clean_transitions AS (
        SELECT
            event_id,
            ts,
            source_offset,
            entity,
            stage_tactic,
            event_class
        FROM deduped_stages
        WHERE prev_tactic IS NULL OR prev_tactic != stage_tactic
    ),
    chains_2_stage AS (
        SELECT
            entity,
            stage_tactic AS t1,
            LEAD(stage_tactic, 1) OVER (PARTITION BY entity ORDER BY ts, source_offset) AS t2,
            LEAD(stage_tactic, 2) OVER (PARTITION BY entity ORDER BY ts, source_offset) AS t3,
            ts AS start_ts,
            LEAD(ts, 1) OVER (PARTITION BY entity ORDER BY ts, source_offset) AS t2_ts,
            LEAD(ts, 2) OVER (PARTITION BY entity ORDER BY ts, source_offset) AS t3_ts,
            event_id AS e1,
            LEAD(event_id, 1) OVER (PARTITION BY entity ORDER BY ts, source_offset) AS e2,
            LEAD(event_id, 2) OVER (PARTITION BY entity ORDER BY ts, source_offset) AS e3
        FROM clean_transitions
    ),
    filtered_chains AS (
        SELECT
            entity,
            CASE
                WHEN t3 IS NOT NULL AND (epoch(t3_ts) - epoch(start_ts)) <= 1800 AND t1 != t2 AND t2 != t3 AND t1 != t3 THEN
                    t1 || ' -> ' || t2 || ' -> ' || t3
                WHEN t2 IS NOT NULL AND (epoch(t2_ts) - epoch(start_ts)) <= 1800 AND t1 != t2 THEN
                    t1 || ' -> ' || t2
                ELSE NULL
            END AS chain_str,
            start_ts,
            COALESCE(t3_ts, t2_ts) AS end_ts,
            CASE
                WHEN t3 IS NOT NULL AND (epoch(t3_ts) - epoch(start_ts)) <= 1800 AND t1 != t2 AND t2 != t3 AND t1 != t3 THEN 3
                WHEN t2 IS NOT NULL AND (epoch(t2_ts) - epoch(start_ts)) <= 1800 AND t1 != t2 THEN 2
                ELSE 0
            END AS stage_count,
            [e1, e2, e3] AS event_ids
        FROM chains_2_stage
        WHERE t2 IS NOT NULL AND (epoch(t2_ts) - epoch(start_ts)) <= 1800 AND t1 != t2
    ),
    aggregated_chains AS (
        SELECT
            chain_str,
            stage_count,
            COUNT(*) AS chain_count,
            MIN(start_ts) AS first_seen,
            MAX(end_ts) AS last_seen,
            LIST(DISTINCT entity)[1:6] AS entities,
            FLATTEN(LIST(event_ids))[1:8] AS sample_events
        FROM filtered_chains
        WHERE chain_str IS NOT NULL
        GROUP BY chain_str, stage_count
        HAVING COUNT(*) >= {min_support}
    )
    SELECT
        chain_str,
        stage_count,
        chain_count,
        first_seen,
        last_seen,
        entities,
        sample_events
    FROM aggregated_chains
    ORDER BY stage_count DESC, chain_count ASC
    LIMIT {limit};
    """

    try:
        rows = con.execute(query).fetchall()
    except Exception as exc:
        logger.warning("Sequences mining query failed: %s", exc)
        return []

    if burst_seconds is None:
        burst_seconds = get_global_burst_seconds(con)

    results: list[PatternCandidate] = []
    for row in rows:
        (
            chain_str,
            stage_count,
            chain_count,
            first_seen,
            last_seen,
            entities,
            sample_events,
        ) = row

        stages = [s.strip() for s in chain_str.split("->")]
        title = f"Multi-Stage Attack Sequence ({stage_count} Stages): {chain_str}"

        # Assign suggested technique based on terminal stage
        terminal_tactic = stages[-1] if stages else "Initial Access"
        technique_map = {
            "Credential Access": "T1110",
            "Initial Access": "T1190",
            "Lateral Movement": "T1021",
            "Execution": "T1204",
            "Discovery": "T1046",
            "Exfiltration": "T1041",
        }
        suggested_tech = technique_map.get(terminal_tactic, "T1078")

        # Chain rarity scoring: rarer sequences of more stages score higher
        rarity_score = 4.0 + (stage_count * 1.5) + max(0.5, 3.0 / max(chain_count, 1))
        score = round(min(10.0, rarity_score), 2)

        key = f"seq:{chain_str}"
        pid = generate_pattern_id("sequence", key)

        clean_sample_events = [e for e in sample_events if e] if sample_events else []

        results.append(
            PatternCandidate(
                pattern_id=pid,
                kind="sequence",
                title=title,
                support=int(chain_count),
                score=score,
                first_seen=first_seen,
                last_seen=last_seen,
                entities=[f"entity:{e}" for e in entities if e],
                example_event_ids=clean_sample_events[:8],
                suggested_technique=suggested_tech,
                suggested_tactic=terminal_tactic,
                details_json={
                    "chain": chain_str,
                    "stages": stages,
                    "stage_count": int(stage_count),
                    "chain_count": int(chain_count),
                    "is_rare_transition": bool(chain_count <= 5),
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

