"""Burst Miner: detects anomalous spikes in event rates per source entity."""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING

from app.pipeline.patterns.base import PatternCandidate, generate_pattern_id
from app.pipeline.patterns.population_guard import (
    apply_population_guard_to_candidates,
    get_global_burst_seconds,
)

if TYPE_CHECKING:
    import duckdb

logger = logging.getLogger(__name__)


def mine_bursts(
    con: duckdb.DuckDBPyConnection,
    min_count: int = 20,
    min_z: float = 3.5,
    burst_seconds: set[str] | None = None,
    exclude_artifacts: bool = True,
) -> list[PatternCandidate]:
    """Mine anomalous rate bursts per (src_ip, event_class) using modified Z-score with floored MAD.
    
    Applies population guard to suppress/exclude global 1-second bursts and 15-minute windows
    with >= 10 distinct sources tripping the same burst.
    """
    query = f"""
    WITH raw_buckets AS (
        SELECT
            src_ip,
            CASE
                WHEN attack IS NOT NULL AND length(trim(attack)) > 0 THEN attack
                WHEN logid IN ('0100032002', 'auth_failure') THEN 'auth_failed'
                WHEN logid IS NOT NULL AND length(trim(logid)) > 0 THEN 'logid_' || logid
                WHEN action IN ('deny', 'block', 'drop') THEN 'blocked_traffic'
                ELSE 'traffic'
            END AS event_class,
            to_timestamp(floor(epoch(ts) / 300) * 300) AS bucket_ts,
            COUNT(*) AS bucket_count,
            MIN(ts) AS first_ts,
            MAX(ts) AS last_ts,
            COUNT(DISTINCT dst_ip) AS distinct_dst_ips,
            COUNT(DISTINCT dst_port) AS distinct_dst_ports,
            LIST(event_id ORDER BY ts, source_offset)[1:8] AS sample_events
        FROM events
        WHERE src_ip IS NOT NULL AND length(trim(src_ip)) > 0
          AND (
              attack IS NOT NULL
              OR logid IN ('0100032002', 'auth_failure')
              OR action IN ('deny', 'block', 'drop')
              OR dst_port IN (22, 88, 389, 445, 1433, 3306, 3389, 5432, 5985, 5986)
          )
        GROUP BY src_ip, event_class, bucket_ts
    ),
    class_medians AS (
        SELECT
            event_class,
            COUNT(*) AS class_bucket_count,
            median(bucket_count) AS raw_med_count
        FROM raw_buckets
        GROUP BY event_class
    ),
    class_mads AS (
        SELECT
            b.event_class,
            GREATEST(median(abs(b.bucket_count - m.raw_med_count)), 1.0) AS raw_mad_count
        FROM raw_buckets b
        JOIN class_medians m ON b.event_class = m.event_class
        GROUP BY b.event_class
    ),
    candidates AS (
        SELECT
            b.src_ip,
            b.event_class,
            b.bucket_ts,
            b.bucket_count,
            b.first_ts,
            b.last_ts,
            b.distinct_dst_ips,
            b.distinct_dst_ports,
            b.sample_events,
            CASE
                WHEN m.class_bucket_count <= 1 THEN (0.6745 * (b.bucket_count - 1.0) / 1.0)
                ELSE (0.6745 * (b.bucket_count - m.raw_med_count) / mad.raw_mad_count)
            END AS mod_z
        FROM raw_buckets b
        JOIN class_medians m ON b.event_class = m.event_class
        JOIN class_mads mad ON b.event_class = mad.event_class
        WHERE b.bucket_count >= {min_count}
          AND (
            CASE
                WHEN m.class_bucket_count <= 1 THEN (0.6745 * (b.bucket_count - 1.0) / 1.0)
                ELSE (0.6745 * (b.bucket_count - m.raw_med_count) / mad.raw_mad_count)
            END
          ) >= {min_z}
    )
    SELECT
        src_ip,
        event_class,
        bucket_ts,
        bucket_count,
        first_ts,
        last_ts,
        distinct_dst_ips,
        distinct_dst_ports,
        sample_events,
        mod_z
    FROM candidates
    ORDER BY mod_z DESC, bucket_count DESC
    LIMIT 100;
    """
    try:
        rows = con.execute(query).fetchall()
    except Exception as exc:
        logger.warning("Burst mining query failed: %s", exc)
        return []

    if burst_seconds is None:
        burst_seconds = get_global_burst_seconds(con)

    results: list[PatternCandidate] = []
    for row in rows:
        (
            src_ip,
            event_class,
            bucket_ts,
            bucket_count,
            first_ts,
            last_ts,
            distinct_dst_ips,
            distinct_dst_ports,
            sample_events,
            mod_z,
        ) = row

        duration = max((last_ts - first_ts).total_seconds() if first_ts and last_ts else 1.0, 1.0)
        rate = round(bucket_count / duration, 2)

        # ATT&CK Mapping
        if "auth" in event_class.lower() or "login" in event_class.lower():
            tech = "T1110"
            tactic = "Credential Access"
            title = f"High-Rate Authentication Burst from {src_ip}"
        elif distinct_dst_ports >= 5 or distinct_dst_ips >= 5:
            tech = "T1046"
            tactic = "Discovery"
            title = f"Port / Host Scanning Burst from {src_ip}"
        elif bucket_count >= 100:
            tech = "T1498"
            tactic = "Impact"
            title = f"Volumetric Traffic Burst from {src_ip}"
        else:
            tech = "T1190"
            tactic = "Initial Access"
            title = f"Anomalous Event Spike ({event_class}) from {src_ip}"

        score = round(min(10.0, 3.5 + float(mod_z) * 0.35 + math.log(max(bucket_count, 1)) * 0.3), 2)
        key = f"burst:{src_ip}:{event_class}:{bucket_ts}"
        pid = generate_pattern_id("burst", key)

        results.append(
            PatternCandidate(
                pattern_id=pid,
                kind="burst",
                title=title,
                support=int(bucket_count),
                score=score,
                first_seen=first_ts,
                last_seen=last_ts,
                entities=[f"src_ip:{src_ip}"],
                example_event_ids=list(sample_events) if sample_events else [],
                suggested_technique=tech,
                suggested_tactic=tactic,
                details_json={
                    "event_class": event_class,
                    "modified_z_score": round(float(mod_z), 2),
                    "duration_sec": round(duration, 1),
                    "peak_rate_eps": rate,
                    "distinct_dst_ips": int(distinct_dst_ips),
                    "distinct_dst_ports": int(distinct_dst_ports),
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
