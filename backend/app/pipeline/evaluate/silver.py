"""Silver-standard independent SQL evaluation over unlabelled log events.

Builds an answer key using independent SQL oracles over DuckDB log events without
using detection rules, incidents, or ground-truth manifests.
Scores detections and incidents against this silver standard to report agreement.

BANNER:
SILVER STANDARD: agreement with independent SQL oracles on firex-10G.log.
No organizer ground truth exists for this file. Not a measure of true accuracy.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

import duckdb
import yaml

from app.store import duck

logger = logging.getLogger(__name__)

BANNER = (
    "SILVER STANDARD: agreement with independent SQL oracles on firex-10G.log. "
    "No organizer ground truth exists for this file. Not a measure of true accuracy."
)

TACTIC_ORDER = {
    "Reconnaissance": 0,
    "Resource Development": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 4,
    "Privilege Escalation": 5,
    "Defense Evasion": 6,
    "Credential Access": 7,
    "Discovery": 8,
    "Lateral Movement": 9,
    "Collection": 10,
    "Command and Control": 11,
    "Exfiltration": 12,
    "Impact": 13,
}

CLEAN_REGION_MAX_OFFSET = 4815675419


@dataclass
class OracleRow:
    oracle_id: str
    expected_technique: str
    expected_tactic: str
    src_ip: str | None
    dst_ip: str | None
    user: str | None
    t_start: str
    t_end: str
    n_events: int
    evidence_event_ids: list[str]
    metric: float
    sub_flags: dict[str, Any] | None = None


@dataclass
class MergedBehavior:
    behavior_id: str
    oracle_id: str
    expected_technique: str
    expected_tactic: str
    src_ip: str | None
    dst_ip: str | None
    user: str | None
    t_start: str
    t_end: str
    n_events: int
    evidence_event_ids: list[str]
    metric: float
    window_count: int
    sub_flags: dict[str, Any] | None = None


def merge_oracle_rows_to_behaviors(oracle_rows: list[OracleRow], max_gap_seconds: int = 3600) -> list[MergedBehavior]:
    """Merge consecutive/overlapping oracle rows for the same entity and oracle class into sustained behaviors."""
    if not oracle_rows:
        return []

    groups: dict[tuple, list[OracleRow]] = {}
    for r in oracle_rows:
        key = (r.oracle_id, r.expected_technique, r.src_ip, r.dst_ip, r.user)
        groups.setdefault(key, []).append(r)

    behaviors: list[MergedBehavior] = []

    for key, rows in groups.items():
        sorted_rows = sorted(rows, key=lambda x: _parse_dt(x.t_start) or datetime.min.replace(tzinfo=UTC))
        cur_b: list[OracleRow] = []

        for r in sorted_rows:
            if not cur_b:
                cur_b.append(r)
                continue

            last_r = cur_b[-1]
            last_end = _parse_dt(last_r.t_end)
            this_start = _parse_dt(r.t_start)

            gap_sec = (this_start - last_end).total_seconds() if (last_end and this_start) else 999999
            if gap_sec <= max_gap_seconds:
                cur_b.append(r)
            else:
                b_start = cur_b[0].t_start
                b_end = max((x.t_end for x in cur_b), key=lambda x: _parse_dt(x) or datetime.min.replace(tzinfo=UTC))
                tot_events = sum(x.n_events for x in cur_b)
                eids = list(dict.fromkeys([eid for x in cur_b for eid in x.evidence_event_ids]))[:20]
                max_metric = max(x.metric for x in cur_b)
                first_r = cur_b[0]
                behaviors.append(MergedBehavior(
                    behavior_id=f"{first_r.oracle_id}:{first_r.src_ip or first_r.dst_ip or first_r.user}:{b_start}",
                    oracle_id=first_r.oracle_id,
                    expected_technique=first_r.expected_technique,
                    expected_tactic=first_r.expected_tactic,
                    src_ip=first_r.src_ip,
                    dst_ip=first_r.dst_ip,
                    user=first_r.user,
                    t_start=b_start,
                    t_end=b_end,
                    n_events=tot_events,
                    evidence_event_ids=eids,
                    metric=max_metric,
                    window_count=len(cur_b),
                    sub_flags=first_r.sub_flags,
                ))
                cur_b = [r]

        if cur_b:
            b_start = cur_b[0].t_start
            b_end = max((x.t_end for x in cur_b), key=lambda x: _parse_dt(x) or datetime.min.replace(tzinfo=UTC))
            tot_events = sum(x.n_events for x in cur_b)
            eids = list(dict.fromkeys([eid for x in cur_b for eid in x.evidence_event_ids]))[:20]
            max_metric = max(x.metric for x in cur_b)
            first_r = cur_b[0]
            behaviors.append(MergedBehavior(
                behavior_id=f"{first_r.oracle_id}:{first_r.src_ip or first_r.dst_ip or first_r.user}:{b_start}",
                oracle_id=first_r.oracle_id,
                expected_technique=first_r.expected_technique,
                expected_tactic=first_r.expected_tactic,
                src_ip=first_r.src_ip,
                dst_ip=first_r.dst_ip,
                user=first_r.user,
                t_start=b_start,
                t_end=b_end,
                n_events=tot_events,
                evidence_event_ids=eids,
                metric=max_metric,
                window_count=len(cur_b),
                sub_flags=first_r.sub_flags,
            ))

    return behaviors


def load_silver_oracle_config(config_path: str = "rules/silver_oracles.yaml") -> dict[str, Any]:
    """Load oracle parameter thresholds from YAML."""
    if not os.path.exists(config_path):
        alt = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", config_path)
        if os.path.exists(alt):
            config_path = alt
    if os.path.exists(config_path):
        with open(config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def _parse_dt(val: Any) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.astimezone(UTC) if val.tzinfo else val.replace(tzinfo=UTC)
    try:
        s = str(val).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    except Exception:
        return None


def _to_epoch(val: Any) -> float:
    if isinstance(val, int | float):
        return float(val)
    dt = _parse_dt(val)
    return dt.timestamp() if dt else 0.0


def _format_dt(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.isoformat()


def _is_family_match(tech_a: str, tech_b: str) -> bool:
    if not tech_a or not tech_b:
        return False
    if tech_a == tech_b:
        return True
    return tech_a.split(".")[0] == tech_b.split(".")[0]


def _compute_distribution(con: duckdb.DuckDBPyConnection, table_or_query: str, metric_col: str) -> dict[str, float | None]:
    """Compute distribution quantiles (p50, p99, p99.9, max) for a metric."""
    try:
        q = f"""
        SELECT
            quantile_cont({metric_col}, 0.50),
            quantile_cont({metric_col}, 0.99),
            quantile_cont({metric_col}, 0.999),
            max({metric_col})
        FROM ({table_or_query})
        WHERE {metric_col} IS NOT NULL
        """
        row = con.execute(q).fetchone()
        if row and row[0] is not None:
            return {
                "p50": round(float(row[0]), 2),
                "p99": round(float(row[1]), 2),
                "p99_9": round(float(row[2]), 2),
                "max": round(float(row[3]), 2),
            }
    except Exception as exc:
        logger.debug("Distribution calculation failed for %s: %s", metric_col, exc)
    return {"p50": None, "p99": None, "p99_9": None, "max": None}


# ============================================================================
# INDEPENDENT SQL ORACLES
# ============================================================================


def _mine_failed_admin_burst(
    con: duckdb.DuckDBPyConnection,
    min_count: int = 500,
    max_distinct_sources: int = 10,
) -> tuple[list[OracleRow], dict, list[dict]]:
    """Oracle 1: failed_admin_burst (T1110.001, Credential Access)."""
    base_query = f"""
    SELECT
        time_bucket(INTERVAL '10 MINUTE', ts) as w_start,
        src_ip,
        arg_max(dst_ip, ts) as dst_ip,
        arg_max(user, ts) as user,
        min(ts) as t_start,
        max(ts) as t_end,
        count(*) as n_events,
        count(*) as metric_val,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM events
    WHERE logid = '0100032002'
      AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    GROUP BY 1, 2
    """
    dist = _compute_distribution(con, base_query, "metric_val")
    query = f"""
    SELECT * FROM ({base_query})
    WHERE metric_val >= {min_count}
    ORDER BY w_start, src_ip
    """
    rows = con.execute(query).fetchall()

    suppressed_windows: list[dict] = []
    clean_results: list[OracleRow] = []

    # Map windows to candidate rows
    window_cands: dict[datetime, list] = {}
    for r in rows:
        w_dt = _parse_dt(r[0])
        if w_dt:
            window_cands.setdefault(w_dt, []).append(r)

    for w_dt, w_rows in window_cands.items():
        distinct_sources = len({r[1] for r in w_rows if r[1]})
        if distinct_sources >= max_distinct_sources:
            suppressed_windows.append({
                "oracle_id": "failed_admin_burst",
                "window": _format_dt(w_dt),
                "duration_seconds": 600,
                "tripping_internal_sources": distinct_sources,
                "reason": f"Population artifact: {distinct_sources} distinct sources in window >= {max_distinct_sources}",
            })
        else:
            for r in w_rows:
                clean_results.append(
                    OracleRow(
                        oracle_id="failed_admin_burst",
                        expected_technique="T1110.001",
                        expected_tactic="Credential Access",
                        src_ip=r[1],
                        dst_ip=r[2],
                        user=r[3],
                        t_start=_format_dt(_parse_dt(r[4])),
                        t_end=_format_dt(_parse_dt(r[5])),
                        n_events=r[6],
                        evidence_event_ids=r[8] if r[8] else [],
                        metric=float(r[7]),
                    )
                )

    return clean_results, dist, suppressed_windows


def _mine_slow_stuffing_24(
    con: duckdb.DuckDBPyConnection,
    min_ips: int = 10,
    max_events: int = 200,
    min_delta_seconds: int = 120,
    max_delta_seconds: int = 480,
) -> tuple[list[OracleRow], dict]:
    """Oracle 2: slow_stuffing_24 (T1110.004, Credential Access)."""
    base_query = f"""
    WITH deltas AS (
        SELECT
            time_bucket(INTERVAL '6 HOUR', ts) as w_start,
            regexp_extract(src_ip, '^([0-9]+\\.[0-9]+\\.[0-9]+)') as subnet_24,
            src_ip,
            user,
            event_id,
            ts,
            epoch(ts) - epoch(lag(ts) OVER (PARTITION BY time_bucket(INTERVAL '6 HOUR', ts), regexp_extract(src_ip, '^([0-9]+\\.[0-9]+\\.[0-9]+)') ORDER BY ts)) as delta
        FROM events
        WHERE logid = '0100032002'
          AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
          AND src_ip IS NOT NULL
    )
    SELECT
        w_start,
        subnet_24,
        count(DISTINCT src_ip) as distinct_ips,
        count(DISTINCT user) as distinct_users,
        count(*) as n_events,
        median(delta) as med_delta,
        min(ts) as t_start,
        max(ts) as t_end,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM deltas
    GROUP BY 1, 2
    """
    dist = _compute_distribution(con, base_query, "distinct_users")
    query = f"""
    SELECT * FROM ({base_query})
    WHERE distinct_ips >= {min_ips}
      AND n_events <= {max_events}
      AND med_delta BETWEEN {min_delta_seconds} AND {max_delta_seconds}
    ORDER BY w_start, subnet_24
    """
    rows = con.execute(query).fetchall()
    results = [
        OracleRow(
            oracle_id="slow_stuffing_24",
            expected_technique="T1110.004",
            expected_tactic="Credential Access",
            src_ip=f"{r[1]}.0/24",
            dst_ip=None,
            user=None,
            t_start=_format_dt(_parse_dt(r[6])),
            t_end=_format_dt(_parse_dt(r[7])),
            n_events=r[4],
            evidence_event_ids=r[8] if r[8] else [],
            metric=float(r[3]),  # distinct users
            sub_flags={"distinct_ips": r[2], "med_delta_sec": round(float(r[5] or 0), 1)},
        )
        for r in rows
    ]
    return results, dist


def _mine_admin_success(con: duckdb.DuckDBPyConnection) -> tuple[list[OracleRow], dict]:
    """Oracle 3: admin_success (T1078.001, Initial Access)."""
    query = f"""
    WITH succ AS (
        SELECT
            event_id,
            ts,
            src_ip,
            dst_ip,
            user,
            regexp_extract(src_ip, '^([0-9]+\\.[0-9]+\\.[0-9]+)') as subnet_24,
            extract(hour from (ts at time zone 'UTC' + INTERVAL 5 HOUR + INTERVAL 30 MINUTE)) as local_hour,
            NOT (
                src_ip LIKE '10.%'
                OR src_ip LIKE '192.168.%'
                OR src_ip LIKE '127.%'
                OR regexp_matches(src_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.')
            ) as is_external
        FROM events
        WHERE logid = '0100032001'
          AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    )
    SELECT
        s.event_id,
        s.ts,
        s.src_ip,
        s.dst_ip,
        s.user,
        s.local_hour,
        s.is_external,
        (s.is_external AND s.local_hour < 6) as odd_hour,
        (
            SELECT count(*)
            FROM events f
            WHERE f.logid = '0100032002'
              AND (f.src_ip = s.src_ip OR regexp_extract(f.src_ip, '^([0-9]+\\.[0-9]+\\.[0-9]+)') = s.subnet_24)
              AND f.ts >= s.ts - INTERVAL 30 MINUTE
              AND f.ts < s.ts
        ) as prior_failures
    FROM succ s
    ORDER BY s.ts
    """
    rows = con.execute(query).fetchall()
    results = []
    prior_fails_list = []
    for r in rows:
        prior_fails = int(r[8] or 0)
        prior_fails_list.append(prior_fails)
        after_fails = prior_fails >= 5
        odd_hr = bool(r[7])
        exp_tech = "T1110.001+T1078.001" if after_fails else "T1078.001"
        results.append(
            OracleRow(
                oracle_id="admin_success",
                expected_technique=exp_tech,
                expected_tactic="Initial Access",
                src_ip=r[2],
                dst_ip=r[3],
                user=r[4],
                t_start=_format_dt(_parse_dt(r[1])),
                t_end=_format_dt(_parse_dt(r[1])),
                n_events=1,
                evidence_event_ids=[r[0]],
                metric=float(prior_fails),
                sub_flags={"after_failures": after_fails, "odd_hour": odd_hr, "local_hour": r[5]},
            )
        )
    dist = {
        "p50": float(sorted(prior_fails_list)[len(prior_fails_list) // 2]) if prior_fails_list else None,
        "p99": float(max(prior_fails_list)) if prior_fails_list else None,
        "p99_9": float(max(prior_fails_list)) if prior_fails_list else None,
        "max": float(max(prior_fails_list)) if prior_fails_list else None,
    }
    return results, dist


def _mine_vpn_impossible_travel(con: duckdb.DuckDBPyConnection, window_minutes: int = 60) -> tuple[list[OracleRow], dict]:
    """Oracle 4: vpn_impossible_travel (T1078.004, Initial Access)."""
    base_query = f"""
    WITH vpn_logins AS (
        SELECT
            event_id,
            ts,
            user,
            src_ip,
            dst_ip,
            srccountry,
            COALESCE(NULLIF(srccountry, ''), regexp_extract(src_ip, '^([0-9]+\\.[0-9]+)')) as country_proxy
        FROM events
        WHERE (action IN ('tunnel-up', 'ssl-login') OR subtype = 'vpn')
          AND user IS NOT NULL
          AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    )
    SELECT
        a.user,
        a.src_ip as src_ip_a,
        b.src_ip as src_ip_b,
        a.country_proxy as country_a,
        b.country_proxy as country_b,
        a.ts as t_start,
        b.ts as t_end,
        (epoch(b.ts) - epoch(a.ts)) / 60.0 as diff_minutes,
        [a.event_id, b.event_id] as sample_eids
    FROM vpn_logins a
    JOIN vpn_logins b ON a.user = b.user AND a.ts < b.ts AND b.ts <= a.ts + INTERVAL {window_minutes} MINUTE
    WHERE a.country_proxy != b.country_proxy
    """
    dist = _compute_distribution(con, base_query, "diff_minutes")
    rows = con.execute(f"{base_query} ORDER BY t_start, a.user").fetchall()
    results = [
        OracleRow(
            oracle_id="vpn_impossible_travel",
            expected_technique="T1078.004",
            expected_tactic="Initial Access",
            src_ip=r[1],
            dst_ip=None,
            user=r[0],
            t_start=_format_dt(_parse_dt(r[5])),
            t_end=_format_dt(_parse_dt(r[6])),
            n_events=2,
            evidence_event_ids=r[8],
            metric=round(float(r[7]), 2),  # diff minutes
            sub_flags={"country_a": r[3], "country_b": r[4], "src_b": r[2]},
        )
        for r in rows
    ]
    return results, dist


def _mine_config_change(con: duckdb.DuckDBPyConnection) -> tuple[list[OracleRow], dict]:
    """Oracle 5: config_change (T1562.002, T1136.001, T1098, Defense Evasion / Persistence)."""
    query = f"""
    SELECT
        event_id,
        ts,
        logid,
        action,
        user,
        src_ip,
        dst_ip,
        msg
    FROM events
    WHERE (logid LIKE '010004%' OR msg ILIKE '%config%' OR msg ILIKE '%log disk%')
      AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    ORDER BY ts
    """
    rows = con.execute(query).fetchall()
    results = []
    # Check for rogue admin: Add followed by Delete within 60 minutes
    add_events: dict[str, tuple[datetime, str]] = {}  # admin_name -> (ts, event_id)

    for r in rows:
        eid, ts_raw, logid, action, user, src_ip, dst_ip, msg = r
        dt = _parse_dt(ts_raw)
        msg_str = str(msg or "")
        action_str = str(action or "")

        tech = "T1562.002"
        tactic = "Defense Evasion"
        sub_flags: dict[str, Any] = {"msg": msg_str, "logid": logid, "action": action_str}

        if "disable" in msg_str.lower() and "log" in msg_str.lower():
            tech = "T1562.002"
            tactic = "Defense Evasion"
        elif logid == "0100044547" and action_str.lower() == "add":
            tech = "T1136.001"
            tactic = "Persistence"
            admin_target = msg_str.split()[-1] if msg_str else "admin"
            if dt:
                add_events[admin_target] = (dt, eid)
        elif logid == "0100044547" and action_str.lower() == "delete":
            admin_target = msg_str.split()[-1] if msg_str else "admin"
            if admin_target in add_events and dt:
                add_dt, add_eid = add_events[admin_target]
                mins = (dt - add_dt).total_seconds() / 60.0
                if mins <= 60.0:
                    tech = "T1098"
                    tactic = "Persistence"
                    sub_flags["rogue_admin"] = True
                    sub_flags["minutes_since_add"] = round(mins, 1)
        elif action_str.lower() == "edit":
            tech = "T1098"
            tactic = "Persistence"

        results.append(
            OracleRow(
                oracle_id="config_change",
                expected_technique=tech,
                expected_tactic=tactic,
                src_ip=src_ip,
                dst_ip=dst_ip,
                user=user,
                t_start=_format_dt(dt),
                t_end=_format_dt(dt),
                n_events=1,
                evidence_event_ids=[eid],
                metric=1.0,
                sub_flags=sub_flags,
            )
        )
    return results, {"p50": 1.0, "p99": 1.0, "p99_9": 1.0, "max": 1.0}


def _mine_virus_detected_not_blocked(con: duckdb.DuckDBPyConnection) -> tuple[list[OracleRow], dict]:
    """Oracle 6: virus_detected_not_blocked (T1105, Command and Control)."""
    query = f"""
    SELECT
        event_id,
        ts,
        src_ip,
        dst_ip,
        user,
        virus,
        action
    FROM events
    WHERE (virus IS NOT NULL OR subtype = 'virus')
      AND lower(coalesce(action, '')) != 'blocked'
      AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    ORDER BY ts
    """
    rows = con.execute(query).fetchall()
    results = [
        OracleRow(
            oracle_id="virus_detected_not_blocked",
            expected_technique="T1105",
            expected_tactic="Command and Control",
            src_ip=r[2],
            dst_ip=r[3],
            user=r[4],
            t_start=_format_dt(_parse_dt(r[1])),
            t_end=_format_dt(_parse_dt(r[1])),
            n_events=1,
            evidence_event_ids=[r[0]],
            metric=1.0,
            sub_flags={"virus": r[5], "action": r[6]},
        )
        for r in rows
    ]
    return results, {"p50": 1.0, "p99": 1.0, "p99_9": 1.0, "max": 1.0}


def _mine_port_scan(con: duckdb.DuckDBPyConnection, min_distinct_ports: int = 200, guard_ratio: float = 0.30) -> tuple[list[OracleRow], dict, list[dict]]:
    """Oracle 7: port_scan (T1046, Discovery) with population guard."""
    base_query = f"""
    SELECT
        time_bucket(INTERVAL '5 MINUTE', ts) as w_start,
        src_ip,
        dst_ip,
        min(ts) as t_start,
        max(ts) as t_end,
        count(*) as n_events,
        count(DISTINCT dst_port) as distinct_ports,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM events
    WHERE dst_port IS NOT NULL
      AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    GROUP BY 1, 2, 3
    """
    dist = _compute_distribution(con, base_query, "distinct_ports")
    query = f"""
    SELECT * FROM ({base_query})
    WHERE distinct_ports >= {min_distinct_ports}
    ORDER BY w_start, src_ip
    """
    rows = con.execute(query).fetchall()

    # Population guard check
    suppressed_windows: list[dict] = []
    clean_results: list[OracleRow] = []

    # Map windows to candidate count
    window_cands: dict[datetime, list] = {}
    for r in rows:
        w_dt = _parse_dt(r[0])
        if w_dt:
            window_cands.setdefault(w_dt, []).append(r)

    for w_dt, w_rows in window_cands.items():
        w_str = w_dt.strftime("%Y-%m-%d %H:%M:%S")
        # Total active internal sources in this 5m window
        tot_row = con.execute(
            f"""
            SELECT count(DISTINCT src_ip)
            FROM events
            WHERE ts >= '{w_str}'::TIMESTAMP AND ts < '{w_str}'::TIMESTAMP + INTERVAL 5 MINUTE
              AND (src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' OR regexp_matches(src_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'))
              AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
            """
        ).fetchone()
        tot_active = tot_row[0] if tot_row and tot_row[0] else 1
        tripping_cnt = len({r[1] for r in w_rows if r[1] and (r[1].startswith("10.") or r[1].startswith("192.168."))})
        ratio = tripping_cnt / tot_active if tot_active > 0 else 0.0

        if tripping_cnt >= 5 and ratio >= guard_ratio:
            suppressed_windows.append({
                "oracle_id": "port_scan",
                "window": _format_dt(w_dt),
                "duration_seconds": 300,
                "tripping_internal_sources": tripping_cnt,
                "total_active_internal": tot_active,
                "ratio": round(ratio, 4),
            })
        else:
            for r in w_rows:
                clean_results.append(
                    OracleRow(
                        oracle_id="port_scan",
                        expected_technique="T1046",
                        expected_tactic="Discovery",
                        src_ip=r[1],
                        dst_ip=r[2],
                        user=None,
                        t_start=_format_dt(_parse_dt(r[3])),
                        t_end=_format_dt(_parse_dt(r[4])),
                        n_events=r[5],
                        evidence_event_ids=r[7] if r[7] else [],
                        metric=float(r[6]),
                    )
                )

    return clean_results, dist, suppressed_windows


def _mine_lateral_fanout(con: duckdb.DuckDBPyConnection, min_distinct_targets: int = 10) -> tuple[list[OracleRow], dict]:
    """Oracle 8: lateral_fanout (T1021.002 SMB / T1021.001 RDP, Lateral Movement)."""
    base_query = f"""
    SELECT
        time_bucket(INTERVAL '1 HOUR', ts) as w_start,
        src_ip,
        dst_port,
        min(ts) as t_start,
        max(ts) as t_end,
        count(*) as n_events,
        count(DISTINCT dst_ip) as distinct_dsts,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM events
    WHERE dst_port IN (445, 3389)
      AND (src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' OR regexp_matches(src_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'))
      AND (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' OR regexp_matches(dst_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'))
      AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    GROUP BY 1, 2, 3
    """
    dist = _compute_distribution(con, base_query, "distinct_dsts")
    query = f"""
    SELECT * FROM ({base_query})
    WHERE distinct_dsts >= {min_distinct_targets}
    ORDER BY w_start, src_ip, dst_port
    """
    rows = con.execute(query).fetchall()
    results = [
        OracleRow(
            oracle_id="lateral_fanout",
            expected_technique="T1021.002" if r[2] == 445 else "T1021.001",
            expected_tactic="Lateral Movement",
            src_ip=r[1],
            dst_ip=None,
            user=None,
            t_start=_format_dt(_parse_dt(r[3])),
            t_end=_format_dt(_parse_dt(r[4])),
            n_events=r[5],
            evidence_event_ids=r[7] if r[7] else [],
            metric=float(r[6]),
            sub_flags={"dst_port": r[2]},
        )
        for r in rows
    ]
    return results, dist


def _mine_dns_tunnel(con: duckdb.DuckDBPyConnection, min_distinct_names: int = 50, min_label_len: int = 32) -> tuple[list[OracleRow], dict]:
    """Oracle 9: dns_tunnel (T1071.004, Command and Control / Exfiltration)."""
    base_query = f"""
    WITH dns_queries AS (
        SELECT
            src_ip,
            hostname,
            length(regexp_extract(hostname, '^([^.]+)\\.')) as first_label_len,
            regexp_extract(hostname, '([^.]+\\.[^.]+)$') as reg_domain,
            ts,
            event_id
        FROM events
        WHERE hostname IS NOT NULL
          AND length(regexp_extract(hostname, '^([^.]+)\\.')) >= {min_label_len}
          AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    )
    SELECT
        src_ip,
        reg_domain,
        count(DISTINCT hostname) as distinct_hostnames,
        count(*) as n_events,
        min(ts) as t_start,
        max(ts) as t_end,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM dns_queries
    GROUP BY 1, 2
    """
    dist = _compute_distribution(con, base_query, "distinct_hostnames")
    query = f"""
    SELECT * FROM ({base_query})
    WHERE distinct_hostnames >= {min_distinct_names}
    ORDER BY distinct_hostnames DESC
    """
    rows = con.execute(query).fetchall()
    results = [
        OracleRow(
            oracle_id="dns_tunnel",
            expected_technique="T1071.004",
            expected_tactic="Command and Control",
            src_ip=r[0],
            dst_ip=None,
            user=None,
            t_start=_format_dt(_parse_dt(r[4])),
            t_end=_format_dt(_parse_dt(r[5])),
            n_events=r[3],
            evidence_event_ids=r[6] if r[6] else [],
            metric=float(r[2]),
            sub_flags={"registered_domain": r[1]},
        )
        for r in rows
    ]
    return results, dist


def _mine_beacon(con: duckdb.DuckDBPyConnection, min_count: int = 100, min_duration_sec: int = 21600, max_cv: float = 0.15) -> tuple[list[OracleRow], dict]:
    """Oracle 10: beacon (T1071.001, Command and Control)."""
    base_query = f"""
    WITH deltas AS (
        SELECT
            src_ip,
            dst_ip,
            dst_port,
            ts,
            sentbyte,
            event_id,
            epoch(ts) - epoch(lag(ts) OVER (PARTITION BY src_ip, dst_ip, dst_port ORDER BY ts)) as delta
        FROM events
        WHERE (src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' OR regexp_matches(src_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'))
          AND NOT (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' OR regexp_matches(dst_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'))
          AND dst_port IS NOT NULL
          AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    ),
    stats AS (
        SELECT
            src_ip,
            dst_ip,
            dst_port,
            count(*) as cnt,
            min(ts) as t_start,
            max(ts) as t_end,
            epoch(max(ts)) - epoch(min(ts)) as timespan,
            stddev_samp(delta) / NULLIF(avg(delta), 0) as cv_interval,
            stddev_samp(sentbyte) / NULLIF(avg(sentbyte), 0) as cv_bytes,
            median(delta) as median_interval,
            list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
        FROM deltas
        WHERE delta IS NOT NULL
        GROUP BY 1, 2, 3
        HAVING count(*) >= {min_count}
           AND (epoch(max(ts)) - epoch(min(ts))) >= {min_duration_sec}
    )
    SELECT
        src_ip, dst_ip, dst_port, cnt, timespan,
        cv_interval, cv_bytes, median_interval, t_start, t_end, sample_eids
    FROM stats
    """
    dist = _compute_distribution(con, base_query, "cv_interval")
    query = f"""
    SELECT * FROM ({base_query})
    WHERE cv_interval <= {max_cv} AND cv_bytes <= {max_cv}
    ORDER BY cv_interval ASC
    """
    rows = con.execute(query).fetchall()
    results = [
        OracleRow(
            oracle_id="beacon",
            expected_technique="T1071.001",
            expected_tactic="Command and Control",
            src_ip=r[0],
            dst_ip=r[1],
            user=None,
            t_start=_format_dt(_parse_dt(r[8])),
            t_end=_format_dt(_parse_dt(r[9])),
            n_events=r[3],
            evidence_event_ids=r[10] if r[10] else [],
            metric=round(float(r[5]), 4),  # cv_interval
            sub_flags={"dst_port": r[2], "cv_bytes": round(float(r[6]), 4), "median_interval_sec": round(float(r[7]), 1)},
        )
        for r in rows
    ]
    return results, dist


def _mine_staged_exfil(con: duckdb.DuckDBPyConnection, min_count: int = 500, min_duration_sec: int = 86400, min_ratio: float = 1.5) -> tuple[list[OracleRow], dict]:
    """Oracle 11: staged_exfil (T1048.002, Exfiltration)."""
    base_query = f"""
    SELECT
        src_ip,
        dst_ip,
        count(*) as cnt,
        min(ts) as t_start,
        max(ts) as t_end,
        (epoch(max(ts)) - epoch(min(ts))) as timespan_sec,
        sum(sentbyte) as total_sent,
        sum(rcvdbyte) as total_rcvd,
        sum(sentbyte) * 1.0 / NULLIF(sum(rcvdbyte), 0) as ratio,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM events
    WHERE (src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' OR regexp_matches(src_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'))
      AND NOT (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' OR regexp_matches(dst_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'))
      AND sentbyte IS NOT NULL
      AND rcvdbyte IS NOT NULL
      AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    GROUP BY 1, 2
    HAVING count(*) >= {min_count}
       AND (epoch(max(ts)) - epoch(min(ts))) >= {min_duration_sec}
    """
    dist = _compute_distribution(con, base_query, "ratio")
    query = f"""
    SELECT * FROM ({base_query})
    WHERE ratio >= {min_ratio}
    ORDER BY ratio DESC
    """
    rows = con.execute(query).fetchall()
    results = [
        OracleRow(
            oracle_id="staged_exfil",
            expected_technique="T1048.002",
            expected_tactic="Exfiltration",
            src_ip=r[0],
            dst_ip=r[1],
            user=None,
            t_start=_format_dt(_parse_dt(r[3])),
            t_end=_format_dt(_parse_dt(r[4])),
            n_events=r[2],
            evidence_event_ids=r[9] if r[9] else [],
            metric=round(float(r[8]), 2),  # ratio
            sub_flags={"total_sent_bytes": r[6], "total_rcvd_bytes": r[7], "duration_hours": round(float(r[5]) / 3600.0, 1)},
        )
        for r in rows
    ]
    return results, dist


def _mine_web_payload(con: duckdb.DuckDBPyConnection, min_count: int = 10) -> tuple[list[OracleRow], dict]:
    """Oracle 12: web_payload (T1190, T1059, T1083, Initial Access / Execution / Discovery)."""
    base_query = f"""
    WITH decoded AS (
        SELECT
            event_id,
            ts,
            src_ip,
            dst_ip,
            url_decode(url) as d_url
        FROM events
        WHERE url IS NOT NULL
          AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    ),
    categorized AS (
        SELECT
            event_id,
            ts,
            src_ip,
            dst_ip,
            CASE
                WHEN regexp_matches(d_url, '(?i)(union\\s+select|or\\s+1=1|\''--|select\\s.+\\sfrom|drop\\s+table)') THEN 'sqli'
                WHEN regexp_matches(d_url, '(?i)(<script|onerror=|javascript:)') THEN 'xss'
                WHEN regexp_matches(d_url, '(?i)(\\.\\./|php://)') THEN 'traversal'
                WHEN regexp_matches(d_url, '(?i)[;|&$]\\s*(cat|id|whoami|wget|curl|nc)\\b') THEN 'cmd_injection'
                ELSE NULL
            END as payload_class
        FROM decoded
    )
    SELECT
        time_bucket(INTERVAL '10 MINUTE', ts) as w_start,
        src_ip,
        dst_ip,
        payload_class,
        count(*) as cnt,
        min(ts) as t_start,
        max(ts) as t_end,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM categorized
    WHERE payload_class IS NOT NULL
    GROUP BY 1, 2, 3, 4
    """
    dist = _compute_distribution(con, base_query, "cnt")
    query = f"""
    SELECT * FROM ({base_query})
    WHERE cnt >= {min_count}
    ORDER BY w_start, src_ip
    """
    rows = con.execute(query).fetchall()
    class_tech_map = {
        "sqli": ("T1190", "Initial Access"),
        "xss": ("T1059.007", "Execution"),
        "traversal": ("T1083", "Discovery"),
        "cmd_injection": ("T1059.004", "Execution"),
    }
    results = []
    for r in rows:
        p_class = r[3]
        tech, tactic = class_tech_map.get(p_class, ("T1190", "Initial Access"))
        results.append(
            OracleRow(
                oracle_id="web_payload",
                expected_technique=tech,
                expected_tactic=tactic,
                src_ip=r[1],
                dst_ip=r[2],
                user=None,
                t_start=_format_dt(_parse_dt(r[5])),
                t_end=_format_dt(_parse_dt(r[6])),
                n_events=r[4],
                evidence_event_ids=r[7] if r[7] else [],
                metric=float(r[4]),
                sub_flags={"payload_class": p_class},
            )
        )
    return results, dist


def _mine_flood(con: duckdb.DuckDBPyConnection, guard_ratio: float = 0.30) -> tuple[list[OracleRow], dict, list[dict]]:
    """Oracle 13: flood (T1498.001 SYN, T1499.002 HTTP, T1498.002 DNS amp)."""
    # (a) SYN flood
    syn_query = f"""
    SELECT
        time_bucket(INTERVAL '1 MINUTE', ts) as w_start,
        dst_ip,
        dst_port,
        regexp_extract(src_ip, '^([0-9]+\\.[0-9]+)') as subnet_16,
        count(*) as cnt,
        min(ts) as t_start,
        max(ts) as t_end,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM events
    WHERE sentpkt <= 1 AND rcvdpkt = 0
      AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    GROUP BY 1, 2, 3, 4
    HAVING count(*) >= 2000
    """
    syn_rows = con.execute(syn_query).fetchall()

    # (b) HTTP flood
    http_query = f"""
    SELECT
        time_bucket(INTERVAL '1 MINUTE', ts) as w_start,
        dst_ip,
        dst_port,
        count(DISTINCT src_ip) as distinct_sources,
        count(*) as cnt,
        min(ts) as t_start,
        max(ts) as t_end,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM events
    WHERE dst_port = 443
      AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    GROUP BY 1, 2, 3
    HAVING count(*) >= 1000 AND count(DISTINCT src_ip) >= 100
    """
    http_rows = con.execute(http_query).fetchall()

    # (c) DNS amplification
    dns_query = f"""
    SELECT
        time_bucket(INTERVAL '1 MINUTE', ts) as w_start,
        dst_ip,
        dst_port,
        count(*) as cnt,
        avg(rcvdbyte) as avg_rcvd,
        min(ts) as t_start,
        max(ts) as t_end,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM events
    WHERE src_port = 53
      AND (proto = 17 OR service ILIKE '%udp%' OR service ILIKE '%dns%')
      AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
    GROUP BY 1, 2, 3
    HAVING count(*) >= 500 AND avg(rcvdbyte) >= 1000
    """
    dns_rows = con.execute(dns_query).fetchall()

    all_raw_cands = []
    for r in syn_rows:
        all_raw_cands.append(("syn", r[0], r[1], r[2], r[4], r[5], r[6], r[7], "T1498.001"))
    for r in http_rows:
        all_raw_cands.append(("http", r[0], r[1], r[2], r[4], r[5], r[6], r[7], "T1499.002"))
    for r in dns_rows:
        all_raw_cands.append(("dns_amp", r[0], r[1], r[2], r[3], r[5], r[6], r[7], "T1498.002"))

    suppressed_windows: list[dict] = []
    clean_results: list[OracleRow] = []

    # Population guard check per 1m bucket
    windows_map: dict[datetime, list] = {}
    for item in all_raw_cands:
        w_dt = _parse_dt(item[1])
        if w_dt:
            windows_map.setdefault(w_dt, []).append(item)

    for w_dt, w_items in windows_map.items():
        w_str = w_dt.strftime("%Y-%m-%d %H:%M:%S")
        tot_row = con.execute(
            f"""
            SELECT count(DISTINCT dst_ip)
            FROM events
            WHERE ts >= '{w_str}'::TIMESTAMP AND ts < '{w_str}'::TIMESTAMP + INTERVAL 1 MINUTE
              AND (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' OR regexp_matches(dst_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'))
              AND source_offset <= {CLEAN_REGION_MAX_OFFSET}
            """
        ).fetchone()
        tot_active = tot_row[0] if tot_row and tot_row[0] else 1
        tripping_cnt = len({it[2] for it in w_items})
        ratio = tripping_cnt / tot_active if tot_active > 0 else 0.0

        if tripping_cnt >= 5 and ratio >= guard_ratio:
            suppressed_windows.append({
                "oracle_id": "flood",
                "window": _format_dt(w_dt),
                "duration_seconds": 120,
                "tripping_internal_destinations": tripping_cnt,
                "total_active_internal": tot_active,
                "ratio": round(ratio, 4),
            })
        else:
            for it in w_items:
                clean_results.append(
                    OracleRow(
                        oracle_id="flood",
                        expected_technique=it[8],
                        expected_tactic="Impact",
                        src_ip=None,
                        dst_ip=it[2],
                        user=None,
                        t_start=_format_dt(_parse_dt(it[5])),
                        t_end=_format_dt(_parse_dt(it[6])),
                        n_events=it[4],
                        evidence_event_ids=it[7] if it[7] else [],
                        metric=float(it[4]),
                        sub_flags={"flood_type": it[0], "dst_port": it[3]},
                    )
                )

    dist = {
        "p50": float(sorted([it[4] for it in all_raw_cands])[len(all_raw_cands) // 2]) if all_raw_cands else None,
        "p99": float(max([it[4] for it in all_raw_cands])) if all_raw_cands else None,
        "p99_9": float(max([it[4] for it in all_raw_cands])) if all_raw_cands else None,
        "max": float(max([it[4] for it in all_raw_cands])) if all_raw_cands else None,
    }
    return clean_results, dist, suppressed_windows


# ============================================================================
# EVALUATION & MATCHING ENGINE
# ============================================================================


def run_silver_eval(
    db_path: str | None = None,
    config_path: str = "rules/silver_oracles.yaml",
    con: duckdb.DuckDBPyConnection | None = None,
) -> dict[str, Any]:
    """Execute all independent SQL oracles and score our detections/incidents against them."""
    cfg = load_silver_oracle_config(config_path)

    # 1. Connect to DuckDB
    close_con = False
    if con is not None:
        active_con = con
        close_con = False
    elif db_path is not None:
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"Database file not found: {db_path}")
        active_con = duckdb.connect(db_path, read_only=True)
        close_con = True
    else:
        active_con = duck._get_conn()
        close_con = False

    try:
        active_con.execute("SET preserve_insertion_order=false;")
    except Exception:
        pass

    try:
        # 2. Mine Oracle Rows
        logger.info("Executing silver-standard independent SQL oracles...")
        oracle_rows: list[OracleRow] = []
        distributions: dict[str, dict] = {}
        all_suppressed_windows: list[dict] = []

        o_map = {o.get("id"): o for o in cfg.get("oracles", []) if isinstance(o, dict)}
        guard_ratio = float(cfg.get("population_guard_ratio", 0.30))

        # Oracle 1
        c1 = o_map.get("failed_admin_burst", {})
        r1, d1, sup1 = _mine_failed_admin_burst(
            active_con,
            min_count=c1.get("min_count", 500),
            max_distinct_sources=c1.get("max_distinct_sources", 10),
        )
        oracle_rows.extend(r1)
        distributions["failed_admin_burst"] = d1
        all_suppressed_windows.extend(sup1)

        # Oracle 2
        c2 = o_map.get("slow_stuffing_24", {})
        r2, d2 = _mine_slow_stuffing_24(
            active_con,
            min_ips=c2.get("min_distinct_ips", 10),
            max_events=c2.get("max_events", 200),
            min_delta_seconds=c2.get("min_delta_seconds", 120),
            max_delta_seconds=c2.get("max_delta_seconds", 480),
        )
        oracle_rows.extend(r2)
        distributions["slow_stuffing_24"] = d2

        # Oracle 3
        r3, d3 = _mine_admin_success(active_con)
        oracle_rows.extend(r3)
        distributions["admin_success"] = d3

        # Oracle 4
        c4 = o_map.get("vpn_impossible_travel", {})
        r4, d4 = _mine_vpn_impossible_travel(active_con, window_minutes=c4.get("window_seconds", 3600) // 60)
        oracle_rows.extend(r4)
        distributions["vpn_impossible_travel"] = d4

        # Oracle 5
        r5, d5 = _mine_config_change(active_con)
        oracle_rows.extend(r5)
        distributions["config_change"] = d5

        # Oracle 6
        r6, d6 = _mine_virus_detected_not_blocked(active_con)
        oracle_rows.extend(r6)
        distributions["virus_detected_not_blocked"] = d6

        # Oracle 7
        c7 = o_map.get("port_scan", {})
        r7, d7, sup7 = _mine_port_scan(
            active_con,
            min_distinct_ports=c7.get("min_distinct_ports", 50),
            guard_ratio=guard_ratio,
        )
        oracle_rows.extend(r7)
        distributions["port_scan"] = d7
        all_suppressed_windows.extend(sup7)

        # Oracle 8
        c8 = o_map.get("lateral_fanout", {})
        r8, d8 = _mine_lateral_fanout(
            active_con,
            min_distinct_targets=c8.get("min_destinations", 10),
        )
        oracle_rows.extend(r8)
        distributions["lateral_fanout"] = d8

        # Oracle 9
        c9 = o_map.get("dns_tunnel", {})
        r9, d9 = _mine_dns_tunnel(
            active_con,
            min_distinct_names=c9.get("min_distinct_hostnames", 50),
            min_label_len=c9.get("min_length", 32),
        )
        oracle_rows.extend(r9)
        distributions["dns_tunnel"] = d9

        # Oracle 10
        c10 = o_map.get("beacon", {})
        r10, d10 = _mine_beacon(
            active_con,
            min_count=c10.get("min_events", 100),
            min_duration_sec=c10.get("min_duration_seconds", 21600),
            max_cv=float(c10.get("max_cv", 0.15)),
        )
        oracle_rows.extend(r10)
        distributions["beacon"] = d10

        # Oracle 11
        c11 = o_map.get("staged_exfil", {})
        r11, d11 = _mine_staged_exfil(
            active_con,
            min_count=c11.get("min_sessions", 500),
            min_duration_sec=c11.get("min_duration_seconds", 86400),
            min_ratio=float(c11.get("min_ratio", 1.5)),
        )
        oracle_rows.extend(r11)
        distributions["staged_exfil"] = d11

        # Oracle 12
        r12, d12 = _mine_web_payload(active_con)
        oracle_rows.extend(r12)
        distributions["web_payload"] = d12

        # Oracle 13
        r13, d13, sup13 = _mine_flood(
            active_con,
            guard_ratio=guard_ratio,
        )
        oracle_rows.extend(r13)
        distributions["flood"] = d13
        all_suppressed_windows.extend(sup13)

        # Merge consecutive oracle rows into sustained behaviors
        merged_behaviors = merge_oracle_rows_to_behaviors(oracle_rows)

        # 3. Fetch our detections & incidents
        raw_detections: list[dict] = []
        raw_incidents: list[dict] = []
        try:
            det_cols = {c[0].lower() for c in active_con.execute("DESCRIBE detections").fetchall()}
            where_sup = "WHERE (d.suppressed = false OR d.suppressed IS NULL)" if "suppressed" in det_cols else ""

            has_det_ev = False
            try:
                active_con.execute("DESCRIBE detection_events")
                has_det_ev = True
            except Exception:
                has_det_ev = False

            if has_det_ev:
                q_dets = f"""
                SELECT
                    d.detection_id,
                    d.rule_id,
                    d.technique_id,
                    d.tactic,
                    d.incident_id,
                    d.ts,
                    coalesce(min(e.ts), d.ts) as first_seen,
                    coalesce(max(e.ts), d.ts) as last_seen,
                    list_distinct(list(e.src_ip) FILTER (WHERE e.src_ip IS NOT NULL AND e.src_ip != '')) as src_ips,
                    list_distinct(list(e.dst_ip) FILTER (WHERE e.dst_ip IS NOT NULL AND e.dst_ip != '')) as dst_ips,
                    list_distinct(list(e.user) FILTER (WHERE e.user IS NOT NULL AND e.user != '')) as users,
                    d.event_ids,
                    d.host,
                    d.severity
                FROM detections d
                LEFT JOIN detection_events de ON d.detection_id = de.detection_id
                LEFT JOIN events e ON de.event_id = e.event_id
                {where_sup}
                GROUP BY d.detection_id, d.rule_id, d.technique_id, d.tactic, d.incident_id, d.ts, d.event_ids, d.host, d.severity
                """
            else:
                q_dets = f"""
                SELECT
                    d.detection_id,
                    d.rule_id,
                    d.technique_id,
                    d.tactic,
                    d.incident_id,
                    d.ts,
                    d.ts as first_seen,
                    d.ts as last_seen,
                    []::VARCHAR[] as src_ips,
                    []::VARCHAR[] as dst_ips,
                    []::VARCHAR[] as users,
                    d.event_ids,
                    d.host,
                    d.severity
                FROM detections d
                {where_sup}
                """
            for r in active_con.execute(q_dets).fetchall():
                eids = r[11]
                if isinstance(eids, str):
                    try:
                        eids = json.loads(eids)
                    except Exception:
                        eids = []
                s_list = r[8] or []
                d_list = r[9] or []
                u_list = r[10] or []
                raw_detections.append({
                    "detection_id": r[0],
                    "rule_id": r[1],
                    "technique_id": r[2],
                    "tactic": r[3],
                    "incident_id": r[4],
                    "ts": r[5],
                    "first_seen": r[6],
                    "last_seen": r[7],
                    "src_ips": s_list,
                    "dst_ips": d_list,
                    "users": u_list,
                    "src_ip": s_list[0] if s_list else None,
                    "dst_ip": d_list[0] if d_list else None,
                    "user": u_list[0] if u_list else None,
                    "event_ids": eids,
                    "host": r[12] if len(r) > 12 else None,
                    "severity": r[13] if len(r) > 13 else 5,
                })
        except Exception as exc:
            logger.warning("Failed to load detections: %s", exc)

        try:
            inc_rows = active_con.execute("SELECT incident_id FROM incidents").fetchall()
            raw_incidents = [{"incident_id": r[0]} for r in inc_rows]
        except Exception:
            raw_incidents = []

        # 4. Score Detections against Oracle Rows
        # Match condition: share src_ip, dst_ip, or user AND time overlap +/- 10 minutes
        matched_oracle_indices = set()
        matched_detection_ids = set()
        oracle_match_map: dict[int, list[dict]] = {}  # oracle_idx -> list[detection]
        det_match_map: dict[str, list[OracleRow]] = {}  # det_id -> list[OracleRow]

        for idx, o in enumerate(oracle_rows):
            o_start = _parse_dt(o.t_start)
            o_end = _parse_dt(o.t_end)
            if not o_start or not o_end:
                continue
            # Tolerance +/- 10 minutes (600 seconds)
            tol_start = o_start.timestamp() - 600
            tol_end = o_end.timestamp() + 600

            for d in raw_detections:
                # Entity match check
                s_ips = d.get("src_ips", [])
                d_ips = d.get("dst_ips", [])
                usrs = d.get("users", [])

                entity_match = False
                if o.src_ip:
                    if o.src_ip.endswith("/24"):
                        prefix = o.src_ip[:-4]
                        if any(s.startswith(prefix) for s in s_ips):
                            entity_match = True
                    elif o.src_ip in s_ips:
                        entity_match = True
                if not entity_match and o.dst_ip and o.dst_ip in d_ips:
                    entity_match = True
                if not entity_match and o.user and any(u.lower() == o.user.lower() for u in usrs):
                    entity_match = True

                # Evidence event IDs intersection fallback
                if not entity_match and o.evidence_event_ids and d.get("event_ids"):
                    if set(o.evidence_event_ids) & set(d["event_ids"]):
                        entity_match = True

                if not entity_match:
                    continue

                # Time window overlap check (+/- 10 minutes)
                d_f = _parse_dt(d.get("first_seen"))
                d_l = _parse_dt(d.get("last_seen") or d.get("first_seen"))
                if not d_f or not d_l:
                    continue
                d_f_sec = d_f.timestamp()
                d_l_sec = d_l.timestamp()

                # Overlap test: d_f_sec <= tol_end AND d_l_sec >= tol_start
                if d_f_sec <= tol_end and d_l_sec >= tol_start:
                    matched_oracle_indices.add(idx)
                    matched_detection_ids.add(d["detection_id"])
                    oracle_match_map.setdefault(idx, []).append(d)
                    det_match_map.setdefault(d["detection_id"], []).append(o)

        # 4b. Score Detections against Merged Behaviors
        matched_behavior_indices = set()
        for b_idx, b in enumerate(merged_behaviors):
            b_start = _parse_dt(b.t_start)
            b_end = _parse_dt(b.t_end)
            if not b_start or not b_end:
                continue
            tol_start = b_start.timestamp() - 600
            tol_end = b_end.timestamp() + 600

            for d in raw_detections:
                s_ips = d.get("src_ips", [])
                d_ips = d.get("dst_ips", [])
                usrs = d.get("users", [])

                entity_match = False
                if b.src_ip:
                    if b.src_ip.endswith("/24"):
                        prefix = b.src_ip[:-4]
                        if any(s.startswith(prefix) for s in s_ips):
                            entity_match = True
                    elif b.src_ip in s_ips:
                        entity_match = True
                if not entity_match and b.dst_ip and b.dst_ip in d_ips:
                    entity_match = True
                if not entity_match and b.user and any(u.lower() == b.user.lower() for u in usrs):
                    entity_match = True

                if not entity_match and b.evidence_event_ids and d.get("event_ids"):
                    if set(b.evidence_event_ids) & set(d["event_ids"]):
                        entity_match = True

                if not entity_match:
                    continue

                d_f = _parse_dt(d.get("first_seen"))
                d_l = _parse_dt(d.get("last_seen") or d.get("first_seen"))
                if not d_f or not d_l:
                    continue
                d_f_sec = d_f.timestamp()
                d_l_sec = d_l.timestamp()

                if d_f_sec <= tol_end and d_l_sec >= tol_start:
                    matched_behavior_indices.add(b_idx)
                    break

        # 5. Compute Per-Class & Overall Recall & Label Accuracy
        classes = sorted({o.oracle_id for o in oracle_rows})
        per_class_stats: dict[str, dict[str, Any]] = {}
        total_exact_matches = 0
        total_family_matches = 0
        total_matched_detections = len(matched_detection_ids)

        for c in classes:
            c_indices = [i for i, o in enumerate(oracle_rows) if o.oracle_id == c]
            c_total = len(c_indices)
            c_matched = len([i for i in c_indices if i in matched_oracle_indices])
            c_recall = (c_matched / c_total) if c_total > 0 else 0.0

            b_indices = [i for i, b in enumerate(merged_behaviors) if b.oracle_id == c]
            b_total = len(b_indices)
            b_matched = len([i for i in b_indices if i in matched_behavior_indices])
            b_recall = (b_matched / b_total) if b_total > 0 else 0.0

            # Label accuracy for detections matching this class
            c_exact = 0
            c_family = 0
            c_dets_count = 0
            for i in c_indices:
                for d in oracle_match_map.get(i, []):
                    c_dets_count += 1
                    d_tech = d.get("technique_id", "")
                    exp_tech = oracle_rows[i].expected_technique
                    # Exact or multi-technique match
                    if exp_tech in d_tech or d_tech in exp_tech:
                        c_exact += 1
                        c_family += 1
                    elif _is_family_match(d_tech, exp_tech):
                        c_family += 1

            per_class_stats[c] = {
                "oracle_rows": c_total,
                "matched": c_matched,
                "silver_recall": round(c_recall, 4),
                "behaviors": b_total,
                "matched_behaviors": b_matched,
                "behavior_recall": round(b_recall, 4),
                "label_accuracy_exact": round(c_exact / c_dets_count, 4) if c_dets_count > 0 else None,
                "label_accuracy_family": round(c_family / c_dets_count, 4) if c_dets_count > 0 else None,
                "metric_distribution": distributions.get(c, {}),
            }

        # Overall exact / family accuracy & confusion list
        confusion_counts: dict[tuple[str, str, str], int] = {}
        for det_id, orow_list in det_match_map.items():
            d = next((x for x in raw_detections if x["detection_id"] == det_id), None)
            if not d:
                continue
            d_tech = d.get("technique_id", "")
            is_exact = any(o.expected_technique in d_tech or d_tech in o.expected_technique for o in orow_list)
            is_family = is_exact or any(_is_family_match(d_tech, o.expected_technique) for o in orow_list)
            if is_exact:
                total_exact_matches += 1
            else:
                for o in orow_list:
                    if o.expected_technique not in d_tech and d_tech not in o.expected_technique:
                        key = (o.oracle_id, o.expected_technique, d_tech)
                        confusion_counts[key] = confusion_counts.get(key, 0) + 1
            if is_family:
                total_family_matches += 1

        confusion_list = [
            {
                "oracle_class": k[0],
                "expected_technique": k[1],
                "emitted_technique": k[2],
                "count": v,
            }
            for k, v in sorted(confusion_counts.items(), key=lambda x: -x[1])
        ]

        # Behaviour-level active detections collapsing:
        # Group active detections by (rule_id, canonical_entity)
        det_behaviors_groups: dict[tuple[str, str], list[dict]] = {}
        for d in raw_detections:
            r_id = d.get("rule_id", "")
            s_ips = d.get("src_ips") or []
            d_ips = d.get("dst_ips") or []
            usrs = d.get("users") or []
            ent = s_ips[0] if s_ips else (d_ips[0] if d_ips else (usrs[0] if usrs else (d.get("host") or "unknown")))
            det_behaviors_groups.setdefault((r_id, ent), []).append(d)

        active_behavior_clusters: list[list[dict]] = []
        for (r_id, ent), d_items in det_behaviors_groups.items():
            d_items.sort(key=lambda x: _to_epoch(x.get("first_seen") or x.get("ts")))
            cur_cluster: list[dict] = []
            cur_cluster_end: float = -1.0
            for itm in d_items:
                itm_start = _to_epoch(itm.get("first_seen") or itm.get("ts"))
                itm_end = _to_epoch(itm.get("last_seen") or itm.get("ts"))
                if not cur_cluster:
                    cur_cluster = [itm]
                    cur_cluster_end = itm_end
                elif itm_start <= cur_cluster_end + 3600.0:
                    cur_cluster.append(itm)
                    cur_cluster_end = max(cur_cluster_end, itm_end)
                else:
                    active_behavior_clusters.append(cur_cluster)
                    cur_cluster = [itm]
                    cur_cluster_end = itm_end
            if cur_cluster:
                active_behavior_clusters.append(cur_cluster)

        total_active_behaviors = len(active_behavior_clusters)
        matched_active_behaviors = sum(
            1 for c in active_behavior_clusters if any(item["detection_id"] in matched_detection_ids for item in c)
        )
        precision_proxy_behavior = round(matched_active_behaviors / total_active_behaviors, 4) if total_active_behaviors > 0 else 0.0
        precision_proxy_detection = round(total_matched_detections / len(raw_detections), 4) if raw_detections else 0.0

        overall_recall = (len(matched_oracle_indices) / len(oracle_rows)) if oracle_rows else 0.0
        overall_behavior_recall = (len(matched_behavior_indices) / len(merged_behaviors)) if merged_behaviors else 0.0
        exact_label_acc = (total_exact_matches / total_matched_detections) if total_matched_detections > 0 else None
        family_label_acc = (total_family_matches / total_matched_detections) if total_matched_detections > 0 else None

        # 6. Incident Coverage (multi-class ordering)
        # Does a single incident contain detections matched to >= 2 oracle classes sharing an entity,
        # and are they ordered by tactic stage?
        covered_incidents_count = 0
        ordered_incidents_count = 0
        multi_class_incidents_count = 0

        # Build incident -> detections mapping
        inc_dets: dict[str, list[dict]] = {}
        for d in raw_detections:
            inc_id = d.get("incident_id")
            if inc_id:
                inc_dets.setdefault(inc_id, []).append(d)

        for inc_id, d_list in inc_dets.items():
            # Get oracle classes for matched detections
            matched_in_inc = []
            for d in d_list:
                for o in det_match_map.get(d["detection_id"], []):
                    matched_in_inc.append((d, o))

            distinct_classes = {o.oracle_id for _, o in matched_in_inc}
            if len(distinct_classes) >= 2:
                multi_class_incidents_count += 1
                # Check entity sharing
                shared_entity = False
                all_ents: set[str] = set()
                for d, o in matched_in_inc:
                    cur_ents = set(d.get("src_ips", [])) | set(d.get("dst_ips", [])) | set(d.get("users", []))
                    if not cur_ents:
                        cur_ents = {e for e in [d.get("src_ip"), d.get("dst_ip"), d.get("user"), o.src_ip, o.dst_ip, o.user] if e}
                    if any(e in all_ents for e in cur_ents):
                        shared_entity = True
                    all_ents.update(cur_ents)

                if shared_entity:
                    covered_incidents_count += 1
                    # Check chronological tactic order
                    sorted_by_time = sorted(
                        matched_in_inc,
                        key=lambda x: _parse_dt(x[0].get("first_seen")) or datetime.min.replace(tzinfo=UTC),
                    )
                    tactic_orders = [TACTIC_ORDER.get(o.expected_tactic, 99) for _, o in sorted_by_time]
                    is_ordered = all(tactic_orders[k] <= tactic_orders[k + 1] for k in range(len(tactic_orders) - 1))
                    if is_ordered:
                        ordered_incidents_count += 1

        # 7. Unconfirmed Detections (by rule)
        unconfirmed_by_rule: dict[str, int] = {}
        for d in raw_detections:
            if d["detection_id"] not in matched_detection_ids:
                rid = d.get("rule_id", "unknown_rule")
                unconfirmed_by_rule[rid] = unconfirmed_by_rule.get(rid, 0) + 1

        # 8. Missed Oracle Rows
        missed_oracle_rows: list[dict[str, Any]] = []
        for idx, o in enumerate(oracle_rows):
            if idx not in matched_oracle_indices:
                missed_oracle_rows.append({
                    "oracle_id": o.oracle_id,
                    "expected_technique": o.expected_technique,
                    "expected_tactic": o.expected_tactic,
                    "src_ip": o.src_ip,
                    "dst_ip": o.dst_ip,
                    "user": o.user,
                    "t_start": o.t_start,
                    "t_end": o.t_end,
                    "metric": o.metric,
                    "evidence_event_ids": o.evidence_event_ids[:5],
                })

        # Summary output payload
        summary = {
            "banner": BANNER,
            "total_oracle_rows": len(oracle_rows),
            "matched_oracle_rows": len(matched_oracle_indices),
            "silver_recall": round(overall_recall, 4),
            "merged_behaviors_count": len(merged_behaviors),
            "matched_behaviors_count": len(matched_behavior_indices),
            "behavior_recall": round(overall_behavior_recall, 4),
            "label_accuracy_exact": round(exact_label_acc, 4) if exact_label_acc is not None else None,
            "label_accuracy_family": round(family_label_acc, 4) if family_label_acc is not None else None,
            "total_our_detections": len(raw_detections),
            "matched_detections": total_matched_detections,
            "unconfirmed_detections_count": len(raw_detections) - total_matched_detections,
            "precision_proxy": precision_proxy_detection,
            "precision_proxy_detection": precision_proxy_detection,
            "precision_proxy_behavior": precision_proxy_behavior,
            "total_active_behaviors": total_active_behaviors,
            "matched_active_behaviors": matched_active_behaviors,
            "confusion_list": confusion_list,
            "total_our_incidents": len(raw_incidents),
            "multi_class_incidents": multi_class_incidents_count,
            "incident_multi_class_coverage": covered_incidents_count,
            "incident_ordered_coverage": ordered_incidents_count,
            "per_class": per_class_stats,
            "unconfirmed_detections_by_rule": dict(sorted(unconfirmed_by_rule.items(), key=lambda x: -x[1])),
            "suppressed_population_windows": all_suppressed_windows,
            "missed_oracle_rows": missed_oracle_rows,
            "all_oracle_rows": [asdict(r) for r in oracle_rows],
            "all_behaviors": [asdict(b) for b in merged_behaviors],
        }

        return summary

    finally:
        if close_con:
            active_con.close()
