"""Service layer for precomputing and managing incident reachability projections."""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
import threading
from typing import Any

from app.config import settings
from app.pipeline.path.reach.assets import load_asset_rules
from app.pipeline.path.reach.engine import compute_reach
from app.schemas.next_paths import (
    DEFAULT_NEXT_PATHS_DISCLAIMER,
    NextPathEvidence,
    NextPathsResponse,
    PredictedPathItem,
)
from app.schemas.reach import NextReach
from app.store import duck

logger = logging.getLogger(__name__)

# Sensitive services mapped to canonical MITRE ATT&CK technique and tactic
SENSITIVE_PORT_MAP: dict[int, dict[str, str]] = {
    445: {"service": "SMB", "technique": "T1021.002", "tactic": "lateral_movement"},
    3389: {"service": "RDP", "technique": "T1021.001", "tactic": "lateral_movement"},
    22: {"service": "SSH", "technique": "T1021.004", "tactic": "lateral_movement"},
    1433: {"service": "MS-SQL", "technique": "T1021", "tactic": "lateral_movement"},
    3306: {"service": "MySQL", "technique": "T1021", "tactic": "lateral_movement"},
    5432: {"service": "PostgreSQL", "technique": "T1021", "tactic": "lateral_movement"},
    1521: {"service": "Oracle", "technique": "T1021", "tactic": "lateral_movement"},
    443: {"service": "HTTPS", "technique": "T1021", "tactic": "lateral_movement"},
    8443: {"service": "HTTPS-Alt", "technique": "T1021", "tactic": "lateral_movement"},
    8080: {"service": "HTTP-Alt", "technique": "T1021", "tactic": "lateral_movement"},
}

SERVICE_NAME_TO_PORT: dict[str, int] = {
    "smb": 445,
    "microsoft-ds": 445,
    "rdp": 3389,
    "ms-wbt-server": 3389,
    "ssh": 22,
    "mssql": 1433,
    "ms-sql": 1433,
    "mysql": 3306,
    "postgres": 5432,
    "postgresql": 5432,
    "oracle": 1521,
    "https": 443,
    "https-alt": 8443,
    "http-alt": 8080,
}

KILL_CHAIN_ORDER: list[str] = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

# In-memory cache for predicted paths: incident_id -> NextPathsResponse
_NEXT_PATHS_CACHE: dict[str, NextPathsResponse] = {}
_CACHE_LOCK = threading.Lock()


def clear_predicted_paths_cache(incident_id: str | None = None) -> None:
    """Clear the in-memory next-paths cache (all or for a specific incident)."""
    with _CACHE_LOCK:
        if incident_id:
            _NEXT_PATHS_CACHE.pop(incident_id, None)
        else:
            _NEXT_PATHS_CACHE.clear()


def is_internal_ip(ip_or_host: str) -> bool:
    """Check if an entity is within internal RFC 1918 ranges (10.*, 192.168.*, 172.16-31.*)."""
    if not ip_or_host:
        return False
    h = str(ip_or_host).strip()
    try:
        ip = ipaddress.ip_address(h)
        if ip.version == 4:
            for net in [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            ]:
                if ip in net:
                    return True
            return False
    except ValueError:
        pass

    # Regex check for 10.*, 192.168.*, 172.16-31.*
    if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)", h):
        return True
    return False


def _clean_entities(entities: list[str] | str | None) -> list[str]:
    """Clean and filter incident entities, stripping invalid/excluded values."""
    if not entities:
        return []
    if isinstance(entities, str):
        try:
            items = json.loads(entities)
        except Exception:
            items = [entities]
    else:
        items = list(entities)

    exclude = {
        s.strip().lower()
        for s in (settings.incident_exclude_entities or [])
    }
    exclude.update({"", "unknown", "none", "null", "127.0.0.1", "::1", "fgt60ftk00000000"})

    cleaned = []
    for item in items:
        val = str(item).strip()
        if val and val.lower() not in exclude:
            cleaned.append(val)
    return cleaned


def extract_access_edges_from_events(
    incident: dict[str, Any] | None = None,
    limit: int = 100_000,
) -> list[dict[str, Any]]:
    """Extract observed network and logon access edges from DuckDB events table.

    When an incident is provided, extraction is scoped to the incident's compromised
    entities and time window for sub-second precision and low blast radius latency.
    Only observed allowed traffic is included.
    """
    edges: list[dict[str, Any]] = []
    try:
        hosts_filter: list[str] = []
        users_filter: list[str] = []
        time_clauses: list[str] = []

        if incident:
            inc_hosts = _clean_entities(incident.get("hosts", []))
            inc_src_ips = _clean_entities(incident.get("src_ips", []))
            hosts_filter = list(dict.fromkeys(inc_hosts + inc_src_ips))
            users_filter = _clean_entities(incident.get("users", []))

            first_seen = incident.get("first_seen")
            last_seen = incident.get("last_seen")
            if first_seen and last_seen:
                time_clauses.append(
                    f"TRY_CAST(ts AS TIMESTAMPTZ) >= TRY_CAST('{first_seen}' AS TIMESTAMPTZ) - INTERVAL '2 HOURS'"
                )
                time_clauses.append(
                    f"TRY_CAST(ts AS TIMESTAMPTZ) <= TRY_CAST('{last_seen}' AS TIMESTAMPTZ) + INTERVAL '2 HOURS'"
                )

        time_sql = f"AND {' AND '.join(time_clauses)}" if time_clauses else ""

        with duck.cursor() as con:
            # 1. Host -> Host allowed connections
            host_where_parts = [
                "src_ip IS NOT NULL AND src_ip != ''",
                "dst_ip IS NOT NULL AND dst_ip != ''",
                "src_ip != dst_ip",
                "LOWER(COALESCE(action, '')) IN ('accept', 'allow', 'pass', 'allowed')",
            ]
            if hosts_filter:
                quoted = ", ".join(f"'{h}'" for h in hosts_filter)
                host_where_parts.append(f"src_ip IN ({quoted})")

            host_query = f"""
            SELECT 
                src_ip AS src_host,
                dst_ip AS tgt_host,
                COALESCE(dst_port, 0) AS d_port,
                LOWER(COALESCE(service, app, CAST(proto AS VARCHAR), 'tcp')) AS proto_srv,
                COUNT(*) AS cnt,
                MAX(ts) AS last_ts,
                LIST(event_id)[1:3] AS sample_evs
            FROM events
            WHERE {' AND '.join(host_where_parts)} {time_sql}
            GROUP BY 1, 2, 3, 4
            ORDER BY cnt DESC
            LIMIT ?
            """
            for row in con.execute(host_query, [limit]).fetchall():
                src, tgt, d_port, proto_srv, cnt, last_ts, ev_ids = row
                port_str = f"/{d_port}" if d_port else ""
                reason = f"allowed on {proto_srv}{port_str} seen {cnt} {'times' if cnt != 1 else 'time'}"
                edges.append({
                    "source": src,
                    "target": tgt,
                    "kind": "connection",
                    "source_kind": "host",
                    "target_kind": "host",
                    "dst_port": d_port,
                    "service": proto_srv,
                    "proto": proto_srv,
                    "reason": reason,
                    "is_admin": False,
                    "count": cnt,
                    "last_seen": str(last_ts) if last_ts else None,
                    "evidence_event_ids": ev_ids or [],
                })

            # 2. User -> Host logons
            user_where_parts = [
                "COALESCE(user, user_raw) IS NOT NULL AND COALESCE(user, user_raw) != ''",
                "COALESCE(host, dst_ip) IS NOT NULL AND COALESCE(host, dst_ip) != ''",
                "LOWER(COALESCE(action, '')) IN ('accept', 'allow', 'pass', 'allowed', 'login', 'success')",
            ]
            if users_filter or hosts_filter:
                entity_clauses = []
                if users_filter:
                    quoted_u = ", ".join(f"'{u}'" for u in users_filter)
                    entity_clauses.append(f"COALESCE(user, user_raw) IN ({quoted_u})")
                if hosts_filter:
                    quoted_h = ", ".join(f"'{h}'" for h in hosts_filter)
                    entity_clauses.append(f"COALESCE(host, dst_ip) IN ({quoted_h})")
                user_where_parts.append(f"({' OR '.join(entity_clauses)})")

            user_query = f"""
            SELECT 
                COALESCE(user, user_raw) AS src_user,
                COALESCE(host, dst_ip) AS tgt_host,
                CASE 
                    WHEN LOWER(COALESCE(user, user_raw)) IN ('admin', 'administrator', 'root') 
                         OR LOWER(COALESCE(user, user_raw)) LIKE '%admin%' 
                    THEN true 
                    ELSE false 
                END AS is_admin,
                COUNT(*) AS cnt,
                MAX(ts) AS last_ts,
                LIST(event_id)[1:3] AS sample_evs
            FROM events
            WHERE {' AND '.join(user_where_parts)} {time_sql}
            GROUP BY 1, 2, 3
            ORDER BY cnt DESC
            LIMIT ?
            """
            for row in con.execute(user_query, [limit]).fetchall():
                src, tgt, is_adm, cnt, last_ts, ev_ids = row
                role = "admin " if is_adm else ""
                reason = f"{src} {role}logon to {tgt} seen {cnt} {'times' if cnt != 1 else 'time'}"
                edges.append({
                    "source": src,
                    "target": tgt,
                    "kind": "admin" if is_adm else "logon",
                    "source_kind": "user",
                    "target_kind": "host",
                    "reason": reason,
                    "is_admin": bool(is_adm),
                    "count": cnt,
                    "last_seen": str(last_ts) if last_ts else None,
                    "evidence_event_ids": ev_ids or [],
                })

    except Exception as exc:
        logger.warning("Access edge extraction error: %s", exc)

    return edges


def precompute_reach_for_incident(
    incident_id: str,
    access_edges: list[dict[str, Any]] | None = None,
    engine_name: str | None = None,
    config: dict[str, Any] | None = None,
) -> NextReach:
    """Precompute NextReach for an incident and persist it into incident_next."""
    inc = duck.get_incident(incident_id)
    if not inc:
        raise ValueError(f"Incident {incident_id!r} not found")

    edges = access_edges if access_edges is not None else extract_access_edges_from_events(incident=inc)
    next_res = compute_reach(
        incident=inc,
        access_edges=edges,
        config=config,
        engine_name=engine_name,
    )

    # Persist into DuckDB incident_next table
    duck.set_incident_next(
        incident_id=incident_id,
        data=next_res.model_dump(),
        blast_hosts=next_res.blast_radius.hosts_count,
        blast_users=next_res.blast_radius.users_count,
        critical_assets=next_res.blast_radius.critical_assets_reached,
    )

    return next_res


def precompute_all_incidents(
    engine_name: str | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Precompute and persist reach analysis for all incidents in the database."""
    total, incs = duck.list_incidents(limit=10_000)
    if not incs:
        return {"total_incidents": 0, "precomputed": 0}

    count = 0
    for inc in incs:
        if inc.get("status") in ("alert", "lead"):
            continue
        inc_id = inc["incident_id"]
        # Skip if reach already precomputed
        if duck.get_incident_next(inc_id):
            count += 1
            continue
        precompute_reach_for_incident(
            incident_id=inc_id,
            access_edges=None,
            engine_name=engine_name,
            config=config,
        )
        count += 1

    return {"total_incidents": total, "precomputed": count}


# =========================================================================
# Predictive Next Paths Deterministic Engine (Task 2 & 4)
# =========================================================================

def get_incident_last_tactic(incident: dict[str, Any]) -> str | None:
    """Determine the incident's last observed tactic in kill-chain order."""
    steps = incident.get("steps", [])
    if isinstance(steps, str):
        try:
            steps = json.loads(steps)
        except Exception:
            steps = []

    if steps:
        # Sort chronologically by first_seen, tie-break by kill chain rank
        def sort_key(s: dict[str, Any]) -> tuple[str, int]:
            ts = str(s.get("first_seen") or s.get("ts") or "")
            tactic = str(s.get("tactic", "")).lower().replace("-", "_").replace(" ", "_")
            rank = KILL_CHAIN_ORDER.index(tactic) if tactic in KILL_CHAIN_ORDER else -1
            return (ts, rank)

        sorted_steps = sorted(steps, key=sort_key)
        for s in reversed(sorted_steps):
            t_raw = str(s.get("tactic", "")).lower().replace("-", "_").replace(" ", "_")
            if t_raw in KILL_CHAIN_ORDER:
                return t_raw

    # Fallback to techniques list
    techs = incident.get("techniques", [])
    if isinstance(techs, str):
        try:
            techs = json.loads(techs)
        except Exception:
            techs = [techs]

    if techs:
        # Common technique to tactic mappings
        tech_to_tactic: dict[str, str] = {
            "T1595": "reconnaissance",
            "T1190": "initial_access",
            "T1566": "initial_access",
            "T1078": "initial_access",
            "T1059": "execution",
            "T1204": "execution",
            "T1505": "persistence",
            "T1053": "persistence",
            "T1136": "persistence",
            "T1055": "privilege_escalation",
            "T1070": "defense_evasion",
            "T1562": "defense_evasion",
            "T1110": "credential_access",
            "T1003": "credential_access",
            "T1046": "discovery",
            "T1087": "discovery",
            "T1082": "discovery",
            "T1021": "lateral_movement",
            "T1005": "collection",
            "T1071": "command_and_control",
            "T1105": "command_and_control",
            "T1048": "exfiltration",
            "T1486": "impact",
            "T1498": "impact",
        }
        for t in reversed(techs):
            prefix = str(t).split(".")[0].upper()
            if prefix in tech_to_tactic:
                return tech_to_tactic[prefix]

    return None


def check_tactic_transition_support(last_tactic: str | None, candidate_tactic: str) -> bool:
    """Check if candidate tactic represents a forward progression in the kill chain.

    e.g. if last observed tactic was credential_access (rank 7), next expected
    tactics are discovery (rank 8) or lateral_movement (rank 9).
    """
    cand = candidate_tactic.lower().replace("-", "_").replace(" ", "_")
    if not last_tactic:
        return True

    last = last_tactic.lower().replace("-", "_").replace(" ", "_")
    if last not in KILL_CHAIN_ORDER or cand not in KILL_CHAIN_ORDER:
        return True

    last_idx = KILL_CHAIN_ORDER.index(last)
    cand_idx = KILL_CHAIN_ORDER.index(cand)

    # Forward tactic transition: candidate tactic is at or after last observed tactic in kill chain
    return cand_idx >= last_idx


def evaluate_asset_criticality(target: str, port: int) -> int:
    """Evaluate target asset criticality returning an integer (1 to 3).

    3 = Critical asset (Domain Controller, Identity, Active Directory, Backup Vault, or explicit host)
    2 = High value server/database (SQL, Database, File Server, or database ports)
    1 = Standard internal host / workstation
    """
    t_low = target.lower().strip()

    # Tier 3: DC, AD, Primary identity, explicit critical assets
    tier3_patterns = ["dc", "domain", "ad", "backup", "vault"]
    explicit_hosts = {
        "dc-01", "dc-02", "dc-server", "ad-primary", "backup-vault"
    }
    try:
        rules = load_asset_rules()
        explicit_hosts.update({str(h).lower() for h in rules.get("explicit_hosts", [])})
    except Exception:
        pass

    if t_low in explicit_hosts or any(p in t_low for p in tier3_patterns):
        return 3

    # Tier 2: Database servers, file servers, or database ports
    tier2_patterns = ["sql", "db", "fs", "file", "srv", "server"]
    db_ports = {1433, 3306, 5432, 1521}
    if port in db_ports or any(p in t_low for p in tier2_patterns):
        return 2

    return 1


def _fetch_candidate_lateral_edges(
    internal_hosts: list[str],
) -> list[dict[str, Any]]:
    """Query allowed outbound connections from internal hosts on sensitive ports.

    Checks reach_edges table first if available, otherwise queries events table.
    """
    if not internal_hosts:
        return []

    quoted_hosts = ", ".join(f"'{h}'" for h in internal_hosts)
    port_list = ", ".join(str(p) for p in SENSITIVE_PORT_MAP)
    edges: list[dict[str, Any]] = []

    with duck.cursor() as con:
        # Check if reach_edges table exists
        has_reach_edges = False
        try:
            row = con.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_name = 'reach_edges'"
            ).fetchone()
            has_reach_edges = bool(row)
        except Exception:
            has_reach_edges = False

        if has_reach_edges:
            try:
                q = f"""
                SELECT 
                    source,
                    target,
                    COALESCE(dst_port, port, 0) AS d_port,
                    LOWER(COALESCE(service, 'tcp')) AS proto_srv,
                    COALESCE(count, cnt, 1) AS cnt,
                    last_seen AS last_ts
                FROM reach_edges
                WHERE source IN ({quoted_hosts})
                  AND target IS NOT NULL AND target != ''
                  AND source != target
                  AND (dst_port IN ({port_list}) OR port IN ({port_list}))
                """
                for r in con.execute(q).fetchall():
                    edges.append({
                        "src_host": str(r[0]),
                        "tgt_host": str(r[1]),
                        "d_port": int(r[2]),
                        "proto_srv": str(r[3]),
                        "cnt": int(r[4]),
                        "last_ts": str(r[5]) if r[5] else None,
                    })
            except Exception as e:
                logger.debug("Failed querying reach_edges table: %s", e)

        # Fallback to events table
        if not edges:
            try:
                q_events = f"""
                SELECT 
                    src_ip AS src_host,
                    dst_ip AS tgt_host,
                    COALESCE(dst_port, 0) AS d_port,
                    LOWER(COALESCE(service, app, CAST(proto AS VARCHAR), 'tcp')) AS proto_srv,
                    COUNT(*) AS cnt,
                    MAX(ts) AS last_ts
                FROM events
                WHERE src_ip IN ({quoted_hosts})
                  AND dst_ip IS NOT NULL AND dst_ip != ''
                  AND src_ip != dst_ip
                  AND LOWER(COALESCE(action, '')) IN ('accept', 'allow', 'pass', 'allowed')
                  AND (
                      dst_port IN ({port_list})
                      OR LOWER(COALESCE(service, app, '')) IN (
                          'smb', 'microsoft-ds', 'rdp', 'ms-wbt-server', 'ssh',
                          'mssql', 'ms-sql', 'mysql', 'postgres', 'postgresql', 'oracle',
                          'https', 'https-alt', 'http-alt'
                      )
                  )
                GROUP BY 1, 2, 3, 4
                ORDER BY cnt DESC
                """
                for r in con.execute(q_events).fetchall():
                    d_p = int(r[2])
                    p_srv = str(r[3])
                    # If port was 0, resolve from service name
                    if d_p == 0:
                        d_p = SERVICE_NAME_TO_PORT.get(p_srv, 0)
                    if d_p in SENSITIVE_PORT_MAP:
                        edges.append({
                            "src_host": str(r[0]),
                            "tgt_host": str(r[1]),
                            "d_port": d_p,
                            "proto_srv": p_srv,
                            "cnt": int(r[4]),
                            "last_ts": str(r[5]) if r[5] else None,
                        })
            except Exception as exc:
                logger.warning("Error fetching candidate lateral edges from events: %s", exc)

    return edges


def predict_next_paths(
    incident: dict[str, Any],
    candidate_edges: list[dict[str, Any]] | None = None,
) -> NextPathsResponse:
    """Deterministically predict top lateral movement attack paths for an incident.

    Formula:
      Score = (allowed_connections_observed * 0.3)
            + (asset_criticality * 0.4)
            + (0.3 if tactic_transition_support else 0.0)
            - (0.5 if target_already_touched else 0.0)

    Takes top 3 paths strictly filtered to sensitive services, calculates
    likelihood (0.0 to 1.0) and confidence ('low' | 'medium' | 'high'), and
    provides actionable monitor_or_block guidance.
    """
    raw_hosts = _clean_entities(incident.get("hosts", []))
    raw_src_ips = _clean_entities(incident.get("src_ips", []))
    all_incident_entities = set(raw_hosts + raw_src_ips)

    # Check steps for additional entities
    steps = incident.get("steps", [])
    if isinstance(steps, str):
        try:
            steps = json.loads(steps)
        except Exception:
            steps = []
    for s in steps:
        h = s.get("host")
        if h:
            all_incident_entities.add(str(h).strip())

    # Identify internal hosts (10.*, 192.168.*, 172.16-31.*)
    internal_hosts = [h for h in all_incident_entities if is_internal_ip(h)]

    # If hosts are hostnames without explicit IP, resolve any internal IPs from events
    if not internal_hosts and raw_hosts:
        try:
            with duck.cursor() as con:
                q_hosts = ", ".join(f"'{h}'" for h in raw_hosts)
                rows = con.execute(
                    f"SELECT DISTINCT src_ip FROM events WHERE host IN ({q_hosts}) AND src_ip IS NOT NULL"
                ).fetchall()
                for r in rows:
                    if r[0] and is_internal_ip(r[0]):
                        internal_hosts.append(r[0])
        except Exception:
            pass

    if not internal_hosts:
        return NextPathsResponse(
            predicted=True,
            disclaimer=DEFAULT_NEXT_PATHS_DISCLAIMER,
            reason="No outbound sensitive service connections observed from compromised entities",
            paths=[],
        )

    # Determine last observed tactic in kill-chain order
    last_tactic = get_incident_last_tactic(incident)

    # Query or receive candidate edges
    raw_candidates = (
        candidate_edges
        if candidate_edges is not None
        else _fetch_candidate_lateral_edges(internal_hosts)
    )

    if not raw_candidates:
        return NextPathsResponse(
            predicted=True,
            disclaimer=DEFAULT_NEXT_PATHS_DISCLAIMER,
            reason="No outbound sensitive service connections observed from compromised entities",
            paths=[],
        )

    # Aggregate candidate connections by (from_entity, to_entity, port)
    aggregated: dict[tuple[str, str, int], dict[str, Any]] = {}

    for c in raw_candidates:
        src = str(c.get("src_host", c.get("source", ""))).strip()
        tgt = str(c.get("tgt_host", c.get("target", ""))).strip()
        port = int(c.get("d_port", c.get("dst_port", c.get("port", 0))))
        srv = str(c.get("proto_srv", c.get("service", ""))).strip().lower()

        # Resolve port if missing
        if port == 0 and srv in SERVICE_NAME_TO_PORT:
            port = SERVICE_NAME_TO_PORT[srv]

        # Strictly filter to sensitive services
        if port not in SENSITIVE_PORT_MAP:
            continue

        # Skip self-connections
        if not src or not tgt or src == tgt:
            continue

        # Ensure source is an internal compromised host
        if not is_internal_ip(src) and src not in internal_hosts:
            continue

        cnt = int(c.get("cnt", c.get("count", 1)))
        ts = str(c.get("last_ts", c.get("last_seen", ""))) or None

        key = (src, tgt, port)
        if key not in aggregated:
            aggregated[key] = {
                "from_entity": src,
                "to_entity": tgt,
                "port": port,
                "count": 0,
                "last_seen": ts,
            }
        aggregated[key]["count"] += cnt
        if ts and (not aggregated[key]["last_seen"] or ts > aggregated[key]["last_seen"]):
            aggregated[key]["last_seen"] = ts

    if not aggregated:
        return NextPathsResponse(
            predicted=True,
            disclaimer=DEFAULT_NEXT_PATHS_DISCLAIMER,
            reason="No outbound sensitive service connections observed from compromised entities",
            paths=[],
        )

    scored_candidates: list[dict[str, Any]] = []

    for (from_ent, to_ent, port), agg in aggregated.items():
        meta = SENSITIVE_PORT_MAP[port]
        service_name = meta["service"]
        pred_technique = meta["technique"]
        pred_tactic = meta["tactic"]

        allowed_count = agg["count"]
        last_obs = agg["last_seen"]

        target_touched = to_ent in all_incident_entities
        tactic_support = check_tactic_transition_support(last_tactic, pred_tactic)
        crit_score = evaluate_asset_criticality(to_ent, port)

        # Deterministic scoring formula:
        # Score = (allowed_connections_observed * 0.3) + (asset_criticality * 0.4)
        #       + (0.3 if tactic_transition_support else 0.0)
        #       - (0.5 if target_already_touched else 0.0)
        score = (
            (allowed_count * 0.3)
            + (crit_score * 0.4)
            + (0.3 if tactic_support else 0.0)
            - (0.5 if target_touched else 0.0)
        )
        score = round(score, 2)

        # Likelihood bounded to 0.0 .. 1.0
        if score <= 0.0:
            likelihood = 0.0
        else:
            likelihood = round(min(1.0, max(0.0, 1.0 - math.exp(-score / 2.5))), 2)

        # Categorical confidence
        if likelihood >= 0.75 or score >= 3.0:
            confidence = "high"
        elif likelihood >= 0.40 or score >= 1.4:
            confidence = "medium"
        else:
            confidence = "low"

        evidence = NextPathEvidence(
            allowed_connections_observed=allowed_count,
            last_observed=last_obs,
            asset_criticality=crit_score,
            target_already_touched=target_touched,
            tactic_transition_support=tactic_support,
        )

        monitor_action = f"Monitor inbound {service_name} ({port}) on {to_ent} from {from_ent}"

        scored_candidates.append({
            "from_entity": from_ent,
            "to_entity": to_ent,
            "service": service_name,
            "port": port,
            "predicted_technique": pred_technique,
            "predicted_tactic": pred_tactic,
            "score": score,
            "likelihood": likelihood,
            "confidence": confidence,
            "evidence": evidence,
            "monitor_or_block": monitor_action,
        })

    # Sort deterministically
    scored_candidates.sort(
        key=lambda c: (
            -c["score"],
            -c["evidence"].allowed_connections_observed,
            -c["evidence"].asset_criticality,
            c["to_entity"],
            c["port"],
        )
    )

    top_3 = scored_candidates[:3]
    path_items: list[PredictedPathItem] = []
    for rank_idx, c in enumerate(top_3):
        path_items.append(
            PredictedPathItem(
                rank=rank_idx + 1,
                from_entity=c["from_entity"],
                to_entity=c["to_entity"],
                service=c["service"],
                port=c["port"],
                predicted_technique=c["predicted_technique"],
                predicted_tactic=c["predicted_tactic"],
                likelihood=c["likelihood"],
                confidence=c["confidence"],
                evidence=c["evidence"],
                monitor_or_block=c["monitor_or_block"],
            )
        )

    return NextPathsResponse(
        predicted=True,
        disclaimer=DEFAULT_NEXT_PATHS_DISCLAIMER,
        reason=None,
        paths=path_items,
    )


def get_predicted_next_paths(
    incident_id: str,
    refresh: bool = False,
) -> NextPathsResponse | None:
    """Retrieve predicted next lateral attack paths for an incident with in-memory caching."""
    if not refresh:
        with _CACHE_LOCK:
            if incident_id in _NEXT_PATHS_CACHE:
                return _NEXT_PATHS_CACHE[incident_id]

    inc = duck.get_incident(incident_id)
    if not inc:
        return None

    resp = predict_next_paths(incident=inc)

    with _CACHE_LOCK:
        _NEXT_PATHS_CACHE[incident_id] = resp

    return resp


def inject_predicted_paths_into_cytoscape(
    cyto_data: dict[str, Any] | Any,
    incident_id: str,
) -> dict[str, Any] | Any:
    """Inject predicted ghost nodes and predicted edges into Cytoscape graph data.

    Ghost nodes represent predicted reachable target entities:
      classes: "ghost-node predicted"
      data: {"id": to_ent, "label": to_ent, "predicted": True}

    Predicted edges represent lateral attack vectors:
      classes: "predicted-edge"
      data: {"source": from_ent, "target": to_ent, "label": "predicted_reach", "predicted": True, "evidence": ...}
    """
    resp = get_predicted_next_paths(incident_id)
    if not resp or not resp.paths:
        return cyto_data

    # Handle dictionary representation
    if isinstance(cyto_data, dict):
        elements = cyto_data.get("elements")
        if isinstance(elements, dict):
            nodes_list = elements.setdefault("nodes", [])
            edges_list = elements.setdefault("edges", [])
        else:
            nodes_list = cyto_data.setdefault("nodes", [])
            edges_list = cyto_data.setdefault("edges", [])

        existing_node_ids = set()
        for n in nodes_list:
            if isinstance(n, dict):
                nid = n.get("data", {}).get("id") or n.get("id")
                if nid:
                    existing_node_ids.add(str(nid))

        existing_edge_ids = set()
        for e in edges_list:
            if isinstance(e, dict):
                eid = e.get("data", {}).get("id") or e.get("id")
                if eid:
                    existing_edge_ids.add(str(eid))

        for p in resp.paths:
            to_ent = p.to_entity
            from_ent = p.from_entity
            edge_id = f"e_pred_{from_ent}_{to_ent}_{p.port}"

            # Add ghost node if target not already present
            if to_ent not in existing_node_ids:
                ghost_node = {
                    "classes": "ghost-node predicted",
                    "data": {
                        "id": to_ent,
                        "label": to_ent,
                        "predicted": True,
                    },
                }
                nodes_list.append(ghost_node)
                existing_node_ids.add(to_ent)

            # Add predicted edge if not already present
            if edge_id not in existing_edge_ids:
                pred_edge = {
                    "classes": "predicted-edge",
                    "data": {
                        "id": edge_id,
                        "source": from_ent,
                        "target": to_ent,
                        "label": "predicted_reach",
                        "predicted": True,
                        "evidence": p.evidence.model_dump(),
                    },
                }
                edges_list.append(pred_edge)
                existing_edge_ids.add(edge_id)

    return cyto_data
