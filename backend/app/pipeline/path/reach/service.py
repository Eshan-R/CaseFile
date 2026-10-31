"""Service layer for precomputing and managing incident reachability projections."""

from __future__ import annotations

import logging
from typing import Any

from app.pipeline.path.reach.engine import compute_reach
from app.schemas.reach import NextReach
from app.store import duck

logger = logging.getLogger(__name__)


def extract_access_edges_from_events(limit: int = 100_000) -> list[dict[str, Any]]:
    """Extract observed network and logon access edges from DuckDB events table."""
    edges: list[dict[str, Any]] = []
    try:
        with duck.cursor() as con:
            # 1. User -> Host logons
            user_logons = con.execute(
                """
                SELECT 
                    COALESCE(user, user_name) AS src_user,
                    COALESCE(host, dst_ip) AS tgt_host,
                    CASE 
                        WHEN LOWER(COALESCE(user, user_name)) IN ('admin', 'administrator', 'root') 
                             OR LOWER(COALESCE(user, user_name)) LIKE '%admin%' 
                        THEN true 
                        ELSE false 
                    END AS is_admin,
                    COUNT(*) AS cnt,
                    MAX(ts) AS last_ts,
                    LIST(event_id)[1:3] AS sample_evs
                FROM events
                WHERE COALESCE(user, user_name) IS NOT NULL 
                  AND COALESCE(user, user_name) != ''
                  AND COALESCE(host, dst_ip) IS NOT NULL
                  AND COALESCE(host, dst_ip) != ''
                GROUP BY 1, 2, 3
                LIMIT ?
                """,
                [limit],
            ).fetchall()

            for row in user_logons:
                src, tgt, is_adm, cnt, last_ts, ev_ids = row
                edges.append({
                    "source": src,
                    "target": tgt,
                    "kind": "admin" if is_adm else "logon",
                    "source_kind": "user",
                    "target_kind": "host",
                    "is_admin": bool(is_adm),
                    "count": cnt,
                    "last_seen": str(last_ts) if last_ts else None,
                    "evidence_event_ids": ev_ids or [],
                })

            # 2. Host -> Host connections
            host_conns = con.execute(
                """
                SELECT 
                    COALESCE(src_ip, host) AS src_host,
                    COALESCE(dst_ip, hostname) AS tgt_host,
                    COUNT(*) AS cnt,
                    MAX(ts) AS last_ts,
                    LIST(event_id)[1:3] AS sample_evs
                FROM events
                WHERE COALESCE(src_ip, host) IS NOT NULL 
                  AND COALESCE(src_ip, host) != ''
                  AND COALESCE(dst_ip, hostname) IS NOT NULL
                  AND COALESCE(dst_ip, hostname) != ''
                  AND COALESCE(src_ip, host) != COALESCE(dst_ip, hostname)
                GROUP BY 1, 2
                LIMIT ?
                """,
                [limit],
            ).fetchall()

            for row in host_conns:
                src, tgt, cnt, last_ts, ev_ids = row
                edges.append({
                    "source": src,
                    "target": tgt,
                    "kind": "connection",
                    "source_kind": "host",
                    "target_kind": "host",
                    "is_admin": False,
                    "count": cnt,
                    "last_seen": str(last_ts) if last_ts else None,
                    "evidence_event_ids": ev_ids or [],
                })
    except Exception as exc:
        logger.debug("Access edge extraction from events fallback: %s", exc)

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

    edges = access_edges if access_edges is not None else extract_access_edges_from_events()
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

    edges = extract_access_edges_from_events()
    count = 0
    for inc in incs:
        inc_id = inc["incident_id"]
        precompute_reach_for_incident(
            incident_id=inc_id,
            access_edges=edges,
            engine_name=engine_name,
            config=config,
        )
        count += 1

    return {"total_incidents": total, "precomputed": count}
