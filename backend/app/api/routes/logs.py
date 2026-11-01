"""Incident attack evidence logs API endpoint."""

from __future__ import annotations

import json
import logging
from collections import defaultdict

from fastapi import APIRouter, HTTPException, Query

from app.schemas.logs import (
    AttackLogItem,
    IncidentLogsResponse,
    LogDetectionItem,
    SeverityCounts,
)
from app.store import duck

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incidents", tags=["logs"])

LEVEL_SEVERITY_MAP: dict[str, int] = {
    "emergency": 9,
    "alert": 9,
    "critical": 7,
    "error": 7,
    "high": 7,
    "warning": 5,
    "medium": 5,
    "notice": 2,
    "low": 2,
    "information": 0,
    "info": 0,
    "debug": 0,
}


def map_level_to_severity(lvl: str | None) -> int:
    """Map FortiGate level or severity string to integer score (0-9)."""
    if not lvl:
        return 0
    return LEVEL_SEVERITY_MAP.get(lvl.strip().lower(), 0)


def compute_severity_label(effective_sev: int) -> str:
    """Map effective severity score (0-10) to UI label."""
    if effective_sev >= 9:
        return "critical"
    if effective_sev >= 7:
        return "high"
    if effective_sev >= 4:
        return "medium"
    if effective_sev >= 1:
        return "low"
    return "info"


@router.get(
    "/{id}/logs",
    response_model=IncidentLogsResponse,
    summary="Get attack logs for an incident",
)
def get_incident_logs(
    id: str,
    limit: int = Query(100, ge=1, le=1000, description="Max logs to return"),
    offset: int = Query(0, ge=0, description="Offset into logs"),
    severity: str | None = Query(
        None,
        description="Filter by severity label (critical, high, medium, low, info)",
    ),
) -> IncidentLogsResponse:
    """Fetch correlated evidence logs for an incident with effective severity calculations."""
    try:
        with duck.cursor() as con:
            tables_views = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
            if "events" not in tables_views:
                return IncidentLogsResponse(
                    total=0,
                    counts=SeverityCounts(),
                    items=[],
                    reason="No evidence logs found for incident",
                )

            # 1. Discover all evidence event IDs for this incident
            event_ids: list[str] = []

            # 1a. Query incident_events
            if "incident_events" in tables_views:
                try:
                    rows = con.execute(
                        "SELECT DISTINCT event_id FROM incident_events WHERE incident_id = ?",
                        [id],
                    ).fetchall()
                    event_ids.extend(r[0] for r in rows if r[0])
                except Exception as exc:
                    logger.debug("Failed querying incident_events: %s", exc)

            # 1b. Query detection_events for detections of this incident
            if not event_ids and "detection_events" in tables_views and "detections" in tables_views:
                try:
                    rows = con.execute(
                        """
                        SELECT DISTINCT de.event_id
                        FROM detection_events de
                        JOIN detections d ON de.detection_id = d.detection_id
                        WHERE d.incident_id = ?
                        """,
                        [id],
                    ).fetchall()
                    event_ids.extend(r[0] for r in rows if r[0])
                except Exception as exc:
                    logger.debug("Failed querying detection_events: %s", exc)

            # 1c. Query detections.event_ids for detections of this incident
            if not event_ids and "detections" in tables_views:
                try:
                    rows = con.execute(
                        "SELECT event_ids FROM detections WHERE incident_id = ?",
                        [id],
                    ).fetchall()
                    for r in rows:
                        if r[0]:
                            eids = json.loads(r[0]) if isinstance(r[0], str) else r[0]
                            if isinstance(eids, list):
                                event_ids.extend(eids)
                except Exception as exc:
                    logger.debug("Failed querying detections.event_ids: %s", exc)

            # 1d. Query incidents table detection_ids
            if not event_ids and "incidents" in tables_views:
                try:
                    inc_row = con.execute(
                        "SELECT detection_ids FROM incidents WHERE incident_id = ?",
                        [id],
                    ).fetchone()
                    if inc_row and inc_row[0]:
                        det_ids = json.loads(inc_row[0]) if isinstance(inc_row[0], str) else inc_row[0]
                        if isinstance(det_ids, list) and det_ids:
                            if "detection_events" in tables_views:
                                rows = con.execute(
                                    "SELECT DISTINCT event_id FROM detection_events WHERE detection_id = ANY(?)",
                                    [det_ids],
                                ).fetchall()
                                event_ids.extend(r[0] for r in rows if r[0])
                            if not event_ids and "detections" in tables_views:
                                rows = con.execute(
                                    "SELECT event_ids FROM detections WHERE detection_id = ANY(?)",
                                    [det_ids],
                                ).fetchall()
                                for r in rows:
                                    if r[0]:
                                        eids = json.loads(r[0]) if isinstance(r[0], str) else r[0]
                                        if isinstance(eids, list):
                                            event_ids.extend(eids)
                except Exception as exc:
                    logger.debug("Failed querying incidents table detection_ids: %s", exc)

            event_ids = list(dict.fromkeys(e for e in event_ids if e))
            if not event_ids:
                return IncidentLogsResponse(
                    total=0,
                    counts=SeverityCounts(),
                    items=[],
                    reason="No evidence logs found for incident",
                )

            # 2. Correlate detection rules citing these event IDs
            event_detections: dict[str, list[LogDetectionItem]] = defaultdict(list)
            seen_dets: dict[str, set[tuple[str, str]]] = defaultdict(set)

            if "detection_events" in tables_views and "detections" in tables_views:
                try:
                    det_rows = con.execute(
                        """
                        SELECT de.event_id, d.rule_id, d.rule_name, COALESCE(de.technique_id, d.technique_id, '') AS technique_id, d.severity
                        FROM detection_events de
                        JOIN detections d ON de.detection_id = d.detection_id
                        WHERE de.event_id = ANY(?)
                        """,
                        [event_ids],
                    ).fetchall()
                    for eid, r_id, r_name, t_id, sev in det_rows:
                        key = (r_id or "", t_id or "")
                        if key not in seen_dets[eid]:
                            seen_dets[eid].add(key)
                            event_detections[eid].append(
                                LogDetectionItem(
                                    rule_id=r_id or "",
                                    rule_name=r_name or "",
                                    technique_id=t_id or "",
                                    severity=int(sev or 0),
                                )
                            )
                except Exception as exc:
                    logger.debug("Failed querying detection_events: %s", exc)

            if "detections" in tables_views:
                try:
                    inc_dets = con.execute(
                        "SELECT rule_id, rule_name, technique_id, severity, event_ids FROM detections WHERE incident_id = ?",
                        [id],
                    ).fetchall()
                    for r_id, r_name, t_id, sev, eids_raw in inc_dets:
                        if eids_raw:
                            eids = json.loads(eids_raw) if isinstance(eids_raw, str) else eids_raw
                            if isinstance(eids, list):
                                for eid in eids:
                                    if eid in event_ids:
                                        key = (r_id or "", t_id or "")
                                        if key not in seen_dets[eid]:
                                            seen_dets[eid].add(key)
                                            event_detections[eid].append(
                                                LogDetectionItem(
                                                    rule_id=r_id or "",
                                                    rule_name=r_name or "",
                                                    technique_id=t_id or "",
                                                    severity=int(sev or 0),
                                                )
                                            )
                except Exception as exc:
                    logger.debug("Failed correlating detections table: %s", exc)

            # 3. Fetch event rows from events view/table
            events_cols = {r[1] for r in con.execute("PRAGMA table_info('events')").fetchall()}
            select_cols = ["event_id"]

            if "ts" in events_cols and "timestamp" in events_cols:
                select_cols.append("COALESCE(ts, TRY_CAST(timestamp AS TIMESTAMPTZ)) AS ts")
            elif "ts" in events_cols:
                select_cols.append("ts")
            elif "timestamp" in events_cols:
                select_cols.append("TRY_CAST(timestamp AS TIMESTAMPTZ) AS ts")
            else:
                select_cols.append("NULL AS ts")

            select_cols.append("src_ip" if "src_ip" in events_cols else "NULL AS src_ip")
            select_cols.append("dst_ip" if "dst_ip" in events_cols else "NULL AS dst_ip")
            select_cols.append("dst_port" if "dst_port" in events_cols else "NULL AS dst_port")
            select_cols.append("action" if "action" in events_cols else "NULL AS action")
            select_cols.append("attack" if "attack" in events_cols else "NULL AS attack")

            if "level" in events_cols and "severity" in events_cols:
                select_cols.append("COALESCE(level, severity) AS level")
            elif "level" in events_cols:
                select_cols.append("level")
            elif "severity" in events_cols:
                select_cols.append("severity AS level")
            else:
                select_cols.append("NULL AS level")

            select_cols.append("raw" if "raw" in events_cols else "NULL AS raw")

            order_by = "ORDER BY ts ASC NULLS LAST"
            if "source_offset" in events_cols:
                order_by = "ORDER BY ts ASC NULLS LAST, source_offset ASC NULLS LAST"

            query = f"""
                SELECT {', '.join(select_cols)}
                FROM events
                WHERE event_id = ANY(?)
                {order_by}
            """
            event_rows = con.execute(query, [event_ids]).fetchall()

            if not event_rows:
                return IncidentLogsResponse(
                    total=0,
                    counts=SeverityCounts(),
                    items=[],
                    reason="No evidence logs found for incident",
                )

            # 4. Process items, calculate effective severity, and tabulate counts
            all_items: list[AttackLogItem] = []
            counts = SeverityCounts()

            for row in event_rows:
                eid = str(row[0])
                raw_ts = row[1]
                src_ip = str(row[2]) if row[2] is not None else None
                dst_ip = str(row[3]) if row[3] is not None else None
                dst_port = int(row[4]) if row[4] is not None else None
                action = str(row[5]) if row[5] is not None else None
                attack = str(row[6]) if row[6] is not None else None
                level = str(row[7]) if row[7] is not None else None
                raw = str(row[8]) if row[8] is not None else None

                dets = event_detections.get(eid, [])
                max_det_sev = max((d.severity for d in dets), default=0)
                mapped_lvl_sev = map_level_to_severity(level)
                effective_sev = max(max_det_sev, mapped_lvl_sev)
                sev_label = compute_severity_label(effective_sev)

                if sev_label == "critical":
                    counts.critical += 1
                elif sev_label == "high":
                    counts.high += 1
                elif sev_label == "medium":
                    counts.medium += 1
                elif sev_label == "low":
                    counts.low += 1
                else:
                    counts.info += 1

                all_items.append(
                    AttackLogItem(
                        event_id=eid,
                        ts=raw_ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        action=action,
                        attack=attack,
                        level=level,
                        effective_severity=effective_sev,
                        severity_label=sev_label,
                        detections=dets,
                        raw=raw,
                    )
                )

            # 5. Apply severity filter, limit, and offset
            filtered_items = all_items
            if severity:
                sev_filter = severity.strip().lower()
                filtered_items = [item for item in all_items if item.severity_label == sev_filter]

            total = len(filtered_items)
            paged_items = filtered_items[offset : offset + limit]

            return IncidentLogsResponse(
                total=total,
                counts=counts,
                items=paged_items,
                reason=None,
            )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error retrieving attack logs for incident %s: %s", id, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve attack logs: {exc}",
        )


# Direct router without /incidents prefix for alternate mounting styles
direct_router = APIRouter(tags=["logs"])
direct_router.add_api_route(
    "/api/v1/incidents/{id}/logs",
    get_incident_logs,
    methods=["GET"],
    response_model=IncidentLogsResponse,
    summary="Get attack logs for an incident",
)
direct_router.add_api_route(
    "/incidents/{id}/logs",
    get_incident_logs,
    methods=["GET"],
    response_model=IncidentLogsResponse,
    summary="Get attack logs for an incident",
)
