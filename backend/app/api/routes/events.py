"""Event query endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query

from app.schemas.event import Event, EventList
from app.store import duck

router = APIRouter(prefix="/events", tags=["events"])


def _parse_rule_ids(val):
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return []
    return []


def _row_to_event(row: dict) -> Event:
    return Event(
        event_id=row["event_id"],
        ts=row["ts"],
        host=row["host"],
        source_file=row["source_file"],
        log_format=row["log_format"],
        raw=row["raw"],
        user=row.get("user_name"),
        pid=row.get("pid"),
        ppid=row.get("ppid"),
        process_name=row.get("process_name"),
        cmd=row.get("cmd"),
        src_ip=row.get("src_ip"),
        dst_ip=row.get("dst_ip"),
        dst_port=row.get("dst_port"),
        file_path=row.get("file_path"),
        technique_id=row.get("technique_id"),
        tactic=row.get("tactic"),
        rule_ids=_parse_rule_ids(row.get("rule_ids")),
        detection_id=row.get("detection_id"),
        incident_id=row.get("incident_id"),
    )


@router.get("", response_model=EventList, summary="List events with optional filters")
def list_events(
    incident_id: str | None = Query(None),
    detection_id: str | None = Query(None),
    host: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> EventList:
    total, rows = duck.list_events(
        incident_id=incident_id,
        detection_id=detection_id,
        host=host,
        offset=offset,
        limit=limit,
    )
    return EventList(total=total, items=[_row_to_event(r) for r in rows])


@router.get("/{event_id}", response_model=Event, summary="Get one event by ID")
def get_event(event_id: str) -> Event:
    row = duck.get_event(event_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Event {event_id!r} not found")
    return _row_to_event(row)

