"""Detection query endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query

from app.schemas.detection import Detection, DetectionList
from app.store import duck

router = APIRouter(prefix="/detections", tags=["detections"])


def _row_to_detection(row: dict) -> Detection:
    return Detection(
        detection_id=row["detection_id"],
        rule_id=row["rule_id"],
        rule_name=row["rule_name"],
        technique_id=row["technique_id"],
        tactic=row["tactic"],
        severity=row["severity"],
        host=row["host"],
        ts=row["ts"],
        event_ids=json.loads(row["event_ids"]) if isinstance(row["event_ids"], str) else row["event_ids"],
        incident_id=row.get("incident_id"),
    )


@router.get("", response_model=DetectionList, summary="List detections")
def list_detections(
    incident_id: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> DetectionList:
    total, rows = duck.list_detections(incident_id=incident_id, offset=offset, limit=limit)
    return DetectionList(total=total, items=[_row_to_detection(r) for r in rows])


@router.get("/{detection_id}", response_model=Detection, summary="Get one detection")
def get_detection(detection_id: str) -> Detection:
    row = duck.get_detection(detection_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Detection {detection_id!r} not found")
    return _row_to_detection(row)

