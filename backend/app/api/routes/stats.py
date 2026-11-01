"""GET /stats – aggregate statistics about ingested data."""

from __future__ import annotations

from fastapi import APIRouter

from app.store import duck

router = APIRouter(tags=["stats"])


@router.get("/stats", summary="Aggregate pipeline statistics")
def get_stats() -> dict:
    total_events = duck.count_events()
    total_dets, _ = duck.list_detections(limit=0)
    total_incs, _ = duck.list_incidents(limit=0)

    return {
        "total_events": total_events,
        "total_detections": total_dets,
        "total_incidents": total_incs,
        "suppressed_population_windows": duck.count_suppressed_windows(),
        "last_ingest_events": duck.get_stat("last_ingest_events"),
        "last_ingest_malformed": duck.get_stat("last_ingest_malformed"),
    }

