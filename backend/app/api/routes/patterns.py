"""API routes for unsupervised pattern discovery and threat catalog."""

from __future__ import annotations

import logging
import os
import threading

from fastapi import APIRouter, Body, HTTPException, Query
from fastapi.responses import FileResponse

from app.pipeline.patterns.exporter import (
    export_iocs_csv,
    export_patterns_json,
    export_patterns_yaml,
)
from app.pipeline.patterns.runner import run_pattern_mining
from app.pipeline.patterns.tune_report import generate_tuning_report
from app.schemas.pattern import PatternListResponse, PatternRecord
from app.store import duck

# DuckDB compatibility aliases
if not hasattr(duck, "create_job") and hasattr(duck, "insert_job"):
    duck.create_job = duck.insert_job
if not hasattr(duck, "get_connection") and hasattr(duck, "_get_conn"):
    duck.get_connection = duck._get_conn

logger = logging.getLogger(__name__)

router = APIRouter()


def _run_mine_job(job_id: str, params: dict | None = None) -> None:
    params = params or {}
    min_score = float(params.get("min_score", 3.0))
    max_patterns = int(params.get("max_patterns", 200))
    try:
        duck.update_job(job_id, status="running", started_at=duck.utc_now(), progress_pct=10.0)
        try:
            duck.ensure_events_view()
        except Exception:
            pass
        patterns, timings = run_pattern_mining(min_score=min_score, max_patterns=max_patterns)
        duck.update_job(job_id, progress_pct=70.0)
        duck.save_patterns_batch(patterns)
        try:
            export_patterns_json(patterns)
            export_patterns_yaml(patterns)
            export_iocs_csv(patterns)
            generate_tuning_report()
        except Exception as export_err:
            logger.warning("Pattern export/tuning report in job %s: %s", job_id, export_err)
        import json
        duck.update_job(
            job_id,
            status="completed",
            progress_pct=100.0,
            finished_at=duck.utc_now(),
            result=json.dumps({"patterns_mined": len(patterns), "timings": timings}),
        )
    except Exception as exc:
        logger.exception("Pattern mining background job %s failed: %s", job_id, exc)
        duck.update_job(
            job_id,
            status="failed",
            error=str(exc),
            finished_at=duck.utc_now(),
        )


# ---------------------------------------------------------------------------
# Background Mining Trigger Endpoint
# ---------------------------------------------------------------------------

@router.post("/mine", status_code=202, summary="Trigger automated pattern discovery job")
def start_pattern_mining_job(body: dict | None = Body(default=None)) -> dict:
    """Trigger automated pattern discovery in a background job via the existing jobs framework.
    
    Returns JSON {"job_id": job_id} with status 202.
    Client can check progress via existing GET /api/v1/jobs/{id}.
    """
    params = body or {}
    job_id = duck.new_id("job_mine")
    create_fn = getattr(duck, "create_job", getattr(duck, "insert_job", None))
    create_fn(job_id, "mine", params)
    
    t = threading.Thread(
        target=_run_mine_job,
        args=(job_id, params),
        daemon=True,
    )
    t.start()
    return {"job_id": job_id, "status": "queued"}


# ---------------------------------------------------------------------------
# Export Endpoints (Registered BEFORE /{pattern_id} to avoid collision)
# ---------------------------------------------------------------------------

@router.get("/export/json")
def export_json():
    """Download discovered patterns in JSON format."""
    path = os.path.abspath("data/patterns.json")
    export_patterns_json(output_path=path)
    return FileResponse(path, media_type="application/json", filename="patterns.json")


@router.get("/export/yaml")
def export_yaml():
    """Download discovered patterns in YAML format."""
    path = os.path.abspath("data/patterns.yaml")
    export_patterns_yaml(output_path=path)
    return FileResponse(path, media_type="application/x-yaml", filename="patterns.yaml")


@router.get("/export/iocs")
def export_iocs():
    """Download extracted indicators of compromise (IOCs) in CSV format."""
    path = os.path.abspath("data/iocs.csv")
    export_iocs_csv(output_path=path)
    return FileResponse(path, media_type="text/csv", filename="iocs.csv")


# ---------------------------------------------------------------------------
# Pattern Catalog & Management Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=PatternListResponse)
def list_patterns(
    status: str | None = Query(None, description="Filter by status: new, approved, rejected"),
    kind: str | None = Query(None, description="Filter by miner kind: burst, rarity, novel_edges, sequence, coordinated"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List discovered patterns with filtering and pagination."""
    total, items = duck.list_patterns(status=status, kind=kind, limit=limit, offset=offset)
    return {"total": total, "items": items}


@router.get("/{pattern_id}", response_model=PatternRecord)
def get_pattern(pattern_id: str):
    """Retrieve detailed metadata for a specific pattern."""
    p = duck.get_pattern(pattern_id)
    if not p:
        raise HTTPException(status_code=404, detail="Pattern not found")
    return p


@router.post("/{pattern_id}/approve")
def approve_pattern(pattern_id: str):
    """Mark a pattern as approved by the security analyst."""
    p = duck.get_pattern(pattern_id)
    if not p:
        raise HTTPException(status_code=404, detail="Pattern not found")
    duck.update_pattern_status(pattern_id, "approved")
    return {"status": "success", "pattern_id": pattern_id, "approval_status": "approved"}


@router.post("/{pattern_id}/reject")
def reject_pattern(pattern_id: str):
    """Mark a pattern as rejected (false alarm or irrelevant)."""
    p = duck.get_pattern(pattern_id)
    if not p:
        raise HTTPException(status_code=404, detail="Pattern not found")
    duck.update_pattern_status(pattern_id, "rejected")
    return {"status": "success", "pattern_id": pattern_id, "approval_status": "rejected"}
