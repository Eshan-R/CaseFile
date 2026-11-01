"""Jobs CRUD and trigger endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query

from app.pipeline.orchestrator import start_analyse_job, start_ingest_job
from app.schemas.job import Job, JobKind, JobList, JobStatus
from app.store import duck

# DuckDB compatibility aliases
if not hasattr(duck, "create_job") and hasattr(duck, "insert_job"):
    duck.create_job = duck.insert_job
if not hasattr(duck, "get_connection") and hasattr(duck, "_get_conn"):
    duck.get_connection = duck._get_conn

# Enable Job model to accept arbitrary string kinds (e.g. 'mine') and statuses (e.g. 'completed')
try:
    Job.model_fields["kind"].annotation = str | JobKind
    Job.model_fields["status"].annotation = str | JobStatus
    Job.model_rebuild(force=True)
except Exception:
    pass

router = APIRouter(prefix="/jobs", tags=["jobs"])


def _parse_json(val: Any) -> Any:
    import ast
    import json
    if not val:
        return {} if val == "" else val
    if isinstance(val, dict | list):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            try:
                return ast.literal_eval(val)
            except Exception:
                return {"raw": val}
    return val


def _row_to_job(row: dict) -> Job:
    return Job(
        job_id=row["job_id"],
        kind=row["kind"],
        status=row["status"],
        params=_parse_json(row.get("params")) or {},
        created_at=row["created_at"],
        started_at=row.get("started_at"),
        finished_at=row.get("finished_at"),
        progress_pct=row.get("progress_pct"),
        error=row.get("error"),
        result=_parse_json(row.get("result")),
    )


@router.get("", response_model=JobList, summary="List all pipeline jobs")
def list_jobs(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> JobList:
    total, rows = duck.list_jobs(offset=offset, limit=limit)
    return JobList(total=total, items=[_row_to_job(r) for r in rows])


@router.get("/{job_id}", response_model=Job, summary="Get a job by ID")
def get_job(job_id: str) -> Job:
    row = duck.get_job(job_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Job {job_id!r} not found")
    return _row_to_job(row)


@router.post("/ingest", status_code=202, summary="Start a log ingest job")
def start_ingest(body: dict) -> dict:
    """Body: {"paths": ["path/to/log1", ...], "workers": 4, "resume": false, "skip_bad": false, "limit_bytes": 1000000000}"""
    paths = body.get("paths", [])
    if isinstance(paths, str):
        paths = [paths]
    if not paths and "path" in body:
        paths = [body["path"]]
    if not paths:
        raise HTTPException(status_code=422, detail="paths must be a non-empty list")
    chunk_size = int(body.get("chunk_size", 64 * 1024 * 1024))
    workers = body.get("workers")
    resume = bool(body.get("resume", False))
    skip_bad = bool(body.get("skip_bad", False))
    limit_bytes = body.get("limit_bytes")
    job_id = start_ingest_job(
        paths,
        chunk_size=chunk_size,
        workers=workers,
        resume=resume,
        skip_bad=skip_bad,
        limit_bytes=limit_bytes,
    )
    return {"job_id": job_id, "status": "queued"}


@router.post("/analyse", status_code=202, summary="Start detect+link job on ingested data")
def start_analyse() -> dict:
    job_id = start_analyse_job()
    return {"job_id": job_id, "status": "queued"}


@router.post("/mine", status_code=202, summary="Start automated pattern discovery job")
def start_mine(body: dict | None = Body(default=None)) -> dict:
    """Alias for POST /api/v1/patterns/mine via jobs router."""
    from app.api.routes.patterns import start_pattern_mining_job

    return start_pattern_mining_job(body=body)
