"""Pipeline orchestrator: runs ingest → detect → link as a single job."""

from __future__ import annotations

import threading

from app.pipeline.detect import engine as detect_engine
from app.pipeline.detect.rule_loader import load_rules
from app.pipeline.ingest.runner import run_ingest
from app.pipeline.link.incidents import build_incidents
from app.store import duck


def _run_analyse_job(job_id: str) -> None:
    """Background thread: run detection + incident linking on ingested data."""
    try:
        duck.update_job(job_id, status="running")
        rules = load_rules()
        det_result = detect_engine.run_detection(rules, job_id)
        inc_result = build_incidents()
        duck.update_job(
            job_id,
            status="done",
            progress_pct=100.0,
            result={**det_result, **inc_result},
        )
    except Exception as exc:
        duck.update_job(job_id, status="failed", error=str(exc))


def _run_ingest_job(
    job_id: str,
    paths: list[str],
    chunk_size: int = 64 * 1024 * 1024,
    workers: int | None = None,
    resume: bool = False,
    skip_bad: bool = False,
    limit_bytes: int | None = None,
) -> None:
    """Background thread: stream logs into DuckDB."""
    try:
        duck.update_job(job_id, status="running")
        result = run_ingest(
            job_id,
            paths,
            chunk_size=chunk_size,
            workers=workers,
            resume=resume,
            skip_bad=skip_bad,
            limit_bytes=limit_bytes,
        )
        duck.update_job(job_id, status="done", progress_pct=100.0, result=result)
    except Exception as exc:
        duck.update_job(job_id, status="failed", error=str(exc))


def start_ingest_job(
    paths: list[str],
    chunk_size: int = 64 * 1024 * 1024,
    workers: int | None = None,
    resume: bool = False,
    skip_bad: bool = False,
    limit_bytes: int | None = None,
) -> str:
    """Create and enqueue an ingest job.  Returns job_id."""
    job_id = duck.new_id("job")
    duck.insert_job(
        job_id,
        "ingest",
        {
            "paths": paths,
            "chunk_size": chunk_size,
            "workers": workers,
            "resume": resume,
            "skip_bad": skip_bad,
            "limit_bytes": limit_bytes,
        },
    )
    t = threading.Thread(
        target=_run_ingest_job,
        args=(job_id, paths, chunk_size, workers, resume, skip_bad, limit_bytes),
        daemon=True,
    )
    t.start()
    return job_id


def start_analyse_job() -> str:
    """Create and enqueue a detect+link job.  Returns job_id."""
    job_id = duck.new_id("job")
    duck.insert_job(job_id, "analyse", {})
    t = threading.Thread(target=_run_analyse_job, args=(job_id,), daemon=True)
    t.start()
    return job_id

