"""Ingest runner: streams log files and stores events in DuckDB."""

from __future__ import annotations

import os
from typing import Any

from app.pipeline.ingest.chunker import stream_events
from app.store import duck


def run_ingest(
    job_id: str,
    paths: list[str],
    chunk_size: int = 50_000,
) -> dict[str, Any]:
    """Ingest all given file paths.  Updates the job row with progress.

    Returns a result summary dict.
    """
    total_events = 0
    total_malformed = 0
    total_lines = 0
    files_done = 0

    for file_index, path in enumerate(paths):
        if not os.path.exists(path):
            continue
        for chunk, malformed, lines in stream_events(path, file_index, chunk_size):
            duck.insert_events_batch(chunk)
            total_events += len(chunk)
            total_malformed += malformed
            total_lines += lines
            progress = (files_done / len(paths) * 100) if len(paths) else 100
            duck.update_job(job_id, progress_pct=progress)
        files_done += 1
        duck.update_job(job_id, progress_pct=files_done / len(paths) * 100)

    result = {
        "files_ingested": files_done,
        "total_events": total_events,
        "total_lines": total_lines,
        "malformed_lines": total_malformed,
    }
    duck.set_stat("last_ingest_events", str(total_events))
    duck.set_stat("last_ingest_malformed", str(total_malformed))
    return result

