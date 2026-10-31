"""Job schemas: ingest / analyse pipeline jobs."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class JobStatus(StrEnum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"


class JobKind(StrEnum):
    ingest = "ingest"
    analyse = "analyse"
    evaluate = "evaluate"


class JobCreate(BaseModel):
    kind: JobKind
    params: dict = Field(default_factory=dict)


class Job(BaseModel):
    job_id: str  # job_<8hex>
    kind: JobKind
    status: JobStatus = JobStatus.queued
    params: dict = Field(default_factory=dict)
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    progress_pct: float | None = None  # 0-100; null if unknown
    error: str | None = None
    result: dict | None = None  # job-kind-specific summary


class JobList(BaseModel):
    total: int
    items: list[Job]

