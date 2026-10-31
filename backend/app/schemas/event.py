"""Normalised event schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class Event(BaseModel):
    """One normalised log event. Stored in DuckDB; IDs are ev_<fileindex>_<byteoffset>."""

    event_id: str = Field(description="ev_<fileindex>_<byteoffset>")
    ts: datetime = Field(description="Event timestamp UTC.")
    host: str
    source_file: str = Field(description="Originating log file path.")
    log_format: str = Field(description="e.g. syslog, evtx, cef, json, csv")
    raw: str = Field(description="Original log line, unmodified.")
    # Parsed fields (all optional – filled by parser)
    user: str | None = None
    pid: int | None = None
    ppid: int | None = None
    process_name: str | None = None
    cmd: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    file_path: str | None = None
    # Enrichment (filled by detection engine)
    technique_id: str | None = None  # e.g. T1053.005
    tactic: str | None = None  # e.g. Persistence
    rule_ids: list[str] = Field(default_factory=list)
    detection_id: str | None = None
    incident_id: str | None = None


class EventList(BaseModel):
    total: int
    items: list[Event]

