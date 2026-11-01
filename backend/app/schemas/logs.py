"""Pydantic models for incident attack evidence logs."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class LogDetectionItem(BaseModel):
    """Detection rule citation associated with an evidence log."""

    rule_id: str
    rule_name: str
    technique_id: str
    severity: int


class AttackLogItem(BaseModel):
    """Single normalized attack log item for incident evidence drawer and logs view."""

    event_id: str
    ts: datetime | str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    action: str | None = None
    attack: str | None = None
    level: str | None = None
    effective_severity: int = 0
    severity_label: str = "info"  # "critical" | "high" | "medium" | "low" | "info"
    detections: list[LogDetectionItem] = Field(default_factory=list)
    raw: str | None = None


class SeverityCounts(BaseModel):
    """Aggregate counts of logs by effective severity across the incident."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class IncidentLogsResponse(BaseModel):
    """Response payload for GET /api/v1/incidents/{id}/logs."""

    total: int = 0
    counts: SeverityCounts = Field(default_factory=SeverityCounts)
    items: list[AttackLogItem] = Field(default_factory=list)
    reason: str | None = None
