"""Pydantic schemas for discovered patterns and threat indicators."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PatternRecord(BaseModel):
    """Schema representing an unsupervised threat pattern record."""

    pattern_id: str
    kind: str
    title: str
    support: int
    score: float
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    entities: list[str] = Field(default_factory=list)
    example_event_ids: list[str] = Field(default_factory=list)
    suggested_technique: str | None = None
    suggested_tactic: str | None = None
    status: str = "new"
    details_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


class PatternListResponse(BaseModel):
    """Paginated list of discovered patterns."""

    total: int
    items: list[PatternRecord]


class PatternStatusUpdate(BaseModel):
    """Request payload to update approval status."""

    status: str = Field(description="'approved', 'rejected', or 'new'")


class IOCRecord(BaseModel):
    """Extracted threat indicator of compromise (IOC)."""

    ioc_type: str
    ioc_value: str
    count: int
    first_seen: datetime | str | None = None
    last_seen: datetime | str | None = None
    source_patterns: list[str] = Field(default_factory=list)
    suggested_technique: str | None = None

