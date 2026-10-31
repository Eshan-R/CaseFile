"""Detection schemas: one alert raised when a rule matches."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class Detection(BaseModel):
    """An alert raised when a rule fires on one or more events."""

    detection_id: str  # det_<8hex>
    rule_id: str
    rule_name: str
    technique_id: str
    tactic: str
    severity: int
    host: str
    ts: datetime = Field(description="Timestamp of the triggering event (UTC).")
    event_ids: list[str] = Field(description="Event IDs that triggered this detection.")
    incident_id: str | None = None


class DetectionList(BaseModel):
    total: int
    items: list[Detection]

