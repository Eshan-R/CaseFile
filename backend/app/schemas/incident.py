"""Incident schemas: a cluster of related detections across hosts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AttackStep(BaseModel):
    """One technique in the reconstructed kill chain."""

    step_order: int = Field(description="Position in the kill chain, 1-based.")
    technique_id: str
    tactic: str
    detection_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    hosts: list[str]
    kill_chain_stage: str = ""
    count: int = 1


class Incident(BaseModel):
    """A group of related detections forming a single attack campaign."""

    incident_id: str  # inc_<8hex>
    title: str
    severity: int = Field(ge=1, le=10)
    risk_score: float = 0.0
    first_seen: datetime
    last_seen: datetime
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    src_ips: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)  # ordered kill chain
    steps: list[AttackStep] = Field(default_factory=list)
    detection_ids: list[str] = Field(default_factory=list)
    detection_count: int = 0
    event_count: int = 0
    status: str = "open"  # "open" | "closed" | "alert" | "lead"
    ips_context: list[dict[str, Any]] = Field(default_factory=list)


class IncidentList(BaseModel):
    total: int
    items: list[Incident]

