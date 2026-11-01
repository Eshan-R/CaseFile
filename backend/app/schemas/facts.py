"""Pydantic schemas for deterministic incident facts."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field


class ReachFactTarget(BaseModel):
    """Predictive reach target with observed access reason."""

    target: str
    kind: str = "host"
    hops: int = 1
    priority: str = "medium"
    reason: str = ""


class ReachFacts(BaseModel):
    """Reachability facts summarizing blast radius and potential next movement."""

    seed_hosts: list[str] = Field(default_factory=list)
    hosts_count: int = 0
    users_count: int = 0
    critical_assets: list[str] = Field(default_factory=list)
    reachable_targets: list[ReachFactTarget] = Field(default_factory=list)


class FactStep(BaseModel):
    """Single collapsed attack step within the reconstructed kill chain."""

    step_order: int
    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    kill_chain_stage: str = ""
    first_seen: str
    last_seen: str
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    src_ips: list[str] = Field(default_factory=list)
    occurrence_count: int = 1
    event_count: int = 0
    evidence_event_ids: list[str] = Field(default_factory=list, description="Up to 8 evidence event IDs")


class IncidentFacts(BaseModel):
    """Deterministic, grounded representation of an incident for narrative generation."""

    incident_id: str
    title: str
    severity: int = Field(ge=1, le=10)
    risk_score: float = 0.0
    status: str = "open"
    detection_count: int = 0
    event_count: int = 0
    first_seen: str
    last_seen: str

    known_entities: list[str] = Field(
        default_factory=list,
        description="Comprehensive whitelist of all known IPs, hosts, and usernames involved in this incident",
    )
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    src_ips: list[str] = Field(default_factory=list)

    steps: list[FactStep] = Field(default_factory=list)
    reach: ReachFacts | None = None
    all_event_ids: list[str] = Field(default_factory=list)
    facts_sha256: str = ""

    def compute_sha256(self) -> str:
        """Compute stable SHA-256 hash of the facts (excluding facts_sha256 itself)."""
        data = self.model_dump(exclude={"facts_sha256"})
        # Canonical JSON with sorted keys
        canonical_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def model_post_init(self, __context: Any) -> None:
        if not self.facts_sha256:
            self.facts_sha256 = self.compute_sha256()

