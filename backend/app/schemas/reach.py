"""Pydantic schemas for reachability analysis and predictive attack paths."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

DEFAULT_DISCLAIMER: str = (
    "DISCLAIMER: Predicted attack paths and reachability estimates are probabilistic risk assessments "
    "based on observed network access topology. They represent potential lateral movement vectors, "
    "not confirmed active compromises."
)


class ReachableTarget(BaseModel):
    """An individual entity reachable by the attacker."""

    target_id: str
    target_label: str
    target_kind: str = "host"  # "host" | "user"
    hops: int
    reason: str
    priority: str  # "critical" | "high" | "medium" | "low"
    evidence_event_ids: list[str] = Field(default_factory=list)
    score: float | None = None
    is_critical: bool = False


class PredictedPath(BaseModel):
    """A scored loop-free attack path from a compromised foothold to a target."""

    node_ids: list[str]
    edge_ids: list[str]
    hops: int
    score: float
    target_label: str
    target_criticality: str  # "critical" | "high" | "standard"
    reasons: list[str] = Field(default_factory=list)


class BlastRadius(BaseModel):
    """Aggregate reachability statistics within max hops."""

    hosts_count: int = 0
    users_count: int = 0
    total_nodes: int = 0
    critical_assets_reached: list[str] = Field(default_factory=list)


class NextReach(BaseModel):
    """Full precomputed next-reach response for an incident."""

    incident_id: str
    compromised_nodes: list[str] = Field(default_factory=list)
    blast_radius: BlastRadius = Field(default_factory=BlastRadius)
    predicted_paths: list[PredictedPath] = Field(default_factory=list)
    reachable_targets: list[ReachableTarget] = Field(default_factory=list)
    engine: str = "networkx"
    disclaimer: str = DEFAULT_DISCLAIMER
    computed_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    message: str | None = None
