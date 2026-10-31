"""Graph schemas for the Cytoscape.js frontend."""

from __future__ import annotations

from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str  # "host" | "user" | "ip" | "technique" | "process"
    data: dict = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    data: dict = Field(default_factory=dict)


class IncidentGraph(BaseModel):
    """Full entity + attack path graph for one incident."""

    incident_id: str
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class ReachNode(BaseModel):
    """A node the attacker could reach from the current foothold."""

    entity: str
    entity_kind: str
    technique_id: str | None = None
    tactic: str | None = None
    recommendation: str | None = None


class ReachResponse(BaseModel):
    incident_id: str
    seed_hosts: list[str]
    reachable: list[ReachNode] = Field(default_factory=list)


# Re-export NextReach schemas
from app.schemas.reach import (  # noqa: E402
    DEFAULT_DISCLAIMER,
    BlastRadius,
    NextReach,
    PredictedPath,
    ReachableTarget,
)

__all__ = [
    "DEFAULT_DISCLAIMER",
    "BlastRadius",
    "GraphEdge",
    "GraphNode",
    "IncidentGraph",
    "NextReach",
    "PredictedPath",
    "ReachNode",
    "ReachResponse",
    "ReachableTarget",
]


