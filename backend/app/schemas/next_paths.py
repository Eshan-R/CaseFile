"""Pydantic models for predictive next paths and lateral reach."""

from __future__ import annotations

from pydantic import BaseModel, Field

DEFAULT_NEXT_PATHS_DISCLAIMER: str = (
    "Based on access observed in the logs; a prediction, not an observation."
)


class NextPathEvidence(BaseModel):
    """Corroborating evidence for a predicted lateral attack path."""

    allowed_connections_observed: int
    last_observed: str | None = None
    asset_criticality: int
    target_already_touched: bool
    tactic_transition_support: bool


class PredictedPathItem(BaseModel):
    """An individual predicted lateral attack step."""

    rank: int
    from_entity: str
    to_entity: str
    service: str
    port: int
    predicted_technique: str
    predicted_tactic: str
    likelihood: float  # 0.0 .. 1.0
    confidence: str    # "low" | "medium" | "high"
    evidence: NextPathEvidence
    monitor_or_block: str


class NextPathsResponse(BaseModel):
    """Response containing deterministic predictive next paths."""

    predicted: bool = True
    disclaimer: str = DEFAULT_NEXT_PATHS_DISCLAIMER
    reason: str | None = None
    paths: list[PredictedPathItem] = Field(default_factory=list)

