"""Evaluation schemas: scoring detected incidents vs planted ground truth."""

from __future__ import annotations

from pydantic import BaseModel, Field


class GroundTruthStep(BaseModel):
    technique_id: str
    tactic: str
    host: str
    ts_start: str  # ISO 8601 UTC
    ts_end: str


class EvaluationRequest(BaseModel):
    incident_id: str
    ground_truth: list[GroundTruthStep]


class StepScore(BaseModel):
    technique_id: str
    matched: bool
    order_correct: bool | None = None
    label_correct: bool | None = None


class EvaluationResult(BaseModel):
    incident_id: str
    ground_truth_steps: int
    detected_steps: int
    matched_steps: int
    detection_rate: float | None = None     # null if no ground truth
    label_accuracy: float | None = None
    order_accuracy: float | None = None
    false_alarm_count: int = 0
    step_scores: list[StepScore] = Field(default_factory=list)

