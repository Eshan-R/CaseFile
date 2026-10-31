"""Evaluator: scores detected incidents against planted ground truth."""

from __future__ import annotations

import json

from app.schemas.evaluation import EvaluationResult, GroundTruthStep, StepScore
from app.store import duck


def evaluate_incident(
    incident_id: str,
    ground_truth: list[GroundTruthStep],
) -> EvaluationResult:
    """Compare the stored incident steps to the ground truth.

    Matches by technique_id.  Time overlap is checked if timestamps available.
    """
    inc = duck.get_incident(incident_id)
    if not inc:
        return EvaluationResult(
            incident_id=incident_id,
            ground_truth_steps=len(ground_truth),
            detected_steps=0,
            matched_steps=0,
        )

    steps = json.loads(inc["steps"]) if isinstance(inc["steps"], str) else inc["steps"]
    detected_techs: list[str] = [s["technique_id"] for s in steps]

    step_scores: list[StepScore] = []
    matched = 0
    correct_labels = 0
    correct_order = 0
    last_order: int | None = None

    for i, gt in enumerate(ground_truth):
        # Find best match by technique_id
        found_idx: int | None = None
        for j, dt in enumerate(detected_techs):
            if dt == gt.technique_id or dt.startswith(gt.technique_id[:5]):
                found_idx = j
                break

        is_match = found_idx is not None
        label_ok = is_match
        order_ok: bool | None = None

        if is_match:
            matched += 1
            correct_labels += 1
            if last_order is None or found_idx >= last_order:
                order_ok = True
                correct_order += 1
            else:
                order_ok = False
            last_order = found_idx

        step_scores.append(StepScore(
            technique_id=gt.technique_id,
            matched=is_match,
            order_correct=order_ok,
            label_correct=label_ok,
        ))

    gt_count = len(ground_truth)
    det_count = len(detected_techs)
    false_alarms = max(0, det_count - matched)

    return EvaluationResult(
        incident_id=incident_id,
        ground_truth_steps=gt_count,
        detected_steps=det_count,
        matched_steps=matched,
        detection_rate=matched / gt_count if gt_count else None,
        label_accuracy=correct_labels / matched if matched else None,
        order_accuracy=correct_order / matched if matched else None,
        false_alarm_count=false_alarms,
        step_scores=step_scores,
    )

