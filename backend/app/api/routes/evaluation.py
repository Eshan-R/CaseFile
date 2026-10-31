"""Evaluation endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException

from app.pipeline.evaluate.evaluator import evaluate_incident, evaluate_manifest
from app.schemas.evaluation import EvaluationRequest, EvaluationResult
from app.store import duck

router = APIRouter(prefix="/evaluate", tags=["evaluation"])


@router.post("/manifest", summary="Score detections against ground-truth manifest")
def evaluate_against_manifest(body: dict) -> dict:
    manifest_path = body.get("manifest_path")
    if not manifest_path:
        raise HTTPException(status_code=422, detail="manifest_path is required")
    log_path = body.get("log_path")
    try:
        return evaluate_manifest(manifest_path, log_file_path=log_path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("", response_model=EvaluationResult, summary="Score an incident against ground truth")
def run_evaluation(body: EvaluationRequest) -> EvaluationResult:
    row = duck.get_incident(body.incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {body.incident_id!r} not found")

    result = evaluate_incident(body.incident_id, body.ground_truth)

    # Persist
    eval_id = duck.new_id("eval")
    duck.insert_evaluation(
        eval_id,
        body.incident_id,
        [g.model_dump() for g in body.ground_truth],
        result.model_dump(),
    )
    return result


@router.get("/{incident_id}", summary="Get stored evaluation results for an incident")
def get_evaluations(incident_id: str) -> dict:
    rows = duck.list_evaluations(incident_id=incident_id)
    results = []
    for r in rows:
        result_data = json.loads(r["result_json"]) if isinstance(r["result_json"], str) else r["result_json"]
        results.append({"eval_id": r["eval_id"], "created_at": r["created_at"], **result_data})
    return {"incident_id": incident_id, "total": len(results), "items": results}

