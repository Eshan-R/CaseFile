"""Rules management endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter

from app.pipeline.detect.rule_loader import load_rules
from app.schemas.rule import Rule, RuleList
from app.store import duck

router = APIRouter(prefix="/rules", tags=["rules"])


def _row_to_rule(row: dict) -> Rule:
    from app.schemas.rule import RuleCondition
    conditions_raw = json.loads(row["conditions"]) if isinstance(row["conditions"], str) else row["conditions"]
    return Rule(
        rule_id=row["rule_id"],
        name=row["name"],
        description=row.get("description", ""),
        technique_id=row["technique_id"],
        tactic=row["tactic"],
        severity=row["severity"],
        log_formats=json.loads(row["log_formats"]) if isinstance(row["log_formats"], str) else row["log_formats"],
        conditions=[RuleCondition(**c) for c in conditions_raw],
        logic=row.get("logic", "all"),
        enabled=row.get("enabled", True),
    )


@router.get("", response_model=RuleList, summary="List all loaded rules")
def list_rules() -> RuleList:
    rows = duck.list_rules()
    items = [_row_to_rule(r) for r in rows]
    return RuleList(total=len(items), items=items)


@router.post("/reload", summary="Reload rules from rules/ directory")
def reload_rules() -> dict:
    rules = load_rules()
    return {"rules_loaded": len(rules)}

