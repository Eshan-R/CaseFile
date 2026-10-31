"""Detection engine: applies rules to ingested events and stores detections."""

from __future__ import annotations

import re
from typing import Any

from app.schemas.rule import Rule, RuleCondition
from app.store import duck


def _match_condition(cond: RuleCondition, event: dict) -> bool:
    """Test one condition against the event dict."""
    value = event.get(cond.field, "") or ""
    value = str(value)
    test = cond.value

    match cond.op:
        case "eq":
            return value == test
        case "contains":
            return test.lower() in value.lower()
        case "startswith":
            return value.lower().startswith(test.lower())
        case "endswith":
            return value.lower().endswith(test.lower())
        case "regex":
            try:
                return bool(re.search(test, value, re.IGNORECASE))
            except re.error:
                return False
        case _:
            return False


def _rule_matches(rule: Rule, event: dict) -> bool:
    """Return True if the rule fires on this event."""
    if not rule.enabled:
        return False
    if rule.log_formats and event.get("log_format") not in rule.log_formats:
        return False
    if not rule.conditions:
        return False

    results = [_match_condition(c, event) for c in rule.conditions]
    if rule.logic == "any":
        return any(results)
    return all(results)


def run_detection(
    rules: list[Rule],
    job_id: str,
    batch_size: int = 5_000,
) -> dict[str, Any]:
    """Scan all events in DuckDB, fire rules, write detections back.

    Processes in batches so memory stays bounded.
    Returns a result summary.
    """
    total_detections = 0
    offset = 0

    while True:
        _, batch = duck.list_events(offset=offset, limit=batch_size)
        if not batch:
            break

        for event in batch:
            for rule in rules:
                if _rule_matches(rule, event):
                    det_id = duck.new_id("det")
                    duck.insert_detection({
                        "detection_id": det_id,
                        "rule_id": rule.rule_id,
                        "rule_name": rule.name,
                        "technique_id": rule.technique_id,
                        "tactic": rule.tactic,
                        "severity": rule.severity,
                        "host": event["host"],
                        "ts": event["ts"],
                        "event_ids": [event["event_id"]],
                    })
                    # Tag the event row
                    with duck.cursor() as con:
                        con.execute(
                            "UPDATE events SET detection_id=?, technique_id=?, tactic=? "
                            "WHERE event_id=?",
                            [det_id, rule.technique_id, rule.tactic, event["event_id"]],
                        )
                    total_detections += 1
                    break  # one detection per event (first matching rule wins)

        offset += batch_size
        duck.update_job(job_id, progress_pct=min(99, offset / (offset + batch_size) * 100))

    return {"total_detections": total_detections}

