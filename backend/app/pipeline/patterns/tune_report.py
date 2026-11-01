"""False Alarm Tuning Advisor for Discovered Rule Candidates."""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any

from app.pipeline.patterns.rule_gen import dry_run_rule, pattern_to_rule_candidate
from app.schemas.rule import Rule
from app.store import duck

if TYPE_CHECKING:
    import duckdb

logger = logging.getLogger(__name__)


def generate_tuning_report(
    candidate_rules: list[Rule] | None = None,
    con: duckdb.DuckDBPyConnection | None = None,
    output_path: str = "data/tune_report.json",
) -> dict[str, Any]:
    """Evaluate candidate rules against the current dataset and produce tuning recommendations."""
    if candidate_rules is None:
        # Load from patterns in database
        _, patterns = duck.list_patterns(limit=None)
        candidate_rules = []
        for p in patterns:
            rule = pattern_to_rule_candidate(p)
            if rule:
                candidate_rules.append(rule)

    report_items: list[dict[str, Any]] = []
    total_evaluated = len(candidate_rules)
    safe_count = 0
    noisy_count = 0
    dormant_count = 0

    def _evaluate(active_con: duckdb.DuckDBPyConnection):
        nonlocal safe_count, noisy_count, dormant_count
        for rule in candidate_rules:
            res = dry_run_rule(rule, active_con)
            matches = res["match_count"]
            passed = res["passed"]

            if not passed:
                recommendation = "Reject or increase threshold (triggers noise guard)"
                status = "noisy"
                noisy_count += 1
            elif matches == 0:
                recommendation = "Dormant on current dataset: verify conditions or hold in draft"
                status = "dormant"
                dormant_count += 1
            else:
                recommendation = "Safe: optimal selectivity and bounded firing rate"
                status = "safe"
                safe_count += 1

            report_items.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "rule_type": rule.type,
                "technique_id": rule.technique_id,
                "tactic": rule.tactic,
                "dataset_matches": matches,
                "status": status,
                "noise_guard_passed": passed,
                "recommendation": recommendation,
                "reason": res["reason"],
            })

    if con is not None:
        _evaluate(con)
    else:
        with duck.cursor() as cur:
            _evaluate(cur)

    summary = {
        "total_rules_evaluated": total_evaluated,
        "safe_rules": safe_count,
        "noisy_rules": noisy_count,
        "dormant_rules": dormant_count,
        "rules": report_items,
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return summary

