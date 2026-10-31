"""Detection rule loader – reads *.yaml files from the rules/ directory."""

from __future__ import annotations

from pathlib import Path

import yaml

from app.schemas.rule import Rule, RuleCondition
from app.store import duck


def load_rules(rules_dir: str = "rules") -> list[Rule]:
    """Load all enabled rules from YAML files and sync to DB.

    Returns the list of Rule objects.
    """
    rules: list[Rule] = []
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        return rules

    for yaml_file in sorted(rules_path.glob("*.yaml")):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            continue

        if not isinstance(data, list):
            data = [data]

        for raw in data:
            if not isinstance(raw, dict):
                continue
            try:
                conditions = [
                    RuleCondition(**c)
                    for c in raw.get("conditions", [])
                ]
                rule = Rule(
                    rule_id=str(raw["rule_id"]),
                    name=raw["name"],
                    description=raw.get("description", ""),
                    technique_id=raw["technique_id"],
                    tactic=raw["tactic"],
                    severity=int(raw.get("severity", 5)),
                    log_formats=raw.get("log_formats", []),
                    conditions=conditions,
                    logic=raw.get("logic", "all"),
                    enabled=raw.get("enabled", True),
                )
                rules.append(rule)
                duck.upsert_rule(rule.model_dump())
            except Exception:
                continue

    return rules

