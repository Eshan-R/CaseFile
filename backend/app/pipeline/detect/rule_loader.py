"""Detection rule loader – reads, validates, and syncs rules/*.yaml files."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.schemas.rule import Rule
from app.store import duck

logger = logging.getLogger(__name__)


class LineLoader(yaml.SafeLoader):
    """PyYAML Loader that annotates mappings with their source line number."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
        mapping = super().construct_mapping(node, deep=deep)
        mapping["__line__"] = node.start_mark.line + 1
        return mapping


def _load_yaml_with_lines(file_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse a YAML file using LineLoader, returning items and syntax errors."""
    errors: list[str] = []
    items: list[dict[str, Any]] = []

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
            if not content.strip():
                return items, errors
            data = yaml.load(content, Loader=LineLoader)
    except yaml.YAMLError as exc:
        line = exc.problem_mark.line + 1 if hasattr(exc, "problem_mark") and exc.problem_mark else 1
        errors.append(f"{file_path}:{line}: YAML parse error: {exc}")
        return items, errors
    except Exception as exc:
        errors.append(f"{file_path}:1: Read error: {exc}")
        return items, errors

    if isinstance(data, list):
        items = [d for d in data if isinstance(d, dict)]
    elif isinstance(data, dict):
        items = [data]

    return items, errors


def _strip_line_metadata(obj: Any) -> Any:
    """Recursively remove __line__ annotations from parsed YAML structures."""
    if isinstance(obj, dict):
        return {k: _strip_line_metadata(v) for k, v in obj.items() if k != "__line__"}
    if isinstance(obj, list):
        return [_strip_line_metadata(x) for x in obj]
    return obj


def validate_rules(rules_dir: str = "rules") -> dict[str, Any]:
    """Validate all YAML files in the rules directory, reporting errors with file and line.

    Returns:
        dict with keys: valid (bool), total_rules (int), errors (list of strings), rules (list of Rule dicts).
    """
    rules_path = Path(rules_dir)
    errors: list[str] = []
    validated_rules: list[Rule] = []

    if not rules_path.exists():
        return {"valid": False, "total_rules": 0, "errors": [f"Rules directory '{rules_dir}' does not exist."], "rules": []}

    for yaml_file in sorted(rules_path.glob("*.yaml")):
        # Skip non-rule YAML files such as assets.yaml and silver_oracles.yaml
        if yaml_file.name in ("assets.yaml", "attack_tactics.yaml", "fortigate_map.yaml", "recommendations.yaml", "silver_oracles.yaml"):
            continue

        raw_items, file_errors = _load_yaml_with_lines(yaml_file)
        errors.extend(file_errors)

        for raw in raw_items:
            line_no = raw.get("__line__", 1)
            # Check mandatory keys
            if "id" not in raw and "rule_id" not in raw:
                errors.append(f"{yaml_file}:{line_no}: Rule is missing required 'id' key.")
                continue

            rule_id = raw.get("id") or raw.get("rule_id")
            clean_raw = _strip_line_metadata(raw)
            try:
                rule = Rule.model_validate(clean_raw)
                validated_rules.append(rule)
            except ValidationError as exc:
                for err in exc.errors():
                    field_name = ".".join(str(loc) for loc in err.get("loc", []))
                    msg = err.get("msg", "Validation error")
                    errors.append(f"{yaml_file}:{line_no}: Rule '{rule_id}' field '{field_name}': {msg}")
            except Exception as exc:
                errors.append(f"{yaml_file}:{line_no}: Rule '{rule_id}' failed validation: {exc}")

    return {
        "valid": len(errors) == 0,
        "total_rules": len(validated_rules),
        "errors": errors,
        "rules": [r.model_dump() for r in validated_rules],
    }


def load_rules(rules_dir: str = "rules", include_disabled: bool = True) -> list[Rule]:
    """Load all rules from rules/*.yaml, validate them, sync to database, and return list."""
    rules_path = Path(rules_dir)
    loaded_rules: list[Rule] = []

    if not rules_path.exists():
        return loaded_rules

    for yaml_file in sorted(rules_path.glob("*.yaml")):
        if yaml_file.name in ("assets.yaml", "attack_tactics.yaml", "fortigate_map.yaml", "recommendations.yaml", "silver_oracles.yaml"):
            continue

        raw_items, errors = _load_yaml_with_lines(yaml_file)
        for err in errors:
            logger.warning(err)

        for raw in raw_items:
            line_no = raw.get("__line__", 1)
            rule_id = raw.get("id") or raw.get("rule_id", "unknown")
            clean_raw = _strip_line_metadata(raw)
            try:
                rule = Rule.model_validate(clean_raw)
                # Sync rule to DuckDB rules table
                rule_dict = {
                    "rule_id": rule.id,
                    "name": rule.name,
                    "description": rule.description,
                    "technique_id": rule.technique_id,
                    "tactic": rule.tactic,
                    "severity": rule.numeric_severity,
                    "log_formats": rule.log_formats,
                    "conditions": [c.model_dump() for c in rule.conditions],
                    "logic": rule.logic,
                    "enabled": rule.enabled,
                }
                duck.upsert_rule(rule_dict)

                if rule.enabled or include_disabled:
                    loaded_rules.append(rule)
            except Exception as exc:
                logger.warning("%s:%d: Failed loading rule '%s': %s", yaml_file, line_no, rule_id, exc)

    return loaded_rules


def get_rule(rule_id: str, rules_dir: str = "rules") -> Rule | None:
    """Find and return a single rule by ID."""
    rules = load_rules(rules_dir=rules_dir, include_disabled=True)
    for r in rules:
        if r.id == rule_id or r.rule_id == rule_id:
            return r
    return None
