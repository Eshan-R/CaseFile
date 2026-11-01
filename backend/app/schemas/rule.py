"""Detection rule schema (loaded from rules/*.yaml)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator


class TechniqueRef(BaseModel):
    """ATT&CK Technique reference."""

    id: str
    name: str = ""


class RuleCondition(BaseModel):
    """Single condition expression."""

    field: str
    op: str = "eq"  # "eq" | "equals" | "in" | "contains" | "regex" | "gt" | "lt"
    value: Any


class Rule(BaseModel):
    """Detection rule loaded from YAML."""

    id: str = ""
    name: str
    description: str = ""
    type: str = "match"  # "match" | "threshold" | "sequence" | "sql"
    sql_file: str | None = None
    sql: str | None = None
    technique: TechniqueRef | dict[str, Any] | str = ""
    tactic: str = ""
    kill_chain_stage: str = ""
    severity: str | int = "medium"
    confidence: float = 0.8
    enabled: bool = True
    superseded_by: str | None = None
    high_fidelity: bool = False
    applies_to: list[str] = Field(default_factory=lambda: ["firewall_kv", "fortigate_kv"])
    suppressed_count: int = 0
    background: bool = False
    prevalence_k: int = 0
    prevalence_share: float = 0.0
    prevalence_entropy: float = 0.0
    prevalence_decision: str = "ACTIVE"

    # Match / Where expressions
    where: dict[str, Any] | list[Any] | None = None
    conditions: list[RuleCondition] = Field(default_factory=list)
    logic: str = Field(default="all", description='"all" (AND) or "any" (OR)')

    # Threshold & Sequence options
    group_by: list[str] = Field(default_factory=list)
    window_seconds: int = 600
    min_count: int = 1
    min_distinct_field: str | None = None  # Field for COUNT(DISTINCT ...) in HAVING clause
    min_distinct: int | None = None  # Minimum distinct count required
    then: dict[str, Any] | None = None
    steps: list[dict[str, Any]] = Field(default_factory=list)

    # Exclusions
    exclude: dict[str, Any] = Field(default_factory=dict)
    log_formats: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def normalize_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        # Handle rule_id alias
        if "id" not in data and "rule_id" in data:
            data["id"] = data["rule_id"]
        elif "rule_id" not in data and "id" in data:
            data["rule_id"] = data["id"]

        # Handle technique if given as technique_id
        if "technique" not in data and "technique_id" in data:
            data["technique"] = {"id": data["technique_id"], "name": ""}
        elif isinstance(data.get("technique"), str):
            data["technique"] = {"id": data["technique"], "name": ""}

        if "applies_to" in data:
            if isinstance(data["applies_to"], str):
                data["applies_to"] = [data["applies_to"]]
            elif isinstance(data["applies_to"], list):
                data["applies_to"] = [str(x) for x in data["applies_to"]]

        return data

    @property
    def rule_id(self) -> str:
        return self.id

    @property
    def technique_id(self) -> str:
        if isinstance(self.technique, TechniqueRef):
            return self.technique.id
        if isinstance(self.technique, dict):
            return str(self.technique.get("id", ""))
        return str(self.technique)

    @property
    def technique_name(self) -> str:
        if isinstance(self.technique, TechniqueRef):
            return self.technique.name
        if isinstance(self.technique, dict):
            return str(self.technique.get("name", ""))
        return ""

    @property
    def numeric_severity(self) -> int:
        if isinstance(self.severity, int):
            return max(1, min(10, self.severity))
        sev_map = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "info": 1,
        }
        return sev_map.get(str(self.severity).lower(), 5)


class RuleList(BaseModel):
    total: int
    items: list[Rule]
