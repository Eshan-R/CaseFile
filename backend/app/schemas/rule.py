"""Detection rule schema (loaded from rules/*.yaml)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RuleCondition(BaseModel):
    field: str
    op: str  # "contains" | "regex" | "eq" | "startswith" | "endswith"
    value: str


class Rule(BaseModel):
    """Detection rule loaded from YAML."""

    rule_id: str
    name: str
    description: str = ""
    technique_id: str  # ATT&CK, e.g. T1078
    tactic: str  # ATT&CK tactic
    severity: int = Field(ge=1, le=10, default=5)
    log_formats: list[str] = Field(default_factory=list)  # empty = all formats
    conditions: list[RuleCondition] = Field(default_factory=list)
    logic: str = Field(default="all", description='"all" (AND) or "any" (OR)')
    enabled: bool = True


class RuleList(BaseModel):
    total: int
    items: list[Rule]

