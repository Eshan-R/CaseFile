"""Pydantic schemas for AI-written and template attack stories."""

from __future__ import annotations

from pydantic import BaseModel, Field


class StoryAction(BaseModel):
    """Recommended containment or remediation action."""

    priority: int = Field(ge=1, le=5, description="1 is highest urgency, 5 is lowest")
    action: str = Field(description="Action key, must match knowledge/response_actions.yaml")
    target: str = Field(description="Target host, IP, or username")
    rationale: str = Field(description="Operational justification for the action")
    command: str = Field(default="", description="Non-executable CLI/EDR command example for clipboard copy")


class StoryStep(BaseModel):
    """Narrative description and structured telemetry for a single attack step."""

    step_order: int
    technique_id: str
    technique_name: str
    tactic: str
    headline: str
    narrative: str
    cited_event_ids: list[str] = Field(default_factory=list, description="Exact event IDs from facts")
    entities_mentioned: list[str] = Field(
        default_factory=list, description="Hosts, users, or IPs directly mentioned in narrative"
    )
    event_count: int = Field(default=1, description="Event count matching step facts")
    first_seen: str = Field(default="", description="First seen timestamp matching step facts")
    last_seen: str = Field(default="", description="Last seen timestamp matching step facts")


class AttackStory(BaseModel):
    """Complete analyst-grade incident narrative and containment recommendations."""

    incident_id: str
    headline: str = Field(description="High-level incident headline, e.g. 'Lateral Movement via SMB on 10.10.20.77'")
    executive_summary: str = Field(description="Concise executive briefing paragraph (business impact, severity)")
    attack_path_summary: str = Field(description="Technical summary of progression through kill chain stages")
    steps: list[StoryStep] = Field(default_factory=list)
    blast_radius_assessment: str = Field(description="Analysis of exposed critical assets and lateral reach")
    recommended_actions: list[StoryAction] = Field(default_factory=list)
    story_source: str = Field(default="llm", description="'llm' | 'template'")
    provider: str = Field(default="gemini", description="LLM provider name")
    model: str = Field(default="", description="LLM model name")
    source: str = Field(default="ai", description="'ai' | 'template' story source")
    fallback_reason: str | None = Field(default=None, description="Reason if template fallback was used")
    facts_sha256: str = Field(default="", description="SHA-256 of the facts used to generate this story")
    generated_at: str = Field(default="", description="ISO-8601 generation timestamp")

