"""Incident narrative report generator orchestrating facts, Gemini LLM, and template fallbacks."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from pydantic.fields import FieldInfo

from app.config import settings
from app.llm.client import get_llm_client
from app.pipeline.report.facts import build_incident_facts
from app.schemas.facts import IncidentFacts
from app.schemas.story import AttackStory, StoryAction, StoryStep

logger = logging.getLogger(__name__)

# Ensure AttackStory supports metadata fields
if "provider" not in AttackStory.model_fields:
    AttackStory.model_fields["provider"] = FieldInfo(annotation=str, default="")
if "model" not in AttackStory.model_fields:
    AttackStory.model_fields["model"] = FieldInfo(annotation=str, default="")
if "source" not in AttackStory.model_fields:
    AttackStory.model_fields["source"] = FieldInfo(annotation=str, default="template")
if "fallback_reason" not in AttackStory.model_fields:
    AttackStory.model_fields["fallback_reason"] = FieldInfo(annotation=str | None, default=None)
AttackStory.model_config["extra"] = "allow"
AttackStory.model_rebuild(force=True)


def is_key_configured() -> bool:
    """Return whether the Gemini LLM provider has an API key configured."""
    return bool(settings.llm_gemini_api_key)


def generate_template_story(facts: IncidentFacts, fallback_reason: str | None = None) -> AttackStory:
    """Generate a high-fidelity, 100% deterministic attack story directly from facts.

    Never requires an LLM or network connection. Used as the baseline and automatic fallback.
    """
    story_steps: list[StoryStep] = []
    for s in facts.steps:
        target_str = ", ".join(s.hosts) if s.hosts else "the target infrastructure"
        headline = f"Step {s.step_order}: {s.technique_name} on {target_str}"
        narrative = (
            f"Observed {s.technique_name} ({s.technique_id}) aligned with {s.tactic} "
            f"({s.kill_chain_stage}) impacting {target_str}. Telemetry records {s.event_count} events "
            f"(occurrence count: {s.occurrence_count}) active between {s.first_seen} and {s.last_seen}."
        )
        story_steps.append(
            StoryStep(
                step_order=s.step_order,
                technique_id=s.technique_id,
                technique_name=s.technique_name,
                tactic=s.tactic,
                headline=headline,
                narrative=narrative,
                cited_event_ids=s.evidence_event_ids[:4],
                entities_mentioned=[h for h in s.hosts if h],
                event_count=s.event_count,
                first_seen=s.first_seen,
                last_seen=s.last_seen,
            )
        )

    # Lateral reach summary
    blast_text = "No outward lateral movement observed."
    if facts.reach and facts.reach.reachable_targets:
        crit_str = f" Critical assets exposed: {', '.join(facts.reach.critical_assets)}." if facts.reach.critical_assets else ""
        blast_text = (
            f"Topology analysis indicates {facts.reach.hosts_count} reachable hosts across "
            f"{len(facts.reach.reachable_targets)} observable vectors.{crit_str}"
        )

    # Approved template actions
    actions: list[StoryAction] = []
    prio = 1
    for h in facts.hosts[:2]:
        actions.append(
            StoryAction(
                priority=prio,
                action="isolate_host",
                target=h,
                rationale=f"Isolate host {h} to contain potential malware or lateral movement.",
                command=f"edr-cli isolate --host {h} --reason 'CaseFile Containment'",
            )
        )
        prio += 1

    for ip in facts.src_ips[:2]:
        actions.append(
            StoryAction(
                priority=prio,
                action="block_ip",
                target=ip,
                rationale=f"Block inbound and outbound network traffic to hostile address {ip}.",
                command=f"iptables -A INPUT -s {ip} -j DROP",
            )
        )
        prio += 1

    for u in facts.users[:2]:
        actions.append(
            StoryAction(
                priority=prio,
                action="disable_account",
                target=u,
                rationale=f"Disable user account {u} pending credential rotation.",
                command=f"Disable-ADAccount -Identity {u}",
            )
        )
        prio += 1

    target_summary = ", ".join(facts.hosts) if facts.hosts else "network endpoints"
    tech_summary = ", ".join([s.technique_name for s in facts.steps]) if facts.steps else "threat activity"

    if fallback_reason is None:
        if not settings.llm_gemini_api_key:
            fallback_reason = "Template (Gemini unavailable: No Gemini API key configured)"
        else:
            fallback_reason = "Template (Deterministic template fallback)"

    provider = "gemini" if settings.llm_gemini_api_key else "template"
    model = settings.llm_model or ""

    return AttackStory(
        incident_id=facts.incident_id,
        headline=f"Attack Campaign targeting {target_summary} ({tech_summary})",
        executive_summary=(
            f"Automated deterministic assessment for incident {facts.incident_id} (severity {facts.severity}/10, "
            f"risk score {facts.risk_score:.1f}/10). The incident encompasses {facts.detection_count} detections "
            f"and {facts.event_count} raw events observed between {facts.first_seen} and {facts.last_seen}."
        ),
        attack_path_summary=(
            f"Identified {len(facts.steps)} progressive kill chain steps spanning {target_summary}."
        ),
        steps=story_steps,
        blast_radius_assessment=blast_text,
        recommended_actions=actions,
        story_source="template",
        source="template",
        provider=provider,
        model=model,
        fallback_reason=fallback_reason,
        facts_sha256=facts.facts_sha256,
        generated_at=datetime.now(UTC).isoformat(),
    )


def generate_story_for_incident(
    incident_id: str,
    facts: IncidentFacts | None = None,
) -> AttackStory:
    """Generate an attack story for an incident, using LLM if available or template on error."""
    if facts is None:
        facts = build_incident_facts(incident_id)

    client = get_llm_client()
    if client is None:
        return generate_template_story(
            facts,
            fallback_reason="Template (Gemini unavailable: No Gemini API key configured)",
        )

    try:
        story = client.generate_story(facts)
        story.source = "ai"
        story.provider = getattr(client, "provider", "") or "gemini"
        story.model = getattr(client, "model", "") or settings.llm_model
        story.fallback_reason = None
        if not story.generated_at:
            story.generated_at = datetime.now(UTC).isoformat()
        return story
    except Exception as exc:
        logger.warning(
            "LLM generation failed for incident %s (%s). Falling back to template story.",
            incident_id,
            exc,
        )
        fb_reason = f"Template (Gemini unavailable: Gemini API error: {exc})"
        return generate_template_story(facts, fallback_reason=fb_reason)


def add_narrative(report_md: str) -> str:
    """Legacy helper for markdown reports."""
    return report_md
