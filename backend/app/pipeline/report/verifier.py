"""Strict grounding verifier for LLM-generated attack stories."""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from app.config import settings
from app.pipeline.report.llm_report import generate_template_story
from app.schemas.facts import IncidentFacts
from app.schemas.story import AttackStory

logger = logging.getLogger(__name__)

# IPv4 regex for detecting hallucinated IP addresses in prose
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

# Default approved response action keys
DEFAULT_APPROVED_ACTIONS = {
    "block_ip",
    "isolate_host",
    "disable_account",
    "reset_credentials",
    "revoke_sessions",
    "sinkhole_dns",
    "enable_enhanced_logging",
    "revert_config",
}


def load_approved_actions() -> set[str]:
    """Load approved action keys from knowledge/response_actions.yaml."""
    # Find knowledge directory relative to backend/app/pipeline/report/verifier.py
    # verifier.py -> report -> pipeline -> app -> backend -> repo_root
    repo_root = Path(__file__).resolve().parents[4]
    actions_file = repo_root / "knowledge" / "response_actions.yaml"
    if not actions_file.exists():
        # Also try parent 3 if running inside backend
        actions_file = Path(__file__).resolve().parents[3] / "knowledge" / "response_actions.yaml"

    if actions_file.exists():
        try:
            with open(actions_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    return set(data.keys())
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", actions_file, exc)

    return DEFAULT_APPROVED_ACTIONS


class VerificationResult(BaseModel):
    """Result of multi-layer story grounding verification."""

    is_valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def verify_story(story: AttackStory, facts: IncidentFacts) -> VerificationResult:
    """Verify an AttackStory against deterministic IncidentFacts.

    Enforces strict grounding:
    1. Incident ID matching.
    2. Per-step technique and citation validation against fact step evidence_event_ids.
    3. Per-step structured telemetry verification (event_count, first_seen, last_seen, entities).
    4. Anti-hallucination regex scan across all prose fields (any IP mentioned must be known).
    5. Containment action whitelist validation against knowledge/response_actions.yaml.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # 1. Incident ID
    if story.incident_id != facts.incident_id:
        errors.append(f"Incident ID mismatch: story has '{story.incident_id}', facts has '{facts.incident_id}'")

    # Map fact steps by step_order and technique_id
    fact_step_by_order = {s.step_order: s for s in facts.steps}
    fact_step_by_tech = {s.technique_id: s for s in facts.steps}
    known_entities_set = {e.lower().strip() for e in facts.known_entities if e}
    known_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    # Parse CIDRs in known_entities, src_ips, hosts and add base & broadcast addresses
    all_raw_entities = set(facts.known_entities) | set(facts.src_ips) | set(facts.hosts)
    for ent in all_raw_entities:
        if not ent or not isinstance(ent, str):
            continue
        ent_str = ent.strip()
        if "/" in ent_str:
            try:
                net = ipaddress.ip_network(ent_str, strict=False)
                known_cidrs.append(net)
                known_entities_set.add(str(net.network_address).lower())
                if net.broadcast_address:
                    known_entities_set.add(str(net.broadcast_address).lower())
            except ValueError:
                pass
        else:
            try:
                ip_obj = ipaddress.ip_address(ent_str)
                known_entities_set.add(str(ip_obj).lower())
            except ValueError:
                pass

    def _is_allowed_entity(entity: str) -> bool:
        ent_clean = entity.lower().strip()
        if ent_clean in known_entities_set:
            return True
        try:
            ip_obj = ipaddress.ip_address(ent_clean)
            return any(ip_obj in net for net in known_cidrs)
        except ValueError:
            return False

    all_facts_eids_set = set(facts.all_event_ids)
    for s in facts.steps:
        all_facts_eids_set.update(s.evidence_event_ids)

    # 2. Per-Step Verification
    for s_step in story.steps:
        f_step = fact_step_by_order.get(s_step.step_order) or fact_step_by_tech.get(s_step.technique_id)
        if not f_step:
            errors.append(
                f"Step {s_step.step_order} ({s_step.technique_id}) does not correspond to any step in incident facts"
            )
            continue

        # Technique ID match
        if s_step.technique_id != f_step.technique_id:
            errors.append(
                f"Step {s_step.step_order} technique mismatch: story has '{s_step.technique_id}', "
                f"fact has '{f_step.technique_id}'"
            )

        # Citations check
        for eid in s_step.cited_event_ids:
            if eid not in f_step.evidence_event_ids and eid not in all_facts_eids_set:
                errors.append(
                    f"Step {s_step.step_order} cited fake or unknown event ID '{eid}' not present in facts"
                )

        # Entities mentioned in step
        for ent in s_step.entities_mentioned:
            if not _is_allowed_entity(ent):
                errors.append(
                    f"Step {s_step.step_order} mentions unknown entity '{ent}' not in facts.known_entities"
                )

        # Event count verification
        if s_step.event_count != f_step.event_count:
            errors.append(
                f"Step {s_step.step_order} event count mismatch: story claims {s_step.event_count}, "
                f"facts record {f_step.event_count}"
            )

        # Timestamp verification (if provided in story step)
        if s_step.first_seen and s_step.first_seen != f_step.first_seen:
            errors.append(
                f"Step {s_step.step_order} first_seen mismatch: story has '{s_step.first_seen}', "
                f"facts have '{f_step.first_seen}'"
            )
        if s_step.last_seen and s_step.last_seen != f_step.last_seen:
            errors.append(
                f"Step {s_step.step_order} last_seen mismatch: story has '{s_step.last_seen}', "
                f"facts have '{f_step.last_seen}'"
            )

    # 3. Global Prose Anti-Hallucination IP Scan
    prose_texts = [
        story.headline,
        story.executive_summary,
        story.attack_path_summary,
        story.blast_radius_assessment,
    ]
    for s_step in story.steps:
        prose_texts.append(s_step.headline)
        prose_texts.append(s_step.narrative)
    for act in story.recommended_actions:
        prose_texts.append(act.rationale)

    full_prose = " ".join(prose_texts)
    mentioned_ips = set(IPV4_REGEX.findall(full_prose))
    for ip in mentioned_ips:
        if not _is_allowed_entity(ip):
            errors.append(
                f"Hallucinated IP address detected in story prose: '{ip}' is not present in incident facts"
            )

    # 4. Response Actions Verification
    approved_actions = load_approved_actions()
    for act in story.recommended_actions:
        if act.action not in approved_actions:
            errors.append(
                f"Unapproved response action '{act.action}' (allowed: {sorted(list(approved_actions))})"
            )
        if not _is_allowed_entity(act.target):
            errors.append(
                f"Action target '{act.target}' for '{act.action}' is not a known entity in incident facts"
            )

    return VerificationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


def generate_and_verify_story(
    facts: IncidentFacts,
    llm_client: Any = None,
) -> AttackStory:
    """Generate an AttackStory via LLM, strictly verify it, retry once on error, or fallback to template."""
    from app.llm.client import get_llm_client

    if llm_client is None:
        llm_client = get_llm_client()

    if llm_client is None:
        fallback_reason = "Template (Gemini unavailable: No Gemini API key configured)"
        logger.info(
            "No Gemini API key configured, using deterministic template story for incident %s",
            facts.incident_id,
        )
        template_story = generate_template_story(facts, fallback_reason=fallback_reason)
        template_story.story_source = "template"
        template_story.source = "template"
        template_story.fallback_reason = fallback_reason
        return template_story

    def _tag_story(st: AttackStory) -> AttackStory:
        st.source = "ai"
        st.provider = getattr(llm_client, "provider", "") or "gemini"
        st.model = getattr(llm_client, "model", "") or settings.llm_model
        st.fallback_reason = None
        st.story_source = "llm"
        if not st.generated_at:
            st.generated_at = datetime.now(UTC).isoformat()
        return st

    fallback_reason: str | None = None

    # Attempt 1: Generate via LLM
    try:
        story = llm_client.generate_story(facts)
        ver_res = verify_story(story, facts)
        if ver_res.is_valid:
            return _tag_story(story)
        fallback_reason = f"Template (Gemini unavailable: Grounding rejection: {'; '.join(ver_res.errors[:2])})"
        logger.warning(
            "Initial story generation failed grounding verification with %d errors: %s",
            len(ver_res.errors),
            ver_res.errors[:3],
        )
    except Exception as exc:
        fallback_reason = f"Template (Gemini unavailable: Gemini API error: {exc})"
        logger.warning("LLM client generation failed on attempt 1: %s", exc)

    # Attempt 2: Re-try once
    try:
        story_retry = llm_client.generate_story(facts)
        ver_res_retry = verify_story(story_retry, facts)
        if ver_res_retry.is_valid:
            return _tag_story(story_retry)
        fallback_reason = f"Template (Gemini unavailable: Grounding rejection: {'; '.join(ver_res_retry.errors[:2])})"
        logger.warning(
            "Retry story generation failed grounding verification: %s",
            ver_res_retry.errors[:3],
        )
    except Exception as exc:
        fallback_reason = f"Template (Gemini unavailable: Gemini API error: {exc})"
        logger.warning("LLM client generation failed on attempt 2: %s", exc)

    # Fallback to 100% deterministic template story
    logger.info("Falling back to deterministic template story for incident %s", facts.incident_id)
    template_story = generate_template_story(facts, fallback_reason=fallback_reason)
    template_story.story_source = "template"
    template_story.source = "template"
    template_story.fallback_reason = fallback_reason
    return template_story
