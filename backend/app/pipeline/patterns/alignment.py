"""Optional AI-assisted pattern alignment and threat narrative enrichment."""

from __future__ import annotations

import logging
from typing import Any

from app.llm.client import get_llm_client
from app.pipeline.patterns.base import PatternCandidate

logger = logging.getLogger(__name__)


def enrich_pattern_with_ai(pattern: PatternCandidate) -> PatternCandidate:
    """Optionally query LLM to produce an analyst-friendly description and ATT&CK alignment."""
    llm = get_llm_client()
    if not llm.is_available():
        return pattern

    prompt = f"""You are an elite SOC Cyber Threat Intelligence analyst.
Analyze the following unsupervised pattern discovered from firewall telemetry:
Kind: {pattern.kind}
Current Title: {pattern.title}
Event Count: {pattern.support}
Entities: {', '.join(pattern.entities[:4])}
Suggested Technique: {pattern.suggested_technique or 'Unknown'}
Details: {pattern.details_json}

Provide a concise, 1-sentence analytical assessment explaining the security significance of this pattern.
Do not hallucinate entities or IPs. Return only the assessment text."""

    try:
        response = llm.generate_story(facts_text=prompt)
        assessment = response.narrative.strip()
        if assessment:
            details: dict[str, Any] = dict(pattern.details_json)
            details["ai_assessment"] = assessment
            pattern.details_json = details
    except Exception as exc:
        logger.debug("AI pattern enrichment skipped/failed: %s", exc)

    return pattern

