"""Optional LLM narrative generator.

Calls the configured LLM provider (OpenAI-compatible /v1/chat/completions)
to add an analyst-style narrative to the Markdown report.
"""

from __future__ import annotations

import httpx

from app.config import settings

_SYSTEM_PROMPT = (
    "You are a senior security analyst. "
    "Given a structured incident report, write a concise 3-5 paragraph narrative "
    "explaining what the attacker did, why it matters, and what to do next. "
    "Use only facts from the report. Never invent evidence."
)


def add_narrative(report_md: str) -> str:
    """Return report_md with an LLM-generated narrative appended.

    Returns original report if LLM is not configured or call fails.
    """
    if not settings.llm_api_key:
        return report_md

    try:
        with httpx.Client(timeout=settings.llm_timeout_seconds) as client:
            response = client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.llm_api_key}"},
                json={
                    "model": settings.llm_model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": report_md},
                    ],
                    "max_tokens": 800,
                    "temperature": 0.2,
                },
            )
        response.raise_for_status()
        narrative = response.json()["choices"][0]["message"]["content"]
        return report_md + "\n\n## Analyst Narrative\n\n" + narrative
    except Exception:
        return report_md

