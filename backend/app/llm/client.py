"""Thin OpenAI-compatible LLM client."""

from __future__ import annotations

import httpx

from app.config import settings


def chat(prompt: str, system: str = "", max_tokens: int = 1000) -> str:
    """Send a prompt and return the reply text.  Raises on failure."""
    if not settings.llm_api_key:
        raise RuntimeError("LLM_API_KEY is not set.")

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    with httpx.Client(timeout=settings.llm_timeout_seconds) as client:
        resp = client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.llm_api_key}"},
            json={"model": settings.llm_model, "messages": messages, "max_tokens": max_tokens},
        )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]

