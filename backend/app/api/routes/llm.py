"""LLM status endpoint reporting provider, model, key configuration, and budget."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.config import settings
from app.llm.client import get_call_count

router = APIRouter(tags=["llm"])


class LLMStatus(BaseModel):
    provider: str = Field(default="gemini", description="Configured LLM provider name")
    model: str = Field(default="", description="Configured LLM model name")
    key_configured: bool = Field(description="Whether a valid Gemini API key is present")
    budget_remaining: int = Field(description="Remaining API call budget for the runtime session")


@router.get(
    "/llm/status",
    response_model=LLMStatus,
    summary="Get LLM provider status, model, key availability, and budget",
)
@router.get("/status", response_model=LLMStatus, include_in_schema=False)
@router.get("/api/v1/llm/status", response_model=LLMStatus, include_in_schema=False)
def get_llm_status() -> LLMStatus:
    budget_remaining = max(0, settings.llm_call_budget - get_call_count())

    return LLMStatus(
        provider="gemini",
        model=settings.llm_model,
        key_configured=bool(settings.llm_gemini_api_key),
        budget_remaining=budget_remaining,
    )
