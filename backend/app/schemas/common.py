"""Common Pydantic models shared across the API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Error envelope returned for every non-2xx response."""

    code: str = Field(description="Machine-readable error code.")
    detail: str = Field(description="Human-readable explanation.")


class HealthComponentStatus(BaseModel):
    ok: bool
    detail: str | None = None
    latency_ms: int | None = None


class HealthResponse(BaseModel):
    status: str  # "ok" | "degraded"
    app_version: str
    database: HealthComponentStatus
    llm: HealthComponentStatus

