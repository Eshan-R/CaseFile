"""Report schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ReportRequest(BaseModel):
    incident_id: str
    use_llm: bool = False


class ReportResponse(BaseModel):
    incident_id: str
    format: str = "markdown"
    content: str
    generated_at: datetime
    llm_used: bool = False

