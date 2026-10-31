"""GET /health – liveness and component status."""

from __future__ import annotations

import time

from fastapi import APIRouter

from app.config import settings
from app.schemas.common import HealthComponentStatus, HealthResponse
from app.store import duck

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Health check")
def health() -> HealthResponse:
    # Database check
    db_ok = False
    db_detail: str | None = None
    db_latency: int | None = None
    t0 = time.monotonic()
    try:
        duck.init_db()
        cnt = duck.count_events()
        db_ok = True
        db_detail = f"{cnt} events in DB"
        db_latency = int((time.monotonic() - t0) * 1000)
    except Exception as exc:
        db_detail = str(exc)

    # LLM check (stub)
    llm_ok = True
    llm_detail = "stub – not checked at startup"

    overall = "ok" if db_ok else "degraded"
    return HealthResponse(
        status=overall,
        app_version=settings.app_version,
        database=HealthComponentStatus(ok=db_ok, detail=db_detail, latency_ms=db_latency),
        llm=HealthComponentStatus(ok=llm_ok, detail=llm_detail),
    )

