"""API routes for predicted next paths and lateral reach."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from app.pipeline.path.reach.service import get_predicted_next_paths
from app.schemas.next_paths import NextPathsResponse
from app.store import duck

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get(
    "/{id}/next-paths",
    response_model=NextPathsResponse,
    summary="Predict next lateral attack paths for an incident",
)
def get_next_paths(id: str) -> NextPathsResponse:
    """Return deterministic predicted next paths for incident {id}."""
    inc = duck.get_incident(id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {id!r} not found")

    resp = get_predicted_next_paths(id)
    if resp is None:
        raise HTTPException(status_code=404, detail=f"Incident {id!r} not found")

    return resp


# Ensure routes are registered before the static mount catch-all
try:
    from app.main import app as _main_app

    _registered_paths = {getattr(r, "path", "") for r in getattr(_main_app, "routes", [])}
    if "/api/v1/incidents/{id}/next-paths" not in _registered_paths:
        _main_app.include_router(router, prefix="/api/v1")
        _main_app.include_router(router)

        # Move static catch-all mount to the very end of routes list
        static_routes = [
            r for r in _main_app.routes
            if getattr(r, "name", "") == "static" or getattr(r, "path", "") == ""
        ]
        for sr in static_routes:
            _main_app.routes.remove(sr)
            _main_app.routes.append(sr)
except Exception:
    pass
