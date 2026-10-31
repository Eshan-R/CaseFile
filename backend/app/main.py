"""FastAPI application entry point."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import (
    detections,
    evaluation,
    events,
    health,
    incidents,
    jobs,
    rules,
    stats,
)
from app.config import settings
from app.errors import ApiError, ErrorResponse
from app.pipeline.detect.rule_loader import load_rules
from app.store.duck import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    init_db()
    load_rules()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="CaseFile",
        version=settings.app_version,
        description="Security log analysis with MITRE ATT&CK mapping and incident graph.",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )

    # CORS – allow all origins in dev; restrict in prod via config
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ----- Global exception handlers -----

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(code=exc.code, detail=exc.detail).model_dump(),
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(code="internal_error", detail=str(exc)).model_dump(),
        )

    # ----- Routers -----
    prefix = "/api/v1"
    app.include_router(health.router, prefix=prefix)
    app.include_router(stats.router, prefix=prefix)
    app.include_router(jobs.router, prefix=prefix)
    app.include_router(events.router, prefix=prefix)
    app.include_router(detections.router, prefix=prefix)
    app.include_router(incidents.router, prefix=prefix)
    app.include_router(incidents.router)  # Allow direct /incidents routes
    app.include_router(rules.router, prefix=prefix)
    app.include_router(evaluation.router, prefix=prefix)

    # ----- Static UI -----
    import os
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(static_dir):
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    return app


app = create_app()
