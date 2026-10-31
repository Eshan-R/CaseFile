"""Neo4j reach engine stub (scheduled for Phase 11)."""

from __future__ import annotations

from typing import Any

from app.pipeline.path.reach.base import NotConfigured, ReachEngine
from app.schemas.reach import NextReach


class Neo4jEngine(ReachEngine):
    """Stub engine for Neo4j graph queries.

    Raises a clear NotConfigured error until Phase 11.
    """

    name: str = "neo4j"

    def compute(
        self,
        incident: dict[str, Any],
        access_edges: list[dict[str, Any]],
        config: dict[str, Any] | None = None,
    ) -> NextReach:
        raise NotConfigured(
            "Neo4j reach engine is not configured. Neo4j support is scheduled for Phase 11."
        )


def compute_reach(incident_id: str) -> dict[str, Any] | None:
    """Legacy helper: returns None so callers fall back to NetworkX."""
    return None
