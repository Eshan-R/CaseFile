"""Public reach engine dispatcher and engine factory."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from app.config import settings
from app.pipeline.path.reach.base import NotConfigured, ReachEngine
from app.pipeline.path.reach.neo4j_engine import Neo4jEngine
from app.pipeline.path.reach.networkx_engine import NetworkXEngine
from app.schemas.reach import NextReach
from app.store import duck

logger = logging.getLogger(__name__)


def get_reach_engine(engine_name: str | None = None) -> ReachEngine:
    """Resolve and instantiate the requested ReachEngine.

    Select by REACH_ENGINE environment variable, CLI flag, or settings.
    If the chosen engine is unavailable or raises NotConfigured, logs a warning
    and falls back to NetworkX.
    """
    raw_name = engine_name or os.environ.get("REACH_ENGINE") or getattr(settings, "reach_engine", "networkx")
    name = str(raw_name).strip().lower()

    if name in ("neo4j", "neo"):
        try:
            _ = Neo4jEngine()
            # Verify if Neo4j is configured
            raise NotConfigured("Neo4j engine is not configured (scheduled for Phase 11).")
        except (NotConfigured, Exception) as exc:
            logger.warning(
                "Selected reach engine %r is unavailable: %s. Falling back to NetworkX.",
                name,
                exc,
            )
            return NetworkXEngine()

    return NetworkXEngine()


def compute_reach(
    incident: dict[str, Any],
    access_edges: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
    engine_name: str | None = None,
) -> NextReach:
    """Compute NextReach using the selected reach engine."""
    engine = get_reach_engine(engine_name=engine_name)
    return engine.compute(incident=incident, access_edges=access_edges, config=config)


def get_or_compute_reach(incident_id: str) -> dict[str, Any]:
    """Legacy helper: return cached reach result or compute on demand."""
    inc = duck.get_incident(incident_id)
    if not inc:
        return {"incident_id": incident_id, "seed_hosts": [], "reachable": []}

    # If already precomputed in incident_next
    next_row = duck.get_incident_next(incident_id)
    if next_row:
        data = json.loads(next_row["data"]) if isinstance(next_row["data"], str) else next_row["data"]
        return {
            "incident_id": incident_id,
            "seed_hosts": data.get("compromised_nodes", []),
            "reachable": [
                {
                    "entity": t.get("target_id"),
                    "entity_kind": t.get("target_kind"),
                    "technique_id": None,
                    "tactic": None,
                    "recommendation": t.get("reason"),
                }
                for t in data.get("reachable_targets", [])
            ],
        }

    # Fallback to computing once
    from app.pipeline.path.reach.service import precompute_reach_for_incident

    next_reach = precompute_reach_for_incident(incident_id)
    return {
        "incident_id": incident_id,
        "seed_hosts": next_reach.compromised_nodes,
        "reachable": [
            {
                "entity": t.target_id,
                "entity_kind": t.target_kind,
                "technique_id": None,
                "tactic": None,
                "recommendation": t.reason,
            }
            for t in next_reach.reachable_targets
        ],
    }
