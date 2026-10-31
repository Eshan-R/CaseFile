"""Public reach API: delegates to Neo4j if available, else NetworkX."""

from __future__ import annotations

import json
from typing import Any

from app.pipeline.path.reach import neo4j_engine, networkx_engine
from app.store import duck


def get_or_compute_reach(incident_id: str) -> dict[str, Any]:
    """Return cached reach result from DB, or compute it on demand."""
    inc = duck.get_incident(incident_id)
    if not inc:
        return {"incident_id": incident_id, "seed_hosts": [], "reachable": []}

    # Serve from cache
    if inc.get("reach_json"):
        return json.loads(inc["reach_json"])

    # Compute
    result = neo4j_engine.compute_reach(incident_id)
    if result is None:
        result = networkx_engine.compute_reach(incident_id)

    # Cache
    duck.set_incident_reach(incident_id, json.dumps(result))
    return result

