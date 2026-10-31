"""Neo4j reach engine stub (optional).

Replace `_AVAILABLE = False` with `True` and fill in the connection
once Neo4j is running.
"""

from __future__ import annotations

_AVAILABLE = False


def compute_reach(incident_id: str) -> dict | None:  # pragma: no cover
    """Return None when Neo4j is not configured; the route falls back to NetworkX."""
    if not _AVAILABLE:
        return None
    raise NotImplementedError("Neo4j engine not yet wired up.")

