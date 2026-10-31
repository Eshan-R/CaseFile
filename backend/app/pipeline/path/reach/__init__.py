"""Reach analysis package for CaseFile.

Provides predictive attack path generation, blast radius calculation,
and reachability estimation using NetworkX with optional Neo4j support.
"""

from __future__ import annotations

from app.pipeline.path.reach.base import NotConfigured, ReachEngine
from app.pipeline.path.reach.engine import compute_reach, get_or_compute_reach, get_reach_engine
from app.pipeline.path.reach.neo4j_engine import Neo4jEngine
from app.pipeline.path.reach.networkx_engine import NetworkXEngine
from app.pipeline.path.reach.service import (
    extract_access_edges_from_events,
    precompute_all_incidents,
    precompute_reach_for_incident,
)
from app.schemas.reach import (
    DEFAULT_DISCLAIMER,
    BlastRadius,
    NextReach,
    PredictedPath,
    ReachableTarget,
)

__all__ = [
    "DEFAULT_DISCLAIMER",
    "BlastRadius",
    "Neo4jEngine",
    "NetworkXEngine",
    "NextReach",
    "NotConfigured",
    "PredictedPath",
    "ReachEngine",
    "ReachableTarget",
    "compute_reach",
    "extract_access_edges_from_events",
    "get_or_compute_reach",
    "get_reach_engine",
    "precompute_all_incidents",
    "precompute_reach_for_incident",
]
