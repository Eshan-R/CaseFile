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
    clear_predicted_paths_cache,
    extract_access_edges_from_events,
    get_predicted_next_paths,
    inject_predicted_paths_into_cytoscape,
    precompute_all_incidents,
    precompute_reach_for_incident,
    predict_next_paths,
)
from app.schemas.next_paths import (
    DEFAULT_NEXT_PATHS_DISCLAIMER,
    NextPathEvidence,
    NextPathsResponse,
    PredictedPathItem,
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
    "DEFAULT_NEXT_PATHS_DISCLAIMER",
    "BlastRadius",
    "Neo4jEngine",
    "NetworkXEngine",
    "NextPathEvidence",
    "NextPathsResponse",
    "NextReach",
    "NotConfigured",
    "PredictedPath",
    "PredictedPathItem",
    "ReachEngine",
    "ReachableTarget",
    "clear_predicted_paths_cache",
    "compute_reach",
    "extract_access_edges_from_events",
    "get_or_compute_reach",
    "get_predicted_next_paths",
    "get_reach_engine",
    "inject_predicted_paths_into_cytoscape",
    "precompute_all_incidents",
    "precompute_reach_for_incident",
    "predict_next_paths",
]
