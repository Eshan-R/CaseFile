"""Automated Pattern Discovery Subsystem."""

from app.pipeline.patterns.base import PatternCandidate, generate_pattern_id
from app.pipeline.patterns.burst import mine_bursts
from app.pipeline.patterns.coordinated import mine_coordinated
from app.pipeline.patterns.novel_edges import mine_novel_edges
from app.pipeline.patterns.population_guard import (
    apply_population_guard_to_candidates,
    get_global_burst_seconds,
)
from app.pipeline.patterns.rarity import mine_rarity
from app.pipeline.patterns.runner import run_pattern_mining
from app.pipeline.patterns.sequences import mine_sequences
from app.store import duck

# DuckDB compatibility aliases
if not hasattr(duck, "create_job") and hasattr(duck, "insert_job"):
    duck.create_job = duck.insert_job
if not hasattr(duck, "get_connection") and hasattr(duck, "_get_conn"):
    duck.get_connection = duck._get_conn

__all__ = [
    "PatternCandidate",
    "apply_population_guard_to_candidates",
    "generate_pattern_id",
    "get_global_burst_seconds",
    "mine_bursts",
    "mine_coordinated",
    "mine_novel_edges",
    "mine_rarity",
    "mine_sequences",
    "run_pattern_mining",
]

