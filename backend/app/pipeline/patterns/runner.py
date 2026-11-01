"""Miner Orchestrator: executes all unsupervised pattern miners in DuckDB and aggregates ranked patterns."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from app.config import settings
from app.pipeline.patterns.base import PatternCandidate
from app.pipeline.patterns.burst import mine_bursts
from app.pipeline.patterns.coordinated import mine_coordinated
from app.pipeline.patterns.novel_edges import mine_novel_edges
from app.pipeline.patterns.population_guard import (
    apply_population_guard_to_candidates,
    get_global_burst_seconds,
)
from app.pipeline.patterns.rarity import mine_rarity
from app.pipeline.patterns.sequences import mine_sequences
from app.store import duck

# DuckDB compatibility aliases
if not hasattr(duck, "create_job") and hasattr(duck, "insert_job"):
    duck.create_job = duck.insert_job
if not hasattr(duck, "get_connection") and hasattr(duck, "_get_conn"):
    duck.get_connection = duck._get_conn

if TYPE_CHECKING:
    import duckdb

logger = logging.getLogger(__name__)


def run_pattern_mining(
    con: duckdb.DuckDBPyConnection | None = None,
    min_score: float = 3.0,
    max_patterns: int = 200,
    exclude_population_artifacts: bool = True,
) -> tuple[list[PatternCandidate], dict[str, float]]:
    """Execute all 5 pattern miners deterministically against DuckDB."""
    start_time = time.perf_counter()
    timings: dict[str, float] = {}

    def _execute_miner(name: str, fn, c: duckdb.DuckDBPyConnection) -> list[PatternCandidate]:
        t0 = time.perf_counter()
        try:
            res = fn(c)
            timings[name] = round(time.perf_counter() - t0, 3)
            logger.info("Miner %s discovered %d patterns in %.3fs", name, len(res), timings[name])
            return res
        except Exception as exc:
            logger.warning("Miner %s failed: %s", name, exc)
            timings[name] = round(time.perf_counter() - t0, 3)
            return []

    all_candidates: list[PatternCandidate] = []

    def _run_all(active_con: duckdb.DuckDBPyConnection):
        # Configure DuckDB connection limits
        try:
            active_con.execute(f"SET threads={settings.duckdb_threads};")
            active_con.execute(f"SET max_memory='{settings.duckdb_memory_limit_gb}GB';")
            active_con.execute("SET preserve_insertion_order=false;")
        except Exception:
            pass

        burst_sec = get_global_burst_seconds(active_con)

        all_candidates.extend(
            _execute_miner(
                "burst",
                lambda c: mine_bursts(c, burst_seconds=burst_sec, exclude_artifacts=exclude_population_artifacts),
                active_con,
            )
        )
        all_candidates.extend(
            _execute_miner(
                "rarity",
                lambda c: mine_rarity(c, burst_seconds=burst_sec, exclude_artifacts=exclude_population_artifacts),
                active_con,
            )
        )
        all_candidates.extend(
            _execute_miner(
                "novel_edges",
                lambda c: mine_novel_edges(c, burst_seconds=burst_sec, exclude_artifacts=exclude_population_artifacts),
                active_con,
            )
        )
        all_candidates.extend(
            _execute_miner(
                "sequences",
                lambda c: mine_sequences(c, burst_seconds=burst_sec, exclude_artifacts=exclude_population_artifacts),
                active_con,
            )
        )
        all_candidates.extend(
            _execute_miner(
                "coordinated",
                lambda c: mine_coordinated(c, burst_seconds=burst_sec, exclude_artifacts=exclude_population_artifacts),
                active_con,
            )
        )

        # Aggregate population guard across all candidate patterns
        apply_population_guard_to_candidates(
            all_candidates,
            burst_seconds=burst_sec,
            window_seconds=900.0,
            max_distinct_sources=10,
            exclude=exclude_population_artifacts,
        )

    if con is not None:
        _run_all(con)
    else:
        # Sync events view over Parquet on server DB before acquiring cursor lock
        try:
            duck.ensure_events_view()
        except Exception as exc:
            logger.debug("ensure_events_view sync: %s", exc)
        with duck.cursor() as cur:
            _run_all(cur)

    # Deduplicate by pattern_id (preserve highest score)
    deduped: dict[str, PatternCandidate] = {}
    for cand in all_candidates:
        if cand.score < min_score:
            continue
        existing = deduped.get(cand.pattern_id)
        if not existing or cand.score > existing.score:
            deduped[cand.pattern_id] = cand

    # Deterministic sorting: score DESC, support DESC, pattern_id ASC
    sorted_patterns = sorted(
        deduped.values(),
        key=lambda p: (-p.score, -p.support, p.pattern_id),
    )

    final_patterns = sorted_patterns[:max_patterns]
    total_time = round(time.perf_counter() - start_time, 3)
    timings["total"] = total_time
    logger.info("Pattern mining completed: %d patterns retained in %.3fs", len(final_patterns), total_time)

    return final_patterns, timings

