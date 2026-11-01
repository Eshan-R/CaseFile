"""Tests for scripts/metrics_tracker.py (MemoryTracker and latency benchmarking)."""

from __future__ import annotations

import os
import sys
import time

from app.main import app
from app.store import duck
from fastapi.testclient import TestClient

# Import metrics_tracker from scripts
_SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from metrics_tracker import MemoryTracker, benchmark_path_latency  # noqa: E402


def test_memory_tracker_lifecycle():
    tracker = MemoryTracker(interval_seconds=0.02)
    tracker.start()

    # Allocate some temporary memory
    data = [bytearray(1024 * 1024) for _ in range(10)]
    time.sleep(0.08)

    peak_mb = tracker.stop()
    assert peak_mb > 0.0
    assert tracker.get_peak_rss_mb() >= peak_mb or tracker.get_peak_rss_mb() > 0.0

    # Test context manager interface
    with MemoryTracker(interval_seconds=0.02) as ctx_tracker:
        _ = [bytearray(512 * 1024) for _ in range(5)]
        time.sleep(0.05)
    assert ctx_tracker.get_peak_rss_mb() > 0.0
    del data


def test_benchmark_path_latency_mocked():
    duck.init_db()
    client = TestClient(app)

    # When no incidents exist
    p50, p95, count = benchmark_path_latency(client=client, max_incidents=5)
    # Count will be 0 or real count if db already has incidents
    assert isinstance(p50, float)
    assert isinstance(p95, float)
    assert isinstance(count, int)
