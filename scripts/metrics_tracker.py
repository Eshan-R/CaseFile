"""Performance metrics tracker for pipeline runs: peak RSS memory and path-open latency.

Cross-platform implementation using psutil. Zero ctypes.wintypes usage.
"""

from __future__ import annotations

import os
import statistics
import sys
import threading
import time
from typing import Any

import psutil

# Ensure backend is on sys.path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_BACKEND_DIR = os.path.join(_REPO_ROOT, "backend")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


class MemoryTracker:
    """Tracks peak resident set size (RSS) in MB across process and known worker processes.
    
    Runs a lightweight background sampling thread that periodically inspects known
    PIDs every 500 ms, avoiding expensive process table tree traversal on Windows.
    """

    def __init__(
        self,
        interval_seconds: float = 0.5,
        pids_provider: Any | None = None,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.pids_provider = pids_provider
        self._lock = threading.Lock()
        self._worker_pids: set[int] = set()
        self._peak_rss_bytes = 0
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._root_pid = os.getpid()
        self._cpu_samples: list[float] = []

    def set_worker_pids(self, pids: Any) -> None:
        """Register worker PIDs to monitor directly."""
        with self._lock:
            for p in pids:
                if isinstance(p, int):
                    self._worker_pids.add(p)

    def _sample_tree_rss(self) -> int:
        """Sum the RSS of the root process and all known worker processes."""
        total_rss = 0
        try:
            try:
                root_proc = psutil.Process(self._root_pid)
                total_rss += root_proc.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            target_pids: set[int] = set()
            if self.pids_provider is not None:
                try:
                    target_pids.update(self.pids_provider())
                except Exception:
                    pass

            with self._lock:
                target_pids.update(self._worker_pids)

            if target_pids:
                for pid in target_pids:
                    if pid == self._root_pid:
                        continue
                    try:
                        p = psutil.Process(pid)
                        total_rss += p.memory_info().rss
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
            else:
                # Fallback to direct children only (recursive=False) to avoid full OS enumeration
                try:
                    root_proc = psutil.Process(self._root_pid)
                    for child in root_proc.children(recursive=False):
                        try:
                            total_rss += child.memory_info().rss
                            with self._lock:
                                self._worker_pids.add(child.pid)
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            pass
                except Exception:
                    pass
        except Exception:
            pass

        return total_rss

    def _monitor(self) -> None:
        while not self._stop_event.is_set():
            try:
                current_rss = self._sample_tree_rss()
                if current_rss > self._peak_rss_bytes:
                    self._peak_rss_bytes = current_rss
                # Sample CPU utilization across all cores
                cpu = psutil.cpu_percent(interval=None)
                if cpu > 0:
                    self._cpu_samples.append(cpu)
            except Exception:
                pass
            self._stop_event.wait(self.interval_seconds)

        try:
            current_rss = self._sample_tree_rss()
            if current_rss > self._peak_rss_bytes:
                self._peak_rss_bytes = current_rss
        except Exception:
            pass

    def start(self) -> MemoryTracker:
        """Start tracking peak memory in background thread."""
        self._stop_event.clear()
        try:
            # Prime CPU percent measurement
            psutil.cpu_percent(interval=None)
            initial_rss = self._sample_tree_rss()
            if initial_rss > self._peak_rss_bytes:
                self._peak_rss_bytes = initial_rss
        except Exception:
            pass
        self._thread = threading.Thread(target=self._monitor, daemon=True, name="MemoryTracker")
        self._thread.start()
        return self

    def stop(self) -> float:
        """Stop tracking and return peak RSS in megabytes."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        return self.get_peak_rss_mb()

    def get_peak_rss_mb(self) -> float:
        """Return the highest recorded process-tree RSS in megabytes."""
        return round(self._peak_rss_bytes / (1024.0 * 1024.0), 2)

    def get_avg_cpu_percent(self) -> float:
        """Return average CPU utilization percentage across all cores during sampling."""
        if not self._cpu_samples:
            return 0.0
        return round(sum(self._cpu_samples) / len(self._cpu_samples), 1)

    def __enter__(self) -> MemoryTracker:
        return self.start()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


def get_system_memory_status() -> dict[str, float]:
    """Return available physical RAM, commit limit, used commit, and available commit in GB."""
    vm = psutil.virtual_memory()
    ram_total_gb = round(vm.total / (1024**3), 2)
    ram_avail_gb = round(vm.available / (1024**3), 2)

    sw = psutil.swap_memory()
    pagefile_total_gb = round(sw.total / (1024**3), 2)
    pagefile_free_gb = round(sw.free / (1024**3), 2)

    commit_limit_gb = ram_total_gb + pagefile_total_gb
    commit_used_gb = round(vm.used / (1024**3), 2)
    commit_avail_gb = ram_avail_gb

    # If on Windows, query GetPerformanceInfo for precise commit stats without ctypes.wintypes
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import Structure, byref, c_size_t, sizeof

            class _PerfInfo(Structure):
                _fields_ = [
                    ("cb", c_size_t),
                    ("CommitTotal", c_size_t),
                    ("CommitLimit", c_size_t),
                    ("CommitPeak", c_size_t),
                    ("PhysicalTotal", c_size_t),
                    ("PhysicalAvailable", c_size_t),
                    ("SystemCache", c_size_t),
                    ("KernelTotal", c_size_t),
                    ("KernelPaged", c_size_t),
                    ("KernelNonpaged", c_size_t),
                    ("PageSize", c_size_t),
                    ("HandleCount", c_size_t),
                    ("ProcessCount", c_size_t),
                    ("ThreadCount", c_size_t),
                ]

            pi = _PerfInfo()
            pi.cb = sizeof(pi)
            if ctypes.windll.psapi.GetPerformanceInfo(byref(pi), sizeof(pi)):
                page_size = pi.PageSize
                commit_limit_gb = round((pi.CommitLimit * page_size) / (1024**3), 2)
                commit_used_gb = round((pi.CommitTotal * page_size) / (1024**3), 2)
                commit_avail_gb = round(((pi.CommitLimit - pi.CommitTotal) * page_size) / (1024**3), 2)
        except Exception:
            pass

    return {
        "ram_total_gb": ram_total_gb,
        "ram_avail_gb": ram_avail_gb,
        "commit_limit_gb": commit_limit_gb,
        "commit_used_gb": commit_used_gb,
        "commit_avail_gb": commit_avail_gb,
        "pagefile_total_gb": pagefile_total_gb,
        "pagefile_free_gb": pagefile_free_gb,
    }


def benchmark_path_latency(
    client: Any | None = None,
    max_incidents: int = 50,
    samples_per_incident: int = 1,
) -> tuple[float, float, int]:
    """Benchmark GET /api/v1/incidents/{id}/path in-process via FastAPI TestClient.
    
    Returns:
        (p50_ms, p95_ms, sampled_count)
    """
    try:
        from app.main import app
        from app.store import duck
    except ImportError:
        from backend.app.main import app
        from backend.app.store import duck
    from fastapi.testclient import TestClient

    if client is None:
        client = TestClient(app)

    total_incidents, incidents = duck.list_incidents(limit=max_incidents)
    if not incidents:
        return 0.0, 0.0, 0

    latencies_ms: list[float] = []

    for inc in incidents:
        inc_id = inc["incident_id"]
        url = f"/api/v1/incidents/{inc_id}/path"
        for _ in range(samples_per_incident):
            t0 = time.perf_counter()
            resp = client.get(url)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if resp.status_code == 200:
                latencies_ms.append(elapsed_ms)

    if not latencies_ms:
        return 0.0, 0.0, 0

    latencies_sorted = sorted(latencies_ms)
    p50 = statistics.median(latencies_sorted)
    # 95th percentile
    idx_p95 = min(len(latencies_sorted) - 1, int(len(latencies_sorted) * 0.95))
    p95 = latencies_sorted[idx_p95]

    return round(p50, 2), round(p95, 2), len(latencies_ms)
