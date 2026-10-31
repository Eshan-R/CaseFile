"""Benchmark end-to-end API response times.

Usage:
    python scripts/benchmark.py [--base-url http://localhost:8000] [--incident-id inc_xxxxxxxx]
"""

from __future__ import annotations

import argparse
import statistics
import time

import httpx


def bench(client: httpx.Client, url: str, n: int = 10, label: str = "") -> None:
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        r = client.get(url)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        times.append(elapsed_ms)
    p50 = statistics.median(times)
    p95 = sorted(times)[int(n * 0.95)]
    status = r.status_code
    print(f"{label or url:<50} p50={p50:6.1f}ms  p95={p95:6.1f}ms  status={status}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--incident-id", default=None)
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    with httpx.Client(base_url=base, timeout=10) as client:
        bench(client, "/api/v1/health", label="GET /health")
        bench(client, "/api/v1/stats", label="GET /stats")
        bench(client, "/api/v1/jobs?limit=50", label="GET /jobs (50)")
        bench(client, "/api/v1/events?limit=100", label="GET /events (100)")
        bench(client, "/api/v1/detections?limit=100", label="GET /detections (100)")
        bench(client, "/api/v1/incidents?limit=50", label="GET /incidents (50)")
        bench(client, "/api/v1/rules", label="GET /rules")

        if args.incident_id:
            iid = args.incident_id
            bench(client, f"/api/v1/incidents/{iid}", label=f"GET incident")
            bench(client, f"/api/v1/incidents/{iid}/graph", label=f"GET graph")
            bench(client, f"/api/v1/incidents/{iid}/path", label=f"GET path")
            bench(client, f"/api/v1/incidents/{iid}/reach", label=f"GET reach")


if __name__ == "__main__":
    main()

