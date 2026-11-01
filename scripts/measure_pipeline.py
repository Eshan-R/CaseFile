"""Measure full analysis pipeline performance, peak memory, API latencies, and ground truth evaluation."""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
from pathlib import Path

# Add backend and scripts to path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_BACKEND_DIR = os.path.join(_REPO_ROOT, "backend")
_SCRIPTS_DIR = os.path.join(_REPO_ROOT, "scripts")

for p in (_BACKEND_DIR, _SCRIPTS_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi.testclient import TestClient  # noqa: E402
from metrics_tracker import MemoryTracker, benchmark_path_latency  # noqa: E402

try:
    from app.main import app  # noqa: E402
    from app.pipeline.detect.engine import run_detection  # noqa: E402
    from app.pipeline.detect.rule_loader import load_rules  # noqa: E402
    from app.pipeline.evaluate.evaluator import evaluate_manifest  # noqa: E402
    from app.pipeline.link.incidents import build_incidents  # noqa: E402
    from app.store import duck  # noqa: E402
except ImportError:
    from backend.app.main import app  # noqa: E402
    from backend.app.pipeline.detect.engine import run_detection  # noqa: E402
    from backend.app.pipeline.detect.rule_loader import load_rules  # noqa: E402
    from backend.app.pipeline.evaluate.evaluator import evaluate_manifest  # noqa: E402
    from backend.app.pipeline.link.incidents import build_incidents  # noqa: E402
    from backend.app.store import duck  # noqa: E402


def main():
    print("=== CaseFile Pipeline Measurement ===")

    # 1. Pipeline Execution
    print("\n[1/4] Running Pipeline Analysis (Detection + Incident Linking)...")
    duck.init_db()

    mem_tracker = MemoryTracker()
    mem_tracker.start()

    t_start = time.perf_counter()
    rules = load_rules()
    print(f"Loaded {len(rules)} detection rules.")

    det_res = run_detection(rules, job_id="job_meas_detect", max_workers=2)
    print(f"Detection phase complete: {det_res['total_detections']} detections in {det_res['elapsed_seconds']}s")

    t_link_start = time.perf_counter()
    link_res = build_incidents()
    t_link_elapsed = time.perf_counter() - t_link_start
    print(f"Incident linking complete: {link_res['incidents_created']} incidents ({link_res['alerts_created']} alerts) in {t_link_elapsed:.2f}s")

    total_proc_time = time.perf_counter() - t_start
    peak_rss = mem_tracker.stop()
    print(f"Total Analysis Processing Time: {total_proc_time:.2f}s")
    print(f"Peak RSS Memory: {peak_rss:.2f} MB")

    # 2. Benchmark API Response Times
    print("\n[2/4] Benchmarking API Response Latencies...")
    client = TestClient(app)

    endpoints = [
        ("/api/v1/health", "GET /health"),
        ("/api/v1/stats", "GET /stats"),
        ("/api/v1/jobs?limit=50", "GET /jobs (50)"),
        ("/api/v1/events?limit=100", "GET /events (100)"),
        ("/api/v1/detections?limit=100", "GET /detections (100)"),
        ("/api/v1/incidents?limit=50", "GET /incidents (50)"),
        ("/api/v1/rules", "GET /rules"),
    ]

    total, incs = duck.list_incidents(limit=5)
    sample_inc_id = incs[0]["incident_id"] if incs else None

    if sample_inc_id:
        endpoints.extend([
            (f"/api/v1/incidents/{sample_inc_id}", f"GET /incidents/{sample_inc_id}"),
            (f"/api/v1/incidents/{sample_inc_id}/graph", "GET incident graph"),
            (f"/api/v1/incidents/{sample_inc_id}/path", "GET incident path"),
            (f"/api/v1/incidents/{sample_inc_id}/reach", "GET incident reach"),
        ])

    print(f"{'Endpoint':<45} {'p50':>10} {'p95':>10} {'Status':>8}")
    print("-" * 75)

    for url, label in endpoints:
        latencies = []
        status_code = 200
        for _ in range(10):
            t0 = time.perf_counter()
            resp = client.get(url)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed_ms)
            status_code = resp.status_code

        p50 = statistics.median(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        print(f"{label:<45} {p50:>8.2f}ms {p95:>8.2f}ms {status_code:>8}")

    path_p50, path_p95, cnt = benchmark_path_latency(client=client, max_incidents=50)
    print(f"\nPath-open latency (across {cnt} incidents): p50={path_p50:.2f}ms, p95={path_p95:.2f}ms")

    # 3. Ground Truth Evaluation
    print("\n[3/4] Running Ground Truth Evaluator...")
    manifest_path = "data/firex-30G.log.manifest.json"
    if Path(manifest_path).exists():
        eval_res = evaluate_manifest(manifest_path)
        duck.set_stat("latest_evaluation", json.dumps(eval_res))
        print("Evaluation results:")
        print(f"  Detection Rate:          {eval_res.get('detection_rate', 0.0) * 100:.2f}%")
        print(f"  Label Accuracy (Exact):  {eval_res.get('label_accuracy_exact', 0.0) * 100:.2f}%")
        print(f"  Label Accuracy (Family): {eval_res.get('label_accuracy_family', 0.0) * 100:.2f}%")
        print(f"  Path Rate:               {eval_res.get('path_rate', 0.0) * 100:.2f}%")
        print(f"  Order Accuracy:          {eval_res.get('order_accuracy', 0.0) * 100:.2f}%")
        print(f"  False Alarm Rate:        {eval_res.get('false_alarm_rate', 0.0) * 100:.2f}%")
        print(f"  Our Detections:          {eval_res.get('our_detections_count', 0)}")
        print(f"  Our Incidents:           {eval_res.get('our_incidents_count', 0)}")
    else:
        print(f"Manifest {manifest_path} not found.")

    print("\n[4/4] Complete.")


if __name__ == "__main__":
    main()
