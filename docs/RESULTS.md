# CaseFile Benchmark & Demonstration Results

**Run Timestamp**: 2026-11-01 05:06:31 UTC  
**Overall Verdict**: **FAIL** (FAIL (One or more gated PRD targets failed))

## Run Metadata

| Parameter | Value |
|---|---|
| **Log File** | `firex-30G.log` |
| **Log File Size** | 19,621,285,387 bytes (18712.32 MB) |
| **Bytes Ingested** | 19,621,285,387 bytes |
| **Events Count** | 37,183,090 |
| **Lines Count** | 37,183,090 |
| **Manifest File** | `firex-30G.log.manifest.json` |
| **Database Path** | `data\r30\run30.duckdb` |

## Pipeline Stage Breakdown

| Pipeline Stage | Duration | Details |
|---|---|---|
| **Ingest** | 440.26s | Parallel Parquet streaming (42.58 MB/s) |
| **Detection Engine** | 2012.65s | 429 raw firings (36 active, 393 suppressed, background-prevalence: 393) |
| **Incident Linking** | 147.39s | Graph component clustering & scoring (18 open, 0 leads) |
| **Reach Precomputation** | 0.07s | BFS target reach for 18 promoted incidents |
| **Total Analysis Time** | **2160.12s** | Detect + Link + Reach (Target: <= 950s) |
| **Ground-Truth Evaluation** | 1.42s | Manifest scoring (Completed) |
| **Latency Benchmark** | Measured | 18 incidents evaluated |
| **Total Processing Time** | **2600.37s** | Ingest + Analysis |
| **Peak Process Memory** | **4406.35 MB** | psutil full process tree RSS (Target: <= 8.0 GB) |

> [!NOTE]
> Path-open latency is measured in-process via FastAPI's `TestClient` over `GET /api/v1/incidents/{id}/path` across real incidents in the target database.

## PRD Scorecard

| Metric | PRD Good Threshold | PRD Great Threshold | Measured Value | Rating | Status |
|---|---|---|---|---|---|
| **Detection Rate** | `>= 70.0%` | `>= 90.0%` | 21.5% | **FAIL** | GATED |
| **Label Accuracy (Exact)** | `>= 60.0%` | `>= 85.0%` | 64.3% | **GOOD** | GATED |
| **Label Accuracy (Family)** | `>= 70.0%` | `>= 90.0%` | 100.0% | **GREAT** | INFO ONLY |
| **Path Rate** | `>= 50.0%` | `== 100.0%` | 44.8% | **FAIL** | GATED |
| **Order Accuracy** | `>= 50.0%` | `>= 85.0%` | NOT MEASURED | **NOT MEASURED** | INFO ONLY |
| **False Alarm Rate** | `<= 30.0%` | `<= 10.0%` | 0.0% | **GREAT** | GATED |
| **Processing Time (15GB)** | `<= 10,800s` | `<= 3,600s` | 2600.4s | **GREAT** | GATED |
| **Peak Memory (RSS)** | `<= 16,384 MB` | `<= 8,192 MB` | 4406.4 MB | **GREAT** | GATED |
| **Path-Open Latency (p50)** | `<= 2,000 ms` | `<= 500 ms` | 19.6 ms | **GREAT** | GATED |
| **Path-Open Latency (p95)** | `<= 3,000 ms` | `<= 1,000 ms` | 102.1 ms | **GREAT** | INFO ONLY |

## Notes & Threshold References
- **Gated Metrics**: The runner exits with status code `1` if any GATED metric fails to meet its **Good** target. If all gated metrics meet or exceed the Good target, it exits with status code `0`.
- **Info Only Metrics**: *Label Accuracy (Family)*, *Order Accuracy*, and *Path-Open Latency (p95)* are tracked as diagnostic indicators and do not affect the runner's exit code.
- **15 GB Processing Extrapolation**: For datasets smaller than 15 GiB, processing time is linearly extrapolated to a 15 GiB equivalent baseline for standard PRD comparison and marked as `[estimate]`.
- **Manifest Size Guard**: The evaluator verifies that actual log file bytes match the declared manifest `bytes`. If mismatched, the process exits with code `3` (unless `--skip-eval` is passed).

