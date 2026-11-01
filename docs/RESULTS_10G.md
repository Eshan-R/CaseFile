# CaseFile Benchmark & Demonstration Results

**Run Timestamp**: 2026-11-01 04:03:53 UTC  
**Overall Verdict**: **PASS** (PASS (All gated PRD targets met))

## Run Metadata

| Parameter | Value |
|---|---|
| **Log File** | `firex-10G.log` |
| **Log File Size** | 6,543,120,032 bytes (6240.01 MB) |
| **Bytes Ingested** | 4,815,700,626 bytes |
| **Events Count** | 9,125,383 |
| **Lines Count** | 9,125,474 |
| **Manifest File** | `SKIPPED (--skip-eval)` |
| **Database Path** | `data/run.duckdb` |

## Pipeline Stage Breakdown

| Pipeline Stage | Duration | Details |
|---|---|---|
| **Ingest** | 97.74s | Parallel Parquet streaming (47.07 MB/s) |
| **Detection Engine** | 74.65s | 427 raw firings (38 active, 389 suppressed, background-prevalence: 389) |
| **Incident Linking** | 7.40s | Graph component clustering & scoring (17 open, 0 leads) |
| **Reach Precomputation** | 0.03s | BFS target reach for 17 promoted incidents |
| **Total Analysis Time** | **82.08s** | Detect + Link + Reach (Target: <= 950s) |
| **Ground-Truth Evaluation** | 0.00s | Manifest scoring (Skipped) |
| **Latency Benchmark** | Measured | 17 incidents evaluated |
| **Total Processing Time** | **179.81s** | Ingest + Analysis |
| **Peak Process Memory** | **4550.56 MB** | psutil full process tree RSS (Target: <= 8.0 GB) |

> [!NOTE]
> Path-open latency is measured in-process via FastAPI's `TestClient` over `GET /api/v1/incidents/{id}/path` across real incidents in the target database.

## PRD Scorecard

| Metric | PRD Good Threshold | PRD Great Threshold | Measured Value | Rating | Status |
|---|---|---|---|---|---|
| **Detection Rate** | `>= 70.0%` | `>= 90.0%` | NOT MEASURED | **NOT MEASURED** | INFO (SKIPPED) |
| **Label Accuracy (Exact)** | `>= 60.0%` | `>= 85.0%` | NOT MEASURED | **NOT MEASURED** | INFO (SKIPPED) |
| **Label Accuracy (Family)** | `>= 70.0%` | `>= 90.0%` | NOT MEASURED | **NOT MEASURED** | INFO (SKIPPED) |
| **Path Rate** | `>= 50.0%` | `== 100.0%` | NOT MEASURED | **NOT MEASURED** | INFO (SKIPPED) |
| **Order Accuracy** | `>= 50.0%` | `>= 85.0%` | NOT MEASURED | **NOT MEASURED** | INFO (SKIPPED) |
| **False Alarm Rate** | `<= 30.0%` | `<= 10.0%` | NOT MEASURED | **NOT MEASURED** | INFO (SKIPPED) |
| **Processing Time (15GB)** | `<= 10,800s` | `<= 3,600s` | 601.4s (15 GB extrapolated: ~601s [estimate]) | **GREAT** | GATED |
| **Peak Memory (RSS)** | `<= 16,384 MB` | `<= 8,192 MB` | 4550.6 MB | **GREAT** | GATED |
| **Path-Open Latency (p50)** | `<= 2,000 ms` | `<= 500 ms` | 9.3 ms | **GREAT** | GATED |
| **Path-Open Latency (p95)** | `<= 3,000 ms` | `<= 1,000 ms` | 36.7 ms | **GREAT** | INFO ONLY |

## Notes & Threshold References
- **Gated Metrics**: The runner exits with status code `1` if any GATED metric fails to meet its **Good** target. If all gated metrics meet or exceed the Good target, it exits with status code `0`.
- **Info Only Metrics**: *Label Accuracy (Family)*, *Order Accuracy*, and *Path-Open Latency (p95)* are tracked as diagnostic indicators and do not affect the runner's exit code.
- **15 GB Processing Extrapolation**: For datasets smaller than 15 GiB, processing time is linearly extrapolated to a 15 GiB equivalent baseline for standard PRD comparison and marked as `[estimate]`.
- **Manifest Size Guard**: The evaluator verifies that actual log file bytes match the declared manifest `bytes`. If mismatched, the process exits with code `3` (unless `--skip-eval` is passed).


## SILVER (agreement, not ground truth)

> [!IMPORTANT]
> **SILVER STANDARD: agreement with independent SQL oracles on firex-10G.log. No organizer ground truth exists for this file. Not a measure of true accuracy.**

| Metric | Target (Good) | Target (Great) | Measured Value | Rating | Status |
|---|---|---|---|---|---|
| **Total Merged Behaviors** | `INFO` | `INFO` | 27 behaviors | **INFO** | INFO ONLY |
| **Behavior Recall** | `INFO` | `INFO` | 96.3% (26 / 27) | **INFO** | INFO ONLY |
| **Oracle Rows (Raw)** | `INFO` | `INFO` | 79 rows | **INFO** | INFO ONLY |
| **Row Recall** | `INFO` | `INFO` | 53.2% (42 / 79) | **INFO** | INFO ONLY |
| **Silver Precision Proxy (Detection-Level)** | `INFO` | `INFO` | 94.7% (36 / 38) | **INFO** | INFO ONLY |
| **Silver Precision Proxy (Behavior-Level)** | `INFO` | `INFO` | 96.5% (28 / 29) | **INFO** | INFO ONLY |
| **Exact Label Agreement** | `INFO` | `INFO` | 97.2% | **INFO** | INFO ONLY |
| **Family Label Agreement** | `INFO` | `INFO` | 97.2% | **INFO** | INFO ONLY |
| **Multi-Class Incidents** | `INFO` | `INFO` | 3 (3 shared) | **INFO** | INFO ONLY |
| **Tactic Ordering Agreement** | `INFO` | `INFO` | 1 / 3 (33.3%) | **INFO** | INFO ONLY |

### Per-Class Oracle Breakdown (Rows & Behaviors)

| Oracle Class | Oracle Rows | Row Matched | Row Recall | Behaviors | Beh Matched | Beh Recall | Exact Acc | Family Acc |
|---|---|---|---|---|---|---|---|---|
| `admin_success` | 5 | 5 | 100.0% | 3 | 3 | 100.0% | 85.7% | 85.7% |
| `beacon` | 1 | 1 | 100.0% | 1 | 1 | 100.0% | 100.0% | 100.0% |
| `config_change` | 5 | 5 | 100.0% | 5 | 5 | 100.0% | 57.1% | 57.1% |
| `dns_tunnel` | 1 | 1 | 100.0% | 1 | 1 | 100.0% | 100.0% | 100.0% |
| `failed_admin_burst` | 1 | 0 | 0.0% | 1 | 0 | 0.0% | N/A | N/A |
| `lateral_fanout` | 43 | 7 | 16.3% | 3 | 3 | 100.0% | 77.8% | 100.0% |
| `port_scan` | 2 | 2 | 100.0% | 2 | 2 | 100.0% | 100.0% | 100.0% |
| `slow_stuffing_24` | 2 | 2 | 100.0% | 1 | 1 | 100.0% | 100.0% | 100.0% |
| `staged_exfil` | 2 | 2 | 100.0% | 2 | 2 | 100.0% | 100.0% | 100.0% |
| `virus_detected_not_blocked` | 3 | 3 | 100.0% | 1 | 1 | 100.0% | 100.0% | 100.0% |
| `vpn_impossible_travel` | 6 | 6 | 100.0% | 2 | 2 | 100.0% | 100.0% | 100.0% |
| `web_payload` | 8 | 8 | 100.0% | 5 | 5 | 100.0% | 100.0% | 100.0% |

### Top 5 Unconfirmed Detection Rules (Precision Proxy)

| Rule ID | Unconfirmed Firings |
|---|---|
| `web-shell-upload-path` | 2 |

### Suppressed Population Windows

| Oracle | Window Start | Duration | Tripping Entities | Active Entities | Ratio | Status |
|---|---|---|---|---|---|---|
| `failed_admin_burst` | 2026-10-30T03:10:00+00:00 | 600s | 157 | 1 | 0.0% | **SUPPRESSED** (Population Artifact) |
| `flood` | 2026-10-30T03:18:00+00:00 | 120s | 231 | 15 | 1540.0% | **SUPPRESSED** (Population Artifact) |

### Technique Confusion Breakdown (Active vs Matched Oracles)

| Oracle Class | Expected Technique | Emitted Technique | Firing Count |
|---|---|---|---|
| `config_change` | `T1098` | `T1562.002` | 1 |

### Incident Review Table & Verification

> Full review table with entity sequences, tactic progression, and chain checks is published in [INCIDENT_TABLE.md](INCIDENT_TABLE.md).

