# One-Command Run and Scorecard Implementation Plan

## 1. Objective
Create an end-to-end one-command demonstration runner (`scripts/run_all.py`), Makefile target (`make demo`), and automated scorecard generator writing to `docs/RESULTS.md`. The runner will measure wall-clock times per pipeline stage, peak RSS memory across process trees using `psutil`, and p50/p95 path-open latencies over 50 real incidents. Any failure against PRD "Good" thresholds will exit non-zero for CI/judge visibility.

---

## 2. Architectural Design & Amendments

### 2.1 Isolated Database Execution
- `run_all.py` accepts `--db` (default: `data/run.duckdb`) and never resets the development database `data/casefile.duckdb` unless `--reset-dev` is explicitly passed.
- Sets `settings.duck_path = args.db` and configures an isolated parquet directory (`data/parquet_run`) to prevent interference with interactive development data.

### 2.2 Manifest Guard & `--skip-eval`
- **Manifest Guard**: Compares actual log file byte size against manifest `bytes`.
  - If mismatched: prints both the actual log size and declared manifest bytes with a clear explanation, and exits with code 3 (unless `--skip-eval` is set).
- **`--skip-eval` Flag**: Skips manifest evaluation entirely.
  - In terminal scorecard and `docs/RESULTS.md`, accuracy rows are marked `NOT MEASURED`.
  - Exit code is computed strictly from measured metrics (processing time, peak memory, path-open latency).

### 2.3 Stage Execution Pipeline
`scripts/run_all.py <log_path> <manifest_path> [--limit-bytes] [--db data/run.duckdb] [--reset-dev] [--skip-eval] [--serve] [--port 8000]`
1. **Memory Tracking**: Start background `psutil` process-tree monitor.
2. **Reset**: Reset target database (`args.db`).
3. **Ingest**: Stream-ingest `<log_path>` into DuckDB & Parquet partition layout (respecting `--limit-bytes`). Record wall-clock time and row counts.
4. **Analyse**:
   - Detection: execute YAML rules with SQL pushdown (`run_detection`).
   - Linking: cluster detections into incidents with hub-capping, RFC1918 host filtering, and promotion filters (`build_incidents`).
   - Reach: precompute reachability topology and blast radius (`precompute_reach_for_incident`).
5. **Evaluate** (unless `--skip-eval`):
   - Check file size against manifest `bytes`. If mismatched, print both numbers and exit 3.
   - Execute `evaluate_manifest(manifest_path, log_file_path=log_path)`.
6. **Path Latency Benchmark**:
   - Query up to 50 real incidents from the database.
   - Benchmark `GET /api/v1/incidents/{id}/path` in-process via FastAPI `TestClient`.
   - Calculate p50 and p95 latencies.
7. **Scorecard**:
   - Evaluate measured metrics against PRD Good and Great thresholds.
   - Compute 15 GB extrapolated processing time if input log < 15 GB (labelled as estimate).
   - Render ASCII table to terminal.
   - Write persistent report to `docs/RESULTS.md` noting that latency is measured in-process via `TestClient`.
   - Exit with code 1 if any gated PRD metric fails; exit 0 if all gated metrics are Good/Great.
8. **Optional Server**:
   - If `--serve` is passed, launch Uvicorn on specified port (default 8000).

---

### 2.4 PRD Targets, Gating, and Thresholds Catalog

| Metric | Target Direction | Good Threshold (Pass) | Great Threshold | Gating Status |
|---|---|---|---|---|
| **Detection Rate** | Higher is better | >= 70.0% | >= 90.0% | **GATED** (Exit 1 on Fail) |
| **Label Accuracy (Exact)** | Higher is better | >= 60.0% | >= 85.0% | **GATED** (Exit 1 on Fail) |
| **Path Rate** | Higher is better | >= 50.0% | == 100.0% | **GATED** (Exit 1 on Fail) |
| **False Alarm Rate** | Lower is better | <= 30.0% | <= 10.0% | **GATED** (Exit 1 on Fail) |
| **Processing Time (15GB)** | Lower is better | <= 10,800 s (3 hours) | <= 3,600 s (1 hour) | **GATED** (Exit 1 on Fail) |
| **Peak Memory (RSS)** | Lower is better | <= 16,384 MB (16 GB) | <= 8,192 MB (8 GB) | **GATED** (Exit 1 on Fail) |
| **Path-Open Latency (p50)** | Lower is better | <= 2,000 ms | <= 500 ms | **GATED** (Exit 1 on Fail) |
| *Label Accuracy (Family)* | Higher is better | >= 70.0% | >= 90.0% | *INFO ONLY* (Does not gate) |
| *Order Accuracy* | Higher is better | >= 50.0% | >= 85.0% | *INFO ONLY* (Does not gate) |
| *Path-Open Latency (p95)* | Lower is better | <= 3,000 ms | <= 1,000 ms | *INFO ONLY* (Does not gate) |

**Rating Logic**:
- If metric satisfies Great threshold -> `GREAT`
- Else if metric satisfies Good threshold -> `GOOD` / `PASS`
- Else -> `FAIL` (If the metric is GATED, exit with code 1)
- If `--skip-eval` is enabled, accuracy metrics show `NOT MEASURED` and only runtime/latency metrics are gated.

---

### 2.5 Processing Time Extrapolation Formula
- `measured_seconds`: wall-clock time for Ingest + Analyse.
- `log_size_bytes`: actual byte size of ingested file.
- If `log_size_bytes < 15 * 1024**3`:
  - `extrapolated_15gb_seconds = measured_seconds * (15 * 1024**3 / log_size_bytes)`
  - Displayed as: `124.5s (15 GB extrapolated: ~1,850s [estimate])`

---

### 2.6 Docker & Makefile Integration
- **Docker Compose**:
  - Main service named `casefile` (with alias `api`).
  - Volumes: `./data:/data`, `./data:/app/data`, `./rules:/app/rules`, `./knowledge:/app/knowledge`, `./scripts:/app/scripts`, `./docs:/app/docs`.
  - Working directory `/app` with `PYTHONPATH=/app/backend`.
  - Tested invocation: `docker compose run --rm casefile python scripts/run_all.py /data/<log> /data/<manifest>`.
- **Makefile**:
  - `demo` target invoking `scripts/run_all.py` with default `LOG` and `MANIFEST` variables.

---

## 3. Implementation Phases

- **Phase R1: Dependencies & Cross-Platform Metrics Tracker**
  - Add `psutil>=5.9.0` to `requirements.txt` and install into `.venv`.
  - Create `scripts/metrics_tracker.py` with `MemoryTracker` (psutil process-tree RSS, cross-platform) and `LatencyBenchmark` (in-process `TestClient` over 50 incidents).

- **Phase R2: One-Command Runner Script (`scripts/run_all.py`)**
  - CLI argument parsing (`log_path`, `manifest_path`, `--limit-bytes`, `--db`, `--reset-dev`, `--skip-eval`, `--serve`, `--port`).
  - Safe DB routing to `--db` (default `data/run.duckdb`), preserving dev DB.
  - Manifest size guard printing exact bytes mismatch and exiting code 3.
  - Sequential pipeline orchestration.

- **Phase R3: Scorecard Engine & `docs/RESULTS.md` Generation**
  - Metric gating logic: gate exit code only on the 7 PRD metrics; mark family accuracy, order accuracy, and p95 latency as INFO.
  - Compute 15 GB extrapolation if log < 15 GB.
  - Terminal ASCII table + write `docs/RESULTS.md` noting TestClient in-process measurement.

- **Phase R4: Refactor Existing Measurement & Makefile**
  - Update `scripts/measure_pipeline.py` to reuse `scripts/metrics_tracker.py` without `ctypes.wintypes`.
  - Add `demo` target to `Makefile`.

- **Phase R5: Docker Support for One-Command Run**
  - Update `Dockerfile` to copy `scripts/` and set `WORKDIR /app`.
  - Update `docker-compose.yml` to define service `casefile` with `./data:/data` and `./data:/app/data`.

- **Phase R6: Documentation & Final Verification**
  - Update `README.md` with one-command flow (`make demo`, `docker compose`, manual 7-step), updated PRD targets table matching `RESULTS.md`, and updated third-party table.
  - Run full test suite and verify `run_all.py` execution.
