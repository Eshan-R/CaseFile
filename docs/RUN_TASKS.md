# One-Command Run and Scorecard Implementation Tasks

## Phase R1: Dependencies & Cross-Platform Metrics Tracker
- [x] R1.1 Add `psutil>=5.9.0` to `requirements.txt` and install into `.venv`
  *Result: Installed psutil-7.2.2 and google-genai-2.34.0, added to requirements.txt.*
- [x] R1.2 Implement `scripts/metrics_tracker.py` with `MemoryTracker` (psutil, process tree RSS, Windows/Linux compatible, zero `ctypes.wintypes`)
  *Result: MemoryTracker implemented with background thread sampling process tree RSS via psutil without wintypes.*
- [x] R1.3 Add path-open latency benchmark helper in `scripts/metrics_tracker.py` measuring p50 and p95 over up to 50 real incidents via HTTP
  *Result: benchmark_path_latency helper created measuring in-process GET /incidents/{id}/path via TestClient.*
- [x] R1.4 Verify `metrics_tracker.py` with a standalone unit test
  *Result: backend/tests/test_metrics_tracker.py passed (2 tests), ruff clean.*

## Phase R2: One-Command Runner (`scripts/run_all.py`)
- [x] R2.1 Create `scripts/run_all.py` with CLI arguments `<log_path> <manifest_path> [--limit-bytes] [--db] [--reset-dev] [--skip-eval] [--serve] [--port]`
  *Result: CLI argument parser implemented with all flags and defaults.*
- [x] R2.2 Implement isolated database configuration (`--db data/run.duckdb` default) protecting `data/casefile.duckdb` unless `--reset-dev` is passed, and stage 1: reset target DB
  *Result: Default target DB set to data/run.duckdb with isolated parquet_run, guarded against overwriting dev db.*
- [x] R2.3 Implement stage 2: log ingestion with wall-clock timing and row counting (supporting `--limit-bytes`)
  *Result: Ingestion executed via run_ingest with timing, event counts, and MB/s reporting.*
- [x] R2.4 Implement stage 3: analysis pipeline (detection + incident linking + reach precomputation) with wall-clock timing
  *Result: Rule detection, Union-Find incident linking, and reach precomputation executed with stage duration tracking.*
- [x] R2.5 Implement stage 4: ground-truth evaluation with manifest size/byte guard (aborts with code 3 on mismatch, unless `--skip-eval`)
  *Result: Manifest size guard verifies byte equality, prints mismatch with both sizes, and exits code 3. Evaluator skipped when --skip-eval is passed.*
- [x] R2.6 Implement stage 5: path-open latency measurement on real database (p50/p95 over 50 incidents in-process via TestClient)
  *Result: Measured p50=63.4ms, p95=77.8ms via TestClient across real database incidents.*
- [x] R2.7 Implement optional `--serve` mode to launch Uvicorn after scorecard output
  *Result: --serve starts Uvicorn on specified port.*

## Phase R3: Scorecard & `docs/RESULTS.md` Generation
- [x] R3.1 Implement PRD threshold comparison logic assigning `PASS`/`GOOD`/`GREAT`/`FAIL` per metric, with Path Rate Great at 100%, and 15 GB extrapolation estimate for logs < 15 GB
  *Result: Rating algorithm evaluates 10 PRD metrics with 100% path-rate Great threshold and linear 15 GB time extrapolation.*
- [x] R3.2 Render formatted terminal scorecard table with stage breakdown, gating only the 7 PRD metrics (family label accuracy, order accuracy, p95 latency as INFO only; `--skip-eval` marks accuracy as NOT MEASURED)
  *Result: Console scorecard printed with GATED vs INFO status and clear PRD targets.*
- [x] R3.3 Generate markdown scorecard in `docs/RESULTS.md` recording date, log file name, size, row counts, stage timings, in-process TestClient notice, and scorecard table
  *Result: docs/RESULTS.md auto-generated with callouts, metadata, stage breakdown, and results table.*
- [x] R3.4 Ensure script exits with non-zero status code if any gated "Good" target fails (exit code 1)
  *Result: Verified exit code 1 when any gated threshold fails, code 0 when all pass, and code 3 on manifest mismatch.*

## Phase R4: Refactor Existing Measurement & Makefile
- [x] R4.1 Update `scripts/measure_pipeline.py` to eliminate `ctypes.wintypes` and reuse `metrics_tracker.py`
  *Result: Rewrote measure_pipeline.py and profile_sample.py to use psutil and metrics_tracker, completely removing ctypes.wintypes.*
- [x] R4.2 Add `demo` target to `Makefile` with customizable `LOG` and `MANIFEST` variables
  *Result: Added demo target in Makefile with customizable $(LOG) and $(MANIFEST).*

## Phase R5: Docker Support for One-Command Run
- [x] R5.1 Update `Dockerfile` to include `COPY scripts/ ./scripts/`, set `WORKDIR /app`, and set `PYTHONPATH=/app/backend`
  *Result: Dockerfile updated with scripts directory, WORKDIR /app, and app-dir backend for uvicorn.*
- [x] R5.2 Update `docker-compose.yml` to define service `casefile` with `./data:/data` and `./data:/app/data` volumes
  *Result: Configured casefile service and api alias with ./data:/data, ./data:/app/data, ./docs:/app/docs, and scripts volume mounts.*
- [x] R5.3 Validate Docker run command syntax: `docker compose run --rm casefile python scripts/run_all.py /data/<log> /data/<manifest>`
  *Result: Validated compose syntax and entrypoint alignment.*

## Phase R6: Documentation & Final Verification
- [x] R6.1 Update `README.md` CLI section with one-command flow (`make demo`, `docker compose`, manual 7-step list)
  *Result: Replaced CLI section with make demo, docker compose, and manual 7-step flow.*
- [x] R6.2 Update `README.md` targets table to match `RESULTS.md` Good/Great thresholds
  *Result: Aligned PRD targets table with exact thresholds, directions, and GATED vs INFO status.*
- [x] R6.3 Update `README.md` third-party components table (vendored Cytoscape/Dagre zero-CDN, Gemini provider, psutil)
  *Result: Updated Cytoscape.js/Dagre to locally vendored 3.30.2/0.8.5, psutil>=5.9.0, google-genai>=2.0.0, and multi-provider LLM description.*
- [x] R6.4 Run full pytest suite and ruff checks across the codebase
  *Result: 145 passed, 5 skipped, 0 failures in pytest; ruff check clean across all files.*
- [x] R6.5 Execute `scripts/run_all.py` on test data and inspect generated `docs/RESULTS.md`
  *Result: Verified execution on test data with --skip-eval; validated docs/RESULTS.md generation, in-process TestClient notice, and exit codes.*
- [x] R6.6 Update `docs/RUN_TASKS.md` with final verification results
  *Result: All phases R1-R6 completed and verified.*

