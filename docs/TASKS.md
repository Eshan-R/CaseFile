# CaseFile Implementation Tasks

## Phase 1: Baseline Verification & Environment State
- [x] 1.1 Confirm actual manifest filename (`data/firex-30G.log.manifest.json`), data logs, and verify baseline test count (96 tests collected)
- [x] 1.2 Run existing test suite (`pytest`) and record pass/fail count
- [x] 1.3 Run linter (`ruff check`) and record status
- [x] 1.4 Inspect DuckDB database columns and types in `data/casefile.duckdb` (events view)
- [x] 1.5 Test rule execution against ingested data in DuckDB and identify remaining SQL/type errors
- [x] 1.6 Regenerate `docs/rule_stats.md` with baseline execution counts and runtimes
- [x] 1.7 Run ground-truth evaluator against `data/firex-30G.log.manifest.json` to capture baseline metrics (detection rate, label accuracy, path rate, false-alarm rate)
- [x] 1.8 Record baseline findings and metrics in TASKS.md
Result: Baseline verified. 96 tests passing (0 failing). `ruff check` passed cleanly. Manifest `firex-30G.log.manifest.json` evaluated: Detection Rate = 0.0% (0/65 planted steps), Incident Detection Rate = 0.0% (0/29 planted incidents), Path Rate = 0.0%, False Alarm Rate = 100.0% (2 our incidents, both unhit), Our Detections = 131. Ingest processing time = 201.91s, path-open latency = 2.58ms. `docs/rule_stats.md` shows 0 detections generated with 7 rules disabled due to missing `cmd` field. DuckDB events view verified with 9,125,383 rows.

## Phase 2: Fix Incident Linking (Highest Priority)
- [x] 2.1 Add `incident_link_window_seconds: int = 1800`, `incident_link_hub_threshold: int = 50`, and `incident_exclude_entities` list to `backend/app/config.py`
- [x] 2.2 Add `detection_count` and `risk_score` columns to DuckDB `incidents` table schema in `backend/app/store/duck.py`
- [x] 2.3 Implement single-query bulk entity extraction (`src_ip`, `dst_ip`, `user`, `event_id` count) in DuckDB excluding firewall device `devname`/`host` (`FGT60FTK00000000`), empty strings, and known infra IPs
- [x] 2.4 Implement hub entity filter capping entities appearing in > N detections from merging clusters
- [x] 2.5 Implement Union-Find (Disjoint-Set) clustering algorithm with time-gap rule: link detection when gap to the most recent detection sharing that entity is <= `incident_link_window_seconds`
- [x] 2.6 Remove hardcoded `limit=100_000` truncation on detection loading
- [x] 2.7 Implement incident promotion filter: only promote clusters with 2+ distinct tactics or corroborated high-severity (severity >= 8) detections to active incidents (`status="open"`), otherwise store as low-priority `status="alert"`
- [x] 2.8 Compute true `event_count` (sum of distinct raw events) and store `detection_count`
- [x] 2.9 Replace `except Exception: pass` around reach precompute with proper error logging and ensure incidents persist even if reach fails
- [x] 2.10 Update `Incident` Pydantic model in `backend/app/schemas/incident.py` to include `detection_count`
- [x] 2.11 Write comprehensive unit tests in `backend/tests/test_incident_linking.py` (within-window merge, time-separated non-merge, firewall host exclusion, hub capping, disjoint entities, transitive A-B-C chain, promotion filter)
- [x] 2.12 Run tests, run `ruff check`, and record Phase 2 outcome
Result: Phase 2 completed successfully. Added `incident_link_window_seconds`, `incident_link_hub_threshold`, and `incident_exclude_entities` to `config.py`. Implemented `get_detection_entities_bulk()` in DuckDB to eliminate N+1 queries. Implemented Union-Find clustering with temporal sliding window, hub capping, firewall host exclusion, and false-alarm promotion filtering. Added `detection_count` and `risk_score` to DuckDB schema and Pydantic models. Replaced silent exception swallowing with `logger.exception`. Added 9 comprehensive unit tests in `backend/tests/test_incident_linking.py`. All 105 tests pass; `ruff check` passes.

## Phase 3: Fix Attack Path Ordering
- [x] 3.1 Create shared `normalise_tactic(tactic: str) -> str` helper handling hyphens, underscores, spaces, and case normalization
- [x] 3.2 Update `_tactic_rank` in `backend/app/pipeline/path/path_builder.py` to use `normalise_tactic`
- [x] 3.3 Add `kill_chain_stage: str = ""` to `AttackStep` in `backend/app/schemas/incident.py`
- [x] 3.4 Populate `kill_chain_stage` on step objects in `backend/app/pipeline/link/incidents.py` and `path_builder.py`
- [x] 3.5 Sort attack steps chronologically by `first_seen` (matching evaluator sequence) with canonical kill-chain tactic rank as tie-break
- [x] 3.6 Write unit tests in `backend/tests/test_path_ordering.py` for every tactic used in `rules/detections.yaml` and verify chronological + tie-break ordering
- [x] 3.7 Run tests, run `ruff check`, and record Phase 3 outcome
Result: Phase 3 completed successfully. Created `normalise_tactic` which normalizes underscore, hyphen, space, and casing variants. Updated `_tactic_rank` in `path_builder.py`. Added `kill_chain_stage` to `AttackStep` and populated it on steps. Updated step ordering to be chronological by `first_seen` with tactic rank as tie-break. Created `backend/tests/test_path_ordering.py` verifying all 9 YAML tactics resolve valid ranks and ordering behavior. All 108 tests pass; `ruff check` passes.

## Phase 4: Detection Rules That Fit the Data
- [x] 4.1 Verify all target fields against `docs/format_samples.json` and DuckDB `events` columns (`sentbyte`, `rcvdbyte`, `bytes_out`, `bytes_in`, `dst_port`, `src_ip`, `dst_ip`, `attack`, `action`, etc.)
- [x] 4.2 Audit all rules in `rules/detections.yaml` against `docs/rule_stats.md` and catalogue disabled rules
- [x] 4.3 Update `backend/app/pipeline/detect/engine.py` to gracefully degrade when missing fields are encountered in `OR` branches with clear log warnings
- [x] 4.4 Update/add YAML rules in `rules/detections.yaml` matching real FortiGate signals from `docs/noise_profile.md` and `docs/data_profile.md`:
  - [x] 4.4.1 Brute-force bursts followed by success (`T1110`)
  - [x] 4.4.2 Port scans / network service discovery (`T1046`)
  - [x] 4.4.3 Large outbound data transfer (`T1048`) using verified byte fields (`bytes_out`, `sentbyte`)
  - [x] 4.4.4 Targeted high-severity IPS attack signatures (filtering out broad uniform noise from ~1,375 sources)
  - [x] 4.4.5 Administrative logins from external or unexpected IPs (`T1078`)
- [x] 4.5 Re-run detection engine across ingested data, regenerate `docs/rule_stats.md`, and record match counts
- [x] 4.6 Add unit tests in `backend/tests/test_detection_sql.py` and `backend/tests/test_phase4_rules.py` covering the updated rule compilation and execution
- [x] 4.7 Run tests, run `ruff check`, and record Phase 4 outcome
  - Result: All 14 detection rules now compile cleanly to set-based DuckDB SQL queries without syntax or binder errors. Missing columns degrade gracefully in OR branches or cleanly disable rules. Added unit test suite in `backend/tests/test_phase4_rules.py` asserting FortiGate signals (large transfers, SQLi/RCE, malware, DNS tunneling, remote logon, administrative logins) trigger rules. Regenerated `docs/rule_stats.md`. All 113 tests passed, ruff check clean.

## Phase 5: Reach Analysis from Real Data
- [x] 5.1 Update `backend/app/pipeline/path/reach/service.py` to compute reach per incident, restricted to that incident's entities and time window
- [x] 5.2 Extract reachability edges from observed *allowed* traffic (`action IN ('accept', 'allow', 'pass', 'allowed')`) in DuckDB events
- [x] 5.3 Incorporate port, protocol/service, and frequency counts into edge reasons (e.g. "allowed on tcp/445 seen 12 times")
- [x] 5.4 Retain `rules/assets.yaml` strictly for criticality matching patterns and manual overrides
- [x] 5.5 Update `backend/app/pipeline/path/reach/networkx_engine.py` to pass through detailed reach reasons to `ReachableTarget`
- [x] 5.6 Verify Neo4j engine option in `backend/app/pipeline/path/reach/neo4j_engine.py` remains functional
- [x] 5.7 Verify path-open latency is kept under 500 ms
- [x] 5.8 Write unit tests in `backend/tests/test_reach.py` with synthetic traffic tables to verify incident-scoped reachability and reason generation
- [x] 5.9 Run tests, run `ruff check`, and record Phase 5 outcome
  - Result: Scoped reach edge extraction to incident entities and time window. Extracted edges only from allowed traffic with human-readable reason strings (e.g. "allowed on smb/445 seen 12 times"). Removed hardcoded sample topology from `assets.yaml`. Added unit test in `test_reach.py` verifying allowed vs. denied traffic separation and latency under 500ms. All tests in `test_reach.py` passed, ruff clean.

## Phase 6: Risk Score and Report
- [x] 6.1 Enhance `backend/app/pipeline/path/risk.py` to compute dynamic risk scores based on tactic breadth, kill chain depth, asset criticality from reach, and detection volume
- [x] 6.2 Wire `score_incident` into `build_incidents()` in `backend/app/pipeline/link/incidents.py`
- [x] 6.3 Update `list_incidents` in `backend/app/store/duck.py` to sort incidents by `risk_score DESC`
- [x] 6.4 Expose `risk_score` in `/api/v1/incidents` responses and schema
- [x] 6.5 Update Markdown report template (`backend/app/pipeline/report/template.py`) to include risk score, detection count, true raw event count, and next reach section with reasons
- [x] 6.6 Write unit tests for risk scoring and report rendering in `backend/tests/test_risk_and_report.py`
- [x] 6.7 Run tests, run `ruff check`, and record Phase 6 outcome
  - Result: Composite dynamic risk score implemented with kill chain depth progression weights, tactic breadth bonus, asset criticality check, and detection volume scaling. Report template updated to include risk score, detection count, raw event count, and reach blast radius with reasons. Added unit test suite in `test_risk_and_report.py`. All tests passed, ruff check clean.

## Phase 7: UI and Packaging
- [x] 7.1 Add storage for last evaluation result in DuckDB stats and add `GET /api/v1/evaluation/latest` endpoint
- [x] 7.2 Update `backend/app/static/index.html`:
  - [x] 7.2.1 Incident list sorted by `risk_score` descending with badge
  - [x] 7.2.2 Display "N raw events merged into this incident" and detection count
  - [x] 7.2.3 Kill chain timeline displaying technique, tactic, kill chain stage, host, and time
  - [x] 7.2.4 Reach panel displaying reachable targets with formatted human-readable reasons
  - [x] 7.2.5 Header displaying evaluation metric badges (detection %, label accuracy %, false-alarm %) from `GET /api/v1/evaluation/latest`
- [x] 7.3 Create `.dockerignore` excluding `data/`, `.venv/`, `.pytest_cache/`, `__pycache__/`
- [x] 7.4 Verify and update `Dockerfile` (ensure `data/` is not copied) and `docker-compose.yml` (mounts `./data:/app/data`)
- [x] 7.5 Verify no remaining imports of root `pipeline/` package and delete duplicate `pipeline/` directory
- [x] 7.6 Update `README.md` Quick Start instructions with Docker Compose and local run steps
- [x] 7.7 Run tests, run `ruff check`, and record Phase 7 outcome
  - Result: Added `/api/v1/evaluate/latest` endpoint and DuckDB stats storage for evaluation metrics. Updated UI with risk score badges, raw event count badges, kill-chain timeline stages, reach reasons, and evaluation pill badges. Created `.dockerignore`, verified Docker volume mounting without copying `data/`, removed duplicate root `pipeline/` directory, and updated README. All 117 tests passed, ruff clean.

## Phase 8: Measure and Report
- [ ] 8.1 Measure processing time and peak memory (peak RSS) of a full ingest + analyse run
- [ ] 8.2 Execute `scripts/benchmark.py` and record API endpoint latencies (health, stats, events, detections, incidents, graph, path, reach)
- [ ] 8.3 Verify path-open latency is under 500 ms (PRD requires < 2,000 ms)
- [ ] 8.4 Run ground-truth evaluator against `data/firex-30G.log.manifest.json` and record final metrics:
  - Detection rate (Target: > 70%)
  - Label accuracy exact & family (Target: > 60%)
  - Path rate (Target: >= 50%)
  - False-alarm rate (Target: < 30%)
  - Peak memory usage (Target: < 16 GB)
- [ ] 8.5 Add "Results" section to `README.md` comparing baseline vs. final metrics
- [ ] 8.6 Update TASKS.md with final summary and verification status
