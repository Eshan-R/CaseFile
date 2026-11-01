# CaseFile Implementation Plan

This implementation plan details the architectural analysis, problem statements, target files, approaches, verification strategies, and risk mitigations for the CaseFile security log analysis system across all 8 phases.

---

## Phase 1: Baseline Verification & Environment State

### Problem Statement
The system's current baseline performance and state must be recorded before making code modifications. `docs/rule_stats.md` currently reflects historical binder errors (e.g. `-(VARCHAR, INTERVAL)` and `time_bucket(INTERVAL, VARCHAR)`) and missing `user_name` columns resulting in 0 detections. We need to verify which errors persist, run the full test suite, confirm the real manifest filename and baseline test counts, execute rule detection on ingested data, regenerate `docs/rule_stats.md`, and record baseline evaluator metrics if possible.

### Files Touched
- `docs/rule_stats.md`
- `docs/TASKS.md`

### Approach
1. Confirm actual filenames: verify `data/firex-30G.log.manifest.json`, `data/firex-10G.log`, `data/sample.log`, and `data/parquet/_manifest.json`.
2. Execute the existing pytest suite using `.venv\Scripts\python.exe -m pytest` and record exact passing/failing tests (verified: 96 tests collected).
3. Run `ruff check` to ensure baseline linting is satisfied.
4. Check the existing DuckDB database (`data/casefile.duckdb`). Inspect events table columns and schema (confirming presence of both normalized and raw FortiGate columns: `src_ip`, `dst_ip`, `srcport`, `dstport`, `sentbyte`, `rcvdbyte`, `bytes_out`, `bytes_in`, `attack`, `logid`, `action`, etc.).
5. Run rule detection using `cli.py analyse` or direct engine execution to evaluate the current rules against existing data in `data/casefile.duckdb`.
6. Check if any SQL binder errors or missing column errors remain; verify whether `TRY_CAST(ts AS TIMESTAMPTZ)` and `_entity_expr` in `backend/app/pipeline/detect/engine.py` resolved previous failures.
7. Regenerate `docs/rule_stats.md` and capture the starting baseline.
8. Attempt baseline evaluation using `cli.py evaluate --manifest data/firex-30G.log.manifest.json` and record baseline detection rate, label accuracy, path rate, and false-alarm rate.

### Verification Strategy
- Real baseline test count and manifest filename confirmed.
- `docs/rule_stats.md` updated with fresh runtime and match statistics without unhandled DuckDB crashes.
- Baseline metrics documented in `docs/TASKS.md`.

### Risks & Mitigations
- *Risk*: DuckDB database lock if another process is holding `data/casefile.duckdb`.
  *Mitigation*: Ensure connections are properly closed using `duck.close()` context managers and verify no background server is locking the file.
- *Risk*: Manifest file size mismatch if evaluating with `--log-file`.
  *Mitigation*: Evaluate against already-ingested DuckDB events without passing `--log-file` if checking database detections against ground truth.

---

## Phase 2: Fix Incident Linking (Highest Priority)

### Problem Statement
`backend/app/pipeline/link/incidents.py` is supposed to merge detections by shared host or IP within a 30-minute window. However, the current code only compares `last["host"] == det["host"]`. In FortiGate firewall logs, all events share the identical firewall hostname (`devname="FGT60FTK00000000"`). As a result, all detections across the entire dataset collapse into 1 or 2 mega-incidents.
Additionally:
- Entity extraction runs N+1 queries (`duck.list_events(detection_id=det["detection_id"], limit=50)`) inside a Python loop, severely degrading performance and undercounting true event counts due to `limit=50`.
- Detections are truncated by a hardcoded `limit=100_000`.
- True event counts and detection counts are not persisted accurately.
- Reach precomputation silently suppresses failures with `except Exception: pass`.
- Without an incident promotion filter, false-alarm clusters dilute genuine attack campaigns.

### Files Touched
- `backend/app/config.py`
- `backend/app/pipeline/link/incidents.py`
- `backend/app/store/duck.py`
- `backend/app/schemas/incident.py`
- `backend/tests/test_incident_linking.py` (new test file)

### Approach
1. **Configuration**:
   - Add to `backend/app/config.py`:
     - `incident_link_window_seconds: int = 1800` (30 minutes)
     - `incident_link_hub_threshold: int = 50` (hub cap: entities appearing in > N detections are barred from merging)
     - `incident_exclude_entities: list[str] = ["FGT60FTK00000000", "10.10.99.1", "127.0.0.1", "8.8.8.8", "0.0.0.0", "unknown"]`
2. **Bulk Entity & Event Query**:
   - Replace the N+1 loop with a single aggregated DuckDB SQL query joining `detection_events` and `events`.
   - Extract distinct `src_ip`, `dst_ip`, `user` (coalesced from `user`, `user_name`, `user_raw`), and true count of distinct `event_id` per detection.
   - Strictly exclude the firewall device `devname`/`host` (`FGT60FTK00000000`), empty strings, and known infrastructure IPs (gateway `10.10.99.1`, DNS `8.8.8.8`, loopback).
3. **Hub Cap & Entity Frequency**:
   - Count detections per entity across the dataset. Any entity appearing in more than `incident_link_hub_threshold` detections is marked as a hub and excluded from merging to prevent artificial super-clusters.
4. **Union-Find Clustering with Sliding Time Gap**:
   - Implement Disjoint-Set (Union-Find) with path compression and rank.
   - Paging/streaming: Remove `limit=100_000` truncation. Query detections sorted chronologically by timestamp `ts`.
   - Time rule: Link detection D to an existing cluster sharing entity E if and only if:
     `D.ts - last_seen_for_entity[E] <= incident_link_window_seconds`.
   - Update `last_seen_for_entity[E] = D.ts` as the sliding window progresses.
   - Support transitive merging across distinct non-hub entities (e.g. A shares IP with B, B shares User with C within the time window).
5. **Incident Promotion Filter (False-Alarm Control)**:
   - Only promote a cluster to an `incident` (`status="open"`) if:
     - It contains 2+ distinct MITRE ATT&CK tactics, OR
     - It contains at least one high-severity detection (severity >= 8) with corroborating evidence (multiple detections or multiple events).
   - Clusters that do not meet promotion criteria are marked as low-priority alerts (`status="alert"`) so they do not pollute incident views or degrade false-alarm evaluation metrics.
6. **Incident Aggregation & Schema**:
   - Store true `event_count` (sum of distinct raw events across all linked detections) and `detection_count` (number of detections in the incident).
   - Update DuckDB schema for `incidents` table to support `detection_count` and `risk_score`.
   - Update `app/schemas/incident.py` to include `detection_count: int` and `risk_score: float`.
7. **Robust Error Handling**:
   - Replace `except Exception: pass` around `precompute_reach_for_incident` with `logger.exception("Failed to precompute reach for incident %s", inc_id)`.
   - Ensure incident insertion and detection linking succeed regardless of reach precompute status.

### Verification Strategy
- Pytest unit tests in `backend/tests/test_incident_linking.py`:
  1. Detections sharing an entity within 1800s merge into one incident.
  2. Firewall devname (`FGT60FTK00000000`) is never used to link detections.
  3. Hub entities appearing in > hub_threshold detections are excluded from linking.
  4. Time-gap check: gap to the most recent detection sharing that entity > 1800s keeps detections separate.
  5. Transitive chain: Det 1 (IP 1) links with Det 2 (IP 1 + User X), and Det 2 links with Det 3 (User X) within window -> all 3 form 1 incident.
  6. Promotion filter: single-tactic low-severity cluster stored as `alert`, multi-tactic or corroborated high-severity cluster promoted to `open` incident.
  7. Correct `event_count` and `detection_count` persisted.
  8. Reach precomputation failure logs an error without preventing incident creation.

### Risks & Mitigations
- *Risk*: Legitimate high-volume lateral movement IPs being capped out by the hub threshold.
  *Mitigation*: Configure `incident_link_hub_threshold` with a sensible default (50) and allow environment override via `config.py`.

---

## Phase 3: Fix Attack Path Ordering

### Problem Statement
`backend/app/pipeline/path/path_builder.py` ranks tactics using `_TACTIC_ORDER` with hyphens (`credential-access`, `lateral-movement`), while rules define tactics with underscores (`credential_access`, `lateral_movement`).
Furthermore:
- The evaluator in `evaluator.py` checks chronological execution of planted steps within ground-truth time windows (`st_start <= d_ts < st_end`). Real attacks unfold in time order.
- Attack steps lack `kill_chain_stage` in `incidents.py`, `path_builder.py`, and `app/schemas/incident.py`.

### Files Touched
- `backend/app/pipeline/path/path_builder.py`
- `backend/app/pipeline/link/incidents.py`
- `backend/app/schemas/incident.py`
- `backend/tests/test_path_ordering.py` (new test file)

### Approach
1. **Evaluator-Aligned Ordering Strategy**:
   - Per evaluator analysis, ground truth stages are sequenced chronologically in time.
   - Primary sort: `first_seen` (timestamp).
   - Secondary sort (tie-break for simultaneous detections): Canonical kill-chain tactic rank (`_tactic_rank`).
2. **Shared Tactic Normalisation**:
   - Create a shared helper function `normalise_tactic(tactic: str) -> str` that lowercases, trims whitespace, and replaces underscores and spaces with hyphens (e.g. `credential_access` -> `credential-access`).
   - Use `normalise_tactic` in `_tactic_rank` and wherever tactics are indexed or compared.
3. **Expose Kill Chain Stage**:
   - Update `AttackStep` in `app/schemas/incident.py` to include `kill_chain_stage: str = ""`.
   - When constructing `steps` in `incidents.py` and `path_builder.py`, extract `kill_chain_stage` from the detection record and populate each step.
4. **Tactic Validation**:
   - Inspect all tactic values present in `rules/detections.yaml` and verify that `_tactic_rank` correctly resolves every single one to its proper kill chain position.

### Verification Strategy
- Pytest unit tests in `backend/tests/test_path_ordering.py`:
  1. Test `normalise_tactic` handles spaces, hyphens, underscores, uppercase, and whitespace.
  2. Verify all tactics from `rules/detections.yaml` resolve before `len(_TACTIC_ORDER)`.
  3. Verify ordering is chronological by `first_seen`, with tactic rank breaking ties.
  4. Verify `kill_chain_stage` is populated and present on every step.

### Risks & Mitigations
- *Risk*: Simultaneous events from different steps having ambiguous ordering.
  *Mitigation*: Tactic kill chain order cleanly breaks ties for simultaneous detections.

---

## Phase 4: Detection Rules That Fit the Data

### Problem Statement
`docs/rule_stats.md` shows 0 detections generated, with many rules marked "Disabled (missing field)" because they check endpoint/host fields (`cmd`, `useradd`, `net user`, `schtasks`, `wevtutil`) that do not exist in network firewall logs.
Furthermore, FortiGate firewall logs contain rich, distinct signals:
- Brute-force bursts followed by successful login (`0100032002` failed admin login burst followed by `0100032001` success or VPN logon).
- Port scans and IP sweeps (high distinct destination ports/IPs within short time windows).
- Large outbound data exfiltration (`bytes_out` / `sentbyte > 10MB` with `action: accept`).
- Repeated IPS attack signatures (`utm` / `ips`). Note: `docs/noise_profile.md` shows IPS signatures appear across ~1,375 sources as broad background noise; rules must NOT fire on uniform noise.
- Admin logins from external/untrusted IPs.
Additionally:
- Field names must be verified against `docs/format_samples.json` and actual DuckDB columns (`sentbyte`, `rcvdbyte`, `dst_port`, `src_ip`, `dst_ip`, `attack`, `action`, etc.).

### Files Touched
- `rules/detections.yaml`
- `backend/app/pipeline/detect/engine.py`
- `docs/rule_stats.md`
- `backend/tests/test_detection_sql.py`

### Approach
1. **Field Verification**:
   - Verified columns in DuckDB `events` view: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `bytes_out`, `bytes_in`, `sentbyte`, `rcvdbyte`, `attack`, `attackid`, `action`, `outcome`, `status`, `subtype`, `type`, `service`, `app`, `proto`, `user`, `host`.
   - Rules must use verified fields supported by FortiGate schema.
2. **Graceful Field Degradation**:
   - In `backend/app/pipeline/detect/engine.py`, enhance `compile_rule_to_sql`:
     - If a missing field is referenced in a disjunction (`OR` condition), log an informative warning and rewrite that condition branch to `FALSE` rather than disabling the entire rule.
     - If a missing field is required in a mandatory condition (`AND` condition or root), log a clear explanation: `"Rule '%s' requires missing column '%s'; rule degraded/disabled."`
3. **Align Rules with Real FortiGate Data**:
   - Keep all rules strictly in YAML (`rules/detections.yaml`), no hard-coded rules in Python.
   - Refactor existing rules:
     - `brute-force-then-success`: Failed login burst (`logid='0100032002'` or `action='login'` and `outcome='failure'`) followed within 600s by successful login (`logid='0100032001'` or `status='success'`).
     - `network-service-discovery`: Group by `src_ip`, count distinct `dst_port` or connections >= 30 within 300s window.
     - `large-outbound-transfer`: Traffic logs with `action = 'accept'` and `(bytes_out > 10485760 OR sentbyte > 10485760)`.
     - `targeted-ips-attack`: Filter out uniform noise; fire only on repeated high-severity IPS attacks from a source targeting specific internal destinations with distinct attack count or known severe signatures (e.g. Cobalt Strike, Log4j, ZeroLogon).
     - `admin-external-login`: Successful admin logins (`action = 'login'` or `subtype = 'vpn'`) from non-RFC1918 source IPs.
4. **Regenerate Statistics**:
   - Execute detection against the ingested database and write updated stats to `docs/rule_stats.md`.

### Verification Strategy
- Pytest tests validating SQL compilation of all rules in `rules/detections.yaml`.
- Run rule execution on `data/casefile.duckdb` and confirm non-zero detection counts in `docs/rule_stats.md`.
- Ensure zero SQL syntax or binder exceptions.

### Risks & Mitigations
- *Risk*: A threshold rule over millions of rows could run slowly if joining without indexes.
  *Mitigation*: Use time bucket aggregations and partition-friendly DuckDB SQL queries with bounded time intervals.

---

## Phase 5: Reach Analysis from Real Data

### Problem Statement
`rules/assets.yaml` defines a hardcoded static network topology (`web-server`, `app-server`, `db-server`), which does not reflect the real network environment observed in the logs.
In reality:
- Allowed network traffic (`src_ip` to `dst_ip`, `dst_port`, `service`, `action = 'accept'`) in the `events` table shows actual reachability.
- Reach should be computed per incident, restricted to that incident's entities and time window, rather than scanning the entire events table.
- Path-open latency must stay under 500 ms (well below the 2,000 ms PRD threshold).
- "Could reach next" predictions must provide descriptive reasons (e.g. "allowed on tcp/445 seen 12 times").
- Neo4j engine option must remain functional alongside the default NetworkX engine.

### Files Touched
- `rules/assets.yaml`
- `backend/app/pipeline/path/reach/assets.py`
- `backend/app/pipeline/path/reach/service.py`
- `backend/app/pipeline/path/reach/networkx_engine.py`
- `backend/app/pipeline/path/reach/neo4j_engine.py`
- `backend/tests/test_reach.py`

### Approach
1. **Incident-Scoped Edge Extraction**:
   - In `backend/app/pipeline/path/reach/service.py`:
     - Scope edge queries to the incident's compromised entities (`hosts`, `src_ips`, `dst_ips`, `users`) and the relevant temporal window (+/- buffer around `first_seen` and `last_seen`).
     - Query allowed traffic: `action IN ('accept', 'allow', 'pass', 'allowed')`.
     - Aggregate connections by `(src_ip, dst_ip, dst_port, service)` with count, max timestamp, and sample event IDs.
     - Format reason strings dynamically: e.g. `"allowed on tcp/{dst_port} ({service}) seen {count} times"`.
2. **Role of `rules/assets.yaml`**:
   - Retain `rules/assets.yaml` solely for:
     - Substring patterns matching critical assets (e.g. `dc`, `ad`, `sql`, `db`, `fs`, `backup`).
     - Explicit critical hosts/IPs list.
     - Criticality configuration (e.g. `auto_critical_admin_pct`).
   - Deprecate hardcoded `hosts:` topology.
3. **Graph Construction & Reason Generation**:
   - In `networkx_engine.py`:
     - Incorporate dynamic port/service reasons into `G.add_edge(...)`.
     - When constructing `ReachableTarget`, populate `reason` using the incoming allowed traffic details.
4. **Preserve Neo4j Engine**:
   - Ensure `Neo4jEngine` interface and query structure accept the enriched edge dictionaries without breaking.
5. **Path-Open Latency**:
   - Precompute reach during incident linking and store in `incident_next`, ensuring API reads remain < 100 ms (well under the 500 ms target).

### Verification Strategy
- Pytest tests in `test_reach.py` verifying:
  1. Denied/blocked traffic is not included in reachability edges.
  2. Edge extraction queries are scoped to incident entities and time window.
  3. Reach reasons specify port, protocol/service, and count.
  4. Critical assets are identified using pattern matching from `rules/assets.yaml`.
  5. API latency for path and reach endpoints stays under 500 ms.

### Risks & Mitigations
- *Risk*: An incident with an external IP could touch too many external destinations.
  *Mitigation*: Scope reachable expansion to internal RFC1918 subnets and critical assets.

---

## Phase 6: Risk Score and Report

### Problem Statement
Currently, incident risk scoring in `backend/app/pipeline/path/risk.py` uses a primitive technique lookup table and is not persisted or integrated into the incident pipeline. Incident lists are sorted only by timestamp, not risk.
Furthermore:
- The Markdown report template (`backend/app/pipeline/report/template.py`) lacks the composite risk score, detection count, true event count, and "Next Reach" blast radius summary.

### Files Touched
- `backend/app/pipeline/path/risk.py`
- `backend/app/pipeline/link/incidents.py`
- `backend/app/store/duck.py`
- `backend/app/schemas/incident.py`
- `backend/app/api/routes/incidents.py`
- `backend/app/pipeline/report/template.py`
- `backend/tests/test_risk_and_report.py` (new test file)

### Approach
1. **Dynamic Composite Risk Scoring**:
   - Rewrite `score_incident(incident: dict, reach_data: dict | None = None) -> float`:
     - **Tactic Breadth**: Distinct ATT&CK tactics involved (wider campaigns score higher).
     - **Kill Chain Progress**: Weight steps by kill chain depth (e.g., Reconnaissance=2, Initial Access=4, Execution=6, Lateral Movement=8, Exfiltration/Impact=10).
     - **Asset Criticality**: Incorporate blast radius and whether critical assets (e.g., Domain Controllers, Databases) are compromised or directly reachable.
     - **Detection Volume & Severity**: Incorporate maximum rule severity and total detection/event counts.
     - Normalized to a 1.0 - 10.0 scale.
2. **Persistence and API Integration**:
   - Compute `risk_score` during incident creation in `incidents.py`.
   - Persist `risk_score` in the DuckDB `incidents` table.
   - Update `duck.list_incidents()` to sort by `risk_score DESC, first_seen DESC`.
   - Expose `risk_score` in `/api/v1/incidents`.
3. **Comprehensive Markdown Report**:
   - Update `render(incident_id: str) -> str` in `backend/app/pipeline/report/template.py`:
     - Executive summary header with Risk Score, Severity, Detection Count, and Raw Event Count.
     - Affected Entities table (Hosts, IPs, Users).
     - Kill Chain progression with techniques, tactics, stages, and timestamps.
     - "Next Reach / Blast Radius" section detailing potential targets, criticality, and reach reasons.

### Verification Strategy
- Pytest tests validating:
  1. Risk scoring formula: multi-tactic incidents with lateral movement or critical assets score higher than single-step initial access incidents.
  2. Incidents API returns results sorted by `risk_score` descending.
  3. Generated Markdown report contains Risk Score, Detection Count, Raw Event Count, and Next Reach details.

### Risks & Mitigations
- *Risk*: Pre-computing reach during incident linking might fail if reach engine encounters unexpected data.
  *Mitigation*: Risk scoring computes gracefully with or without reach pre-computation, falling back to base metadata.

---

## Phase 7: UI and Packaging

### Problem Statement
The web UI (`backend/app/static/index.html`) requires enhancements:
- Incidents list needs to be sorted by risk, displaying "N raw events merged into this incident" and detection count.
- Timeline needs to display MITRE technique, tactic, stage, host, and time.
- Reach panel needs to show actionable reach predictions with reasons.
- Header metrics require a stored last-evaluation result and a dedicated GET endpoint (current routes only provide POST `/evaluate/manifest`).
Packaging requirements:
- Existing `Dockerfile` and `docker-compose.yml` must NOT copy `data/` into the image; must use volume mounting and a `.dockerignore`.
- Clean up unused code: remove the duplicate root-level `pipeline/` shim directory after verifying nothing imports it.
- Update `README.md` Quick Start instructions.

### Files Touched
- `backend/app/static/index.html`
- `backend/app/api/routes/evaluation.py`
- `backend/app/store/duck.py`
- `Dockerfile`
- `.dockerignore` (new file)
- `docker-compose.yml`
- `README.md`
- Remove `pipeline/` directory

### Approach
1. **Evaluation Metrics Storage & GET Endpoint**:
   - Store the most recent evaluation summary in DuckDB stats (`last_evaluation_result`).
   - Add `GET /api/v1/evaluation/latest` endpoint returning the stored evaluation metrics (detection rate, label accuracy exact/family, false alarm rate, path rate).
2. **Frontend Enhancements (`index.html`)**:
   - Incident cards: Show `risk_score` badge, title, time range, detection count, and formatted string: `"N raw events merged"`.
   - Timeline view: Render step order, technique ID, human-friendly tactic name, kill chain stage, host, and start/end timestamps.
   - Reach view: Display reachable entities, criticality status, priority badge, and human-readable reason string (e.g. "allowed on tcp/445 seen 12 times").
   - Header: Add evaluation stats pill (Detection Rate %, Label Acc %, False Alarm %) queried from `/api/v1/evaluation/latest`.
3. **Container Packaging**:
   - Create `.dockerignore` ignoring `data/`, `.venv/`, `.pytest_cache/`, `__pycache__/`, `*.duckdb*`.
   - Update `Dockerfile`: Ensure `data/` is NOT copied into image. Use volume mounts in `docker-compose.yml`.
   - Update `docker-compose.yml` to mount `./data:/app/data` and expose port 8000.
4. **Clean Up Root `pipeline/` Shim**:
   - Confirm zero occurrences of `from pipeline` or `import pipeline` across all workspace code.
   - Safely remove the legacy root `pipeline/` directory.
5. **Documentation**:
   - Update `README.md` Quick Start with clear instructions for running via Docker Compose as well as standard local Python setup.

### Verification Strategy
- Open UI via browser / check HTML markup and JS API handling.
- Verify `GET /api/v1/evaluation/latest` returns stored metrics.
- Verify Docker configuration syntax and `.dockerignore` exclusions.
- Run `pytest` and `ruff check` after deleting the `pipeline/` shim to guarantee zero broken imports.

### Risks & Mitigations
- *Risk*: Deleting `pipeline/` breaks an external benchmark or entrypoint script.
  *Mitigation*: Confirmed via grep that all tests and scripts import from `app.*` with `PYTHONPATH=backend`.

---

## Phase 8: Measure, Benchmark, and Final Report

### Problem Statement
The system must be rigorously benchmarked against the PRD targets:
- Detection rate > 70%
- Label accuracy > 60%
- Path rate >= 50%
- False alarm rate < 30%
- Path open latency < 2,000 ms (target < 500 ms)
- Memory usage < 16 GB
- Processing time: full ingest + analyse run time and peak RSS memory must be measured.
All final results must be documented in `docs/TASKS.md` and `README.md`.

### Files Touched
- `scripts/benchmark.py`
- `docs/TASKS.md`
- `README.md`

### Approach
1. **Run Full Pipeline Benchmark (Time & Peak RSS)**:
   - Measure full ingest + analyse execution time and peak memory (peak RSS via `psutil` or `resource`).
2. **Run End-to-End API Benchmark**:
   - Execute `python scripts/benchmark.py` measuring p50 and p95 latency for health, stats, events, detections, incidents, graph, path, and reach endpoints.
   - Confirm path-open latency is well below 500 ms.
3. **Run Ground-Truth Evaluator**:
   - Execute evaluator against `data/firex-30G.log.manifest.json`.
   - Compute detection rate, label accuracy exact/family, path rate, and false-alarm rate.
4. **Document Results**:
   - Record baseline vs. final metrics in `docs/TASKS.md`.
   - Add a "Results" section to `README.md` summarizing the verified metrics against the PRD thresholds.
5. **Final Summary**:
   - Highlight what was completed, any partial/blocked areas, and the top three open risks.

### Verification Strategy
- Automated benchmark outputs recorded and verified.
- Evaluator results printed and checked against PRD thresholds.
- Full pytest test suite passing cleanly with zero warnings/errors.
