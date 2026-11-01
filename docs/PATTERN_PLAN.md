# Automated Pattern Discovery Implementation Plan

## 1. Executive Summary & Objective
Implement an automated, unsupervised pattern discovery subsystem for CaseFile that autonomously mines high-fidelity attack patterns and threat indicators from normalized log telemetry (`events` view) without relying on ground-truth manifests or pre-hardcoded IOCs. 

The pattern discovery engine will execute purely via set-based DuckDB SQL queries over partitioned Parquet data, achieving sub-5-minute runtimes on 9.1M+ row datasets with bounded memory consumption. Discovered patterns are ranked, cataloged in DuckDB, exposed via REST APIs and UI, compiled into draft detection rules (with noise guard dry-runs and `rules/discovered.yaml` export), and evaluated for planted attack coverage by the evaluation subsystem.

---

## 2. Architectural Principles & Constraints

1. **Strict Manifest Isolation**:
   - The pattern discovery engine learns exclusively from log telemetry in DuckDB (`events` view).
   - Manifest files (`*.manifest.json`) are strictly inaccessible to the mining pipeline. Only the evaluator may read manifests post-hoc to measure planted attack coverage.
2. **Zero Hard-Coded IOCs & Behavioral Rule Candidates**:
   - No specific IPs, domains, hashes, or signature strings may be hard-coded.
   - All indicators must emerge algorithmically through statistical deviation, temporal clustering, graph topology, and information entropy.
   - Generated rule candidates must be purely behavioral (threshold/rarity rules with event class, window, min_count, min_distinct). Specific IPs and domains belong in `iocs.csv` only.
   - Rules must match the exact schema in `app/schemas/rule.py` (`id`, `name`, `type`, `technique_id`, `tactic`, `conditions`, `logic`, `severity`, `window_seconds`, `threshold`, `group_by`, `min_distinct_field`, `min_distinct_count`).
3. **High Performance & Bounded Memory**:
   - All 5 miners run set-based SQL queries directly inside DuckDB; zero per-event Python loops.
   - Targeted execution time: $\le 5$ minutes on 9.1M events.
   - Peak RSS bounded by DuckDB memory limits and streaming aggregations.
4. **Deterministic Execution**:
   - All queries order explicitly by `ts` and numeric `source_offset` (`ORDER BY ts, source_offset`).
   - `pattern_id` is a stable SHA-256 hash of `(kind, canonical_key)`. Zero random IDs.
   - Re-running the pipeline produces bit-for-bit identical pattern sets, scores, and example event IDs (excluding timestamp `created_at`).
   - `upsert_pattern` preserves existing approval status (`approved` / `rejected`) upon re-mining.
   - Raw ingest format and canonical `event_id` (`ev_<stream>_<source_offset>`) remain untouched.

---

## 3. Subsystem Architecture & Specific Miner Logic

### Phase P1: Pattern Miners (`backend/app/pipeline/patterns/`)
Implement 5 modular, set-based DuckDB miners under `backend/app/pipeline/patterns/`:

#### P1.a: Burst Miner (`burst.py`)
- **Detection Target**: Sudden anomalous bursts of activity from a source entity (`src_ip`) for a specific event class (`logid`, `attack`, or `action`) relative to a robust baseline.
- **Statistical Model**: Compare each source to all sources of the same event class. Median and Median Absolute Deviation (MAD) modified Z-score per time window:
  $$\text{Modified Z} = \frac{0.6745 \cdot (\text{count} - \text{median})}{\max(\text{MAD}, 1)}$$
  (Flooring MAD at $\ge 1$ prevents division-by-zero or infinite z-scores when most sources have zero/one event).
- **Thresholds**: Modified $Z \ge 3.5$, minimum absolute event count $\ge 20$.
- **Extracted Attributes**: Total burst count, peak rate (events/sec), burst duration, distinct destination IPs (`COUNT(DISTINCT dst_ip)`), distinct destination ports (`COUNT(DISTINCT dst_port)`), top 8 sorted `event_id`s (`ORDER BY ts, source_offset`).
- **Suggested ATT&CK Mapping**: T1110 (Brute Force) for auth failures, T1046 (Network Service Discovery) for port sweeps, T1498 (Network DoS) for traffic bursts.

#### P1.b: Rarity & Entropy Miner (`rarity.py`)
- **Detection Target**:
  1. Low-frequency values of `attack`, `hostname`, `url`, `virus`, `user`, and `service` occurring with low count.
  2. **Suspicious Signal Requirement**: Rare values must co-occur with a suspicious signal: blocked action (`action IN ('deny', 'block', 'drop')`), external source (`NOT is_rfc1918(src_ip)`), or high severity (`severity IN ('high', 'critical', 'alert')` or level $\ge 4$).
  3. Keep top $K$ rare values per dimension (e.g. top 50 per field).
  4. Long or high-entropy hostnames/domain names (Shannon entropy $H \ge 3.8$ bits, length $\ge 22$), identifying DGA or DNS tunneling.
- **DuckDB SQL Formulation**: Frequency window aggregations over distinct dimension values joined with suspicious event filters.
- **Suggested ATT&CK Mapping**: T1568 (Dynamic Resolution / DGA) or T1071 (Application Layer Protocol).

#### P1.c: Novel Edges Miner (`novel_edges.py`)
- **Detection Target**: Infrequent or previously unobserved connection edges restricted to:
  - Internal-to-internal edges (`RFC1918 -> RFC1918`) on high-value lateral administration ports: SMB (445), RDP (3389), SSH (22), WinRM (5985/5986), Kerberos (88), LDAP (389), and Databases (1433, 3306, 5432).
  - External-to-internal edges (`non-RFC1918 -> RFC1918`) on non-public services (ports other than 80, 443).
- **Frequency Filtering**: Use "seen at most $N$ times overall" ($N \le 10$) across the dataset rather than arbitrary time slicing. Cap results to top 100 highest-priority novel edges.
- **Suggested ATT&CK Mapping**: T1021 (Remote Services) or T1570 (Lateral Tool Transfer).

#### P1.d: Multi-Tactic Ordered Sequences Miner (`sequences.py`)
- **Detection Target**:
  - Raw events have **no** tactic field in the log. The sequence miner mines sequences of **event classes** (`logid`, `subtype`, `action`, `attack` family, port class) within sliding 30-minute windows per entity (`src_ip` and internal host).
  - Classes are mapped to tactics post-hoc via `knowledge/` taxonomy or existing detection rule definitions.
  - Configurable minimum support (`min_support >= 2`).
  - Also rank single-entity cross-tactic chains by chain rarity (identifying unique planted attack sequences).
- **DuckDB SQL Formulation**: Window functions over ordered tokens (`ORDER BY ts, source_offset`), mining ordered subsequences spanning 2+ distinct mapped tactics.
- **Suggested ATT&CK Mapping**: Kill-chain attack progression.

#### P1.e: Coordinated Multi-Source Burst Miner (`coordinated.py`)
- **Detection Target**: Multiple distinct sources (`src_ip` count $\ge 2$) executing the same burst signature (same attack signature, destination port, or target host) within the same 10-minute window.
- **Scoring**: $S = \text{distinct\_sources} \cdot \ln(\text{total\_events})$.
- **Suggested ATT&CK Mapping**: T1110 (Distributed Password Spraying) or T1498 (Distributed Denial of Service).

---

### Phase P2: Pattern Catalog, Persistence & Exports
1. **Database Schema (`patterns` table in DuckDB)**:
   ```sql
   CREATE TABLE IF NOT EXISTS patterns (
       pattern_id          TEXT PRIMARY KEY, -- Stable hash of (kind, key)
       kind                TEXT NOT NULL,
       title               TEXT NOT NULL,
       support             INTEGER NOT NULL,
       first_seen          TIMESTAMPTZ,
       last_seen           TIMESTAMPTZ,
       entities            TEXT NOT NULL DEFAULT '[]',
       example_event_ids   TEXT NOT NULL DEFAULT '[]', -- Max 8 sorted IDs
       score               DOUBLE NOT NULL,
       suggested_technique TEXT,
       suggested_tactic    TEXT,
       status              TEXT NOT NULL DEFAULT 'new', -- 'new' | 'approved' | 'rejected'
       details_json        TEXT NOT NULL DEFAULT '{}',
       created_at          TIMESTAMPTZ NOT NULL
   );
   ```
2. **Catalog Capping**:
   - Limit stored patterns to top $N$ patterns (configurable, default 200) with score above minimum threshold (`min_score = 3.0`).
   - `upsert_pattern` preserves existing status (`approved` or `rejected`) when patterns are re-mined.
3. **REST API Endpoints (`app/api/routes/patterns.py`)**:
   - **Route Ordering**: Register `/patterns/export/*` BEFORE `/patterns/{id}` to avoid path matching collisions!
   - `GET /api/v1/patterns/export/json`: Download `patterns.json`.
   - `GET /api/v1/patterns/export/yaml`: Download `patterns.yaml`.
   - `GET /api/v1/patterns/export/iocs`: Download `iocs.csv`.
   - `GET /api/v1/patterns`: List patterns with filtering by `status`, `kind`, and pagination.
   - `GET /api/v1/patterns/{id}`: Detailed pattern metadata.
   - `POST /api/v1/patterns/{id}/approve`: Transition status to `approved`.
   - `POST /api/v1/patterns/{id}/reject`: Transition status to `rejected`.
4. **Export Artifacts (`app/pipeline/patterns/exporter.py`)**:
   - `data/patterns.json`, `data/patterns.yaml`, `data/iocs.csv` (IOCs: specific attacker IPs, domains, signatures with counts and linked incident IDs).

---

### Phase P3: Rule Candidate Synthesis & Safety Dry-Runs
1. **Behavioral Rule Synthesis (`rule_gen.py`)**:
   - Draft rules generated against `app/schemas/rule.py` (`id`, `name`, `type`, `technique_id`, `tactic`, `conditions`, `severity`, `window_seconds`, `threshold`, `group_by`, `min_distinct_field`, `min_distinct_count`).
   - Must be purely behavioral (threshold/rarity rules with event class, window, min_count, min_distinct). Specific IPs/domains go into `iocs.csv` only.
2. **Noise Guard Dry-Run**:
   - Compiles each draft with `compile_rule_to_sql` and runs count queries against the `events` view.
   - Match-type candidates: auto-reject if $>1,000$ matches.
   - Threshold-type candidates: judge by number of firing groups.
   - Auto-qualification is **OFF** by default: only rules with status `approved` are written to `rules/discovered.yaml`.
   - `detections.yaml` is **never** edited.
3. **Rule Tuning Advisor (`tune_report.py`)**:
   - Flags rules with zero precision or disproportionate false alarms and proposes disabling them (report only).

---

### Phase P4: Automation, UI & Optional AI Alignment
1. **Pipeline & CLI Integration**:
   - Added to `scripts/run_all.py` with `--skip-patterns` flag. Deterministic SQL (`ORDER BY ts, source_offset`) throughout.
   - `casefile patterns` CLI commands: `mine`, `list`, `export`, `approve`, `reject`.
2. **Interactive UI (`backend/app/static/index.html`)**:
   - Dedicated **Patterns** tab with ranked table, status badges, approve/reject buttons, and "View in Graph".
3. **Optional LLM Alignment**:
   - Enriches pattern titles and MITRE mappings with Gemini / Mock fallback under strict grounding checks.

---

### Phase P5: Evaluator Coverage & Deliverables
1. **Evaluator Coverage Measurement (`evaluator.py`)**:
   - When a manifest is provided to the evaluator, test planted `event_ids` against each pattern's SQL predicate and time range via DuckDB SQL (not merely checking the 8 sample IDs).
   - If no manifest is provided (or `--skip-eval`), report `"NOT MEASURED"`.
2. **Final Deliverable Report (`docs/PATTERN_REPORT.md`)**:
   - Top 20 discovered patterns with support and sorted example `event_id`s.
   - Miner execution wall-clock time and peak process-tree RSS.
   - Catalog of discovered IOCs.

---

### Phase P4: Integration, UI & AI Enrichment
1. **Pipeline & CLI Integration**:
   - Integration in `scripts/run_all.py`: Executes pattern discovery stage after incident linking and reach precomputation, saving artifacts to `data/`.
   - Typer CLI command group `casefile patterns`:
     - `casefile patterns mine [--min-score 5.0]`
     - `casefile patterns list [--status new/approved/rejected]`
     - `casefile patterns export [--format json/yaml/csv]`
     - `casefile patterns approve <pattern_id>`
     - `casefile patterns reject <pattern_id>`
2. **Interactive UI (`backend/app/static/index.html`)**:
   - Add a **Patterns** tab to the navigation header.
   - Render ranked table: Pattern ID, Kind badge, Title, Score, Support, ATT&CK mapping, and Action buttons (**Approve**, **Reject**, **View in Graph**).
   - "View in Graph" navigates to the incident explorer and highlights participating entities.
3. **Optional LLM Story Enrichment**:
   - If an LLM provider is active (Gemini or Mock), query the LLM with structured pattern statistics (event counts, ports, services, time spans) inside `<FACTS_DATA>` tags.
   - Strict grounding verification: verifies suggested MITRE IDs exist in `attack_tactics.yaml` and no fabricated entities are added.
   - Safe deterministic fallback if LLM is disabled or unavailable.

---

### Phase P5: Evaluation & Planted Attack Coverage
1. **Evaluator Coverage Measurement (`app/pipeline/evaluate/evaluator.py`)**:
   - The evaluator alone (never the miners) correlates pattern entities and timestamps against the ground-truth manifest's planted incidents.
   - Computes:
     - `planted_incident_pattern_coverage`: Percentage of planted incidents with at least one matching discovered pattern.
     - `unmatched_pattern_ratio`: Percentage of discovered patterns that represent organic background anomalies rather than planted attacks.
   - If no manifest is provided (or `--skip-eval` is active), records `"NOT MEASURED"`.
2. **Final Deliverable Report (`docs/PATTERN_REPORT.md`)**:
   - Table of the top 20 discovered patterns with support and sorted example `event_id`s.
   - Miner execution wall-clock time and full process-tree peak RSS.
   - Summary table of discovered IOCs (attacker IPs, compromised internal hosts, rare signatures).

---

## 5. Verification & Testing Strategy
- Unit tests for each miner:
  - `test_burst_miner.py`: Verifies burst detection with synthetic spike events.
  - `test_rarity_miner.py`: Verifies Shannon entropy calculation and rare value extraction.
  - `test_novel_edges_miner.py`: Verifies baseline window exclusion and RFC1918 sensitive port detection.
  - `test_sequences_miner.py`: Verifies multi-tactic chronological sequence detection.
  - `test_coordinated_miner.py`: Verifies multi-source burst grouping.
- Integration tests:
  - `test_pattern_api.py`: Tests endpoints (`GET /patterns`, `POST /patterns/{id}/approve`, export endpoints).
  - `test_rule_candidate_gen.py`: Tests SQL compilation, dry-run noise guard, and `rules/discovered.yaml` writer.
- End-to-end regression:
  - Run full pytest test suite (`pytest backend/tests/`) and `ruff check .` after every phase.

