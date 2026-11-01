# Automated Pattern Discovery Implementation Tasks

## Phase P1: Pattern Miners (`backend/app/pipeline/patterns/`)
- [x] P1.1 Setup `backend/app/pipeline/patterns/__init__.py` and common base utilities (stable SHA-256 `pattern_id` generator, scoring normalization, entity extraction)
  - Result: Created `base.py` with deterministic SHA-256 `pat_<hash>` ID generator, Shannon entropy calculation, RFC1918 checking, and `PatternCandidate` dataclass.
- [x] P1.2 Implement Burst Miner (`burst.py`): per `(src_ip, event_class)` modified Z-score against all sources of the same class, with floored MAD `GREATEST(mad, 1)`, minimum absolute event count $\ge 20$, duration, count, distinct dst_ips/dst_ports, and sorted top 8 `event_id`s (`ORDER BY ts, source_offset`)
  - Result: Implemented `burst.py` in DuckDB SQL using 5-minute buckets, floored MAD $\ge 1.0$, min_count=20, modified Z $\ge 3.5$, and deterministic `ORDER BY ts, source_offset`.
- [x] P1.3 Implement Rarity & Entropy Miner (`rarity.py`): top $K$ rare values per dimension (attack, hostname, url, virus, user, service) requiring co-occurrence with a suspicious signal (blocked action, external source, or high severity) + Shannon entropy calculation for DGA/tunneling hostnames
  - Result: Implemented `rarity.py` in DuckDB SQL filtering rare values co-occurring with blocked actions, external IPs, or high severity, plus Shannon entropy threshold $H \ge 3.8$ for DGA detection.
- [x] P1.4 Implement Novel Edges Miner (`novel_edges.py`): internal->internal edges on sensitive ports (445, 3389, 22, 5985, etc.) and external->internal edges on non-public services; filter for seen $\le N$ times overall; cap results to top 100
  - Result: Implemented `novel_edges.py` in DuckDB SQL with sensitivity weighting for SMB/RDP/SSH/DB ports and external non-public ingress, capped at top 100.
- [x] P1.5 Implement Multi-Tactic Ordered Sequences Miner (`sequences.py`): per-entity sliding 30-min windows over event classes (logid, subtype, action, attack family, port class) mapped to tactics post-hoc; configurable `min_support`; rank single-entity cross-tactic chains by chain rarity
  - Result: Implemented `sequences.py` in DuckDB SQL mapping raw event classes to MITRE tactics post-hoc, extracting 2-4 stage chains within 30-min windows, and scoring by chain rarity.
- [x] P1.6 Implement Coordinated Multi-Source Burst Miner (`coordinated.py`): $\ge 2$ distinct sources executing identical burst signature in the same 10-minute window
  - Result: Implemented `coordinated.py` in DuckDB SQL grouping by 10-minute windows with identical attack/URL/port signatures across $\ge 2$ sources, scored via $S = \text{sources} \cdot \ln(\text{events})$.
- [x] P1.7 Implement Miner Orchestrator (`runner.py`): executes all miners in DuckDB SQL, ranks patterns by composite score, enforces deterministic ordering (`ORDER BY ts, source_offset`), and caps stored catalog at top $N$ patterns above `min_score`
  - Result: Implemented `run_pattern_mining` in `runner.py` with DuckDB resource limits, timing instrumentation, deterministic sorting by `(-score, -support, pattern_id)`, and deduplication.
- [x] P1.8 Add unit tests in `backend/tests/test_patterns_miners.py` verifying all 5 miners with synthetic data; run `pytest` and `ruff check .`
  - Result: Added comprehensive tests in `test_patterns_miners.py`; all 7 tests passed in 1.17s. Ruff check clean (0 errors). Golden parser test passed 100%.

## Phase P2: Catalog, Persistence & Exports
- [x] P2.1 Add `patterns` table DDL and indexes to `backend/app/store/duck.py` with stable hash `pattern_id`
  - Result: Added `patterns` table DDL in `duck.py` with stable primary key `pattern_id`, score, support, example_event_ids, entities, and status.
- [x] P2.2 Implement pattern persistence functions in `duck.py` (`upsert_pattern` preserving existing approved/rejected status, `list_patterns`, `get_pattern`, `update_pattern_status`)
  - Result: Implemented `upsert_pattern` with status-preserving `ON CONFLICT DO UPDATE`, `save_patterns_batch`, `get_pattern`, `list_patterns`, and `update_pattern_status`.
- [x] P2.3 Implement Pydantic schemas in `backend/app/schemas/pattern.py` (`PatternRecord`, `PatternListResponse`, `PatternStatusUpdate`, `IOCRecord`)
  - Result: Created typed schemas in `pattern.py` with deserialization support for entities, example event IDs, and details.
- [x] P2.4 Implement pattern REST API routes in `backend/app/api/routes/patterns.py` registering `/patterns/export/*` BEFORE `/patterns/{id}`, and mount router in `app/main.py`
  - Result: Created `patterns.py` router with `/export/json`, `/export/yaml`, `/export/iocs`, list/get routes, and approve/reject actions; registered in `main.py`.
- [x] P2.5 Implement pattern and IOC export utilities in `backend/app/pipeline/patterns/exporter.py` generating `data/patterns.json`, `data/patterns.yaml`, and `data/iocs.csv` (specific IPs/domains with counts and linked incident IDs)
  - Result: Created `exporter.py` with JSON, YAML, and CSV IOC extractors isolating specific IPs and domains from behavioral patterns.
- [x] P2.6 Add API and export tests in `backend/tests/test_patterns_api.py`; run `pytest` and `ruff check .`
  - Result: Added `test_patterns_api.py`; all 4 tests passed in 4.79s. Ruff check clean (0 errors).

## Phase P3: Rule Candidates & Noise Guard Dry-Run
- [x] P3.1 Implement Behavioral Rule Candidate Generator (`rule_gen.py`): translates discovered patterns into valid behavioral `Rule` models matching `app/schemas/rule.py` (threshold/rarity rules with event class, window, min_count, min_distinct; never hardcoding specific IPs/domains)
  - Result: Implemented `pattern_to_rule_candidate` in `rule_gen.py` synthesizing behavioral threshold/match rules conforming to `app/schemas/rule.py` without hardcoding specific IPs or domains.
- [x] P3.2 Implement SQL Compilation & Dry-Run verification: dry-runs candidate SQL against `events` view to count total matches and evaluate firing groups
  - Result: Implemented `dry_run_rule` dynamically inspecting target database column metadata and executing count queries.
- [x] P3.3 Implement Noise Guard: reject match-type candidates $>1,000$ matches and judge threshold-type candidates by number of groups; auto-qualification OFF by default
  - Result: Added threshold limits (1,000 for match, 500 for threshold) rejecting excessively broad candidate rules.
- [x] P3.4 Implement `rules/discovered.yaml` writer for approved rule candidates (never modifying `detections.yaml`) and verify discovery by `rule_loader.py`
  - Result: Implemented `export_discovered_rules` writing clean YAML to `rules/discovered.yaml` without modifying `detections.yaml`, validated with production `validate_rules`.
- [x] P3.5 Implement false-alarm tuning advisor in `tune_report.py` proposing rules to disable based on zero-precision / high false-alarm rates (report only)
  - Result: Implemented `generate_tuning_report` generating `data/tune_report.json` evaluating selectivity and recommending threshold adjustments.
- [x] P3.6 Add rule generation and safety tests in `backend/tests/test_patterns_rules.py`; run `pytest` and `ruff check .`
  - Result: Added `test_patterns_rules.py`; all 4 tests passed in 8.81s. Ruff check clean (0 errors).

## Phase P4: Automation, UI & Optional AI Alignment
- [x] P4.1 Integrate pattern discovery into `scripts/run_all.py` as an automated pipeline stage with `--skip-patterns` flag; maintain deterministic SQL (`ORDER BY ts, source_offset`)
  - Result: Integrated automated pattern mining stage and tuning report generation into `run_all.py` with `--skip-patterns` flag and deterministic DuckDB execution.
- [x] P4.2 Implement Typer CLI command group `casefile patterns` in `backend/app/cli.py` (`mine`, `list`, `export`, `approve`, `reject`)
  - Result: Added `patterns` command group to `cli.py` supporting `mine`, `list`, `approve`, `reject`, and `export` with Rich table formatting. Verified via `test_patterns_cli.py`.
- [x] P4.3 Add **Patterns** tab to web UI in `backend/app/static/index.html` with ranked table, status pills, approve/reject buttons, and "View in Graph" entity cross-links
  - Result: Added interactive Patterns view in `index.html` with filtering, export buttons, approve/reject actions, and graph navigation. Zero-CDN verified via `test_ui_static.py`.
- [x] P4.4 Add optional Gemini / Mock pattern alignment helper proposing structured titles and ATT&CK mappings under strict grounding verification
  - Result: Created `alignment.py` querying LLM client when available with strict grounding to MITRE ATT&CK taxonomy and deterministic fallback.
- [x] P4.5 Run `pytest` and `ruff check .`
  - Result: All 16 pattern tests and UI static tests passed cleanly. Ruff check 0 errors.

## Phase P5: Evaluation, Coverage & Deliverables
- [x] P5.1 Extend `backend/app/pipeline/evaluate/evaluator.py` to evaluate planted event_ids against each pattern's SQL predicate and time range via DuckDB SQL (reporting incident coverage rate and unmatched pattern ratio; "NOT MEASURED" when no matching manifest exists)
  - Result: Extended `evaluator.py` with `planted_incident_pattern_coverage` and `unmatched_pattern_ratio` using DuckDB SQL event/entity matching; verified with 4/4 passing tests in `test_evaluator.py`.
- [x] P5.2 Execute end-to-end pattern discovery on the full dataset and generate `docs/PATTERN_REPORT.md` featuring top 20 patterns, runtime/memory stats, and discovered IOCs
  - Result: Executed full pattern discovery across 9,125,383 rows in 101.84s (Peak RSS: 84.4 MB); cataloged 200 patterns across all 5 miner families, extracted 494 IOCs into `data/iocs.csv`, and authored comprehensive deliverable in `docs/PATTERN_REPORT.md`.
- [x] P5.3 Run full test suite across the repository (`pytest backend/tests/`) and `ruff check .`
  - Result: Executed full test suite: 163 passed, 5 skipped in 21.71s (0 failures, 0 errors). Golden parser test `test_parser_golden.py` passed 100%. `ruff check .` clean with 0 warnings/errors.
- [x] P5.4 Update `docs/PATTERN_TASKS.md` with final verification results
  - Result: All tasks in Phases P1 through P5 completed and verified.
