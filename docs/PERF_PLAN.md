# Ingestion Throughput, Memory & Pipeline Optimization Plan

## 1. Objective
Maximize log ingestion throughput (MB/s and rows/s) and minimize peak RSS memory consumption on an 8-to-16-core system (detected: 12 physical cores, 16 logical threads, Power Scheme: Balanced, Plugged-in: True) for the FortiGate log dataset (`data/firex-10G.log`), while strictly preserving canonical `event_id` integrity, parser output equivalence, and DuckDB analytical query determinism.

---

## 2. Hard Constraints, Invariants & Stopping Criteria

1. **Stop Condition**:
   - Ingest optimization will conclude when:
     - Ingestion throughput is $\ge 2\times$ faster than the baseline **AND** whole-process peak RSS is $\le 8\text{ GB}$; **OR**
     - Ingestion is no longer the slowest pipeline stage.
   - *Note*: Peak RSS below 4 GB alone does **not** stop the work.

2. **Canonical `event_id`**: Must strictly equal `ev_<stream>_<byte offset of line start>`. Provenance and ground-truth evaluation depend on this exact byte offset.

3. **Strict Output Equivalence & Standalone Golden Fixture**:
   - Sample ~5,000 lines across 4 distinct file regions (~20,000 lines total):
     1. Start of file (clean traffic startup)
     2. Middle of file (steady-state production telemetry)
     3. Corrupted tail region (binary/garbage lines with expected `None` results)
     4. Complex edge-case lines:
        - Escaped quotes (`\"`) and backslashes (`\\\\`)
        - Non-ASCII multi-byte UTF-8 sequences
        - CRLF (`\r\n`) and LF (`\n`) endings
        - Malformed lines lacking `date=` or `logid=` (returning `None`)
        - Tokens without `=` mid-line
        - Empty values (`key=`) at the end of lines
        - Duplicate keys within a line (last key wins)
        - Unterminated quotes
        - Tab (`\t`) separated pairs
        - Final line without trailing newline
   - The fixture will store the **raw input lines** alongside the baseline parsed dictionary outputs in `backend/tests/fixtures/golden_sample.json.gz` (size bounded under ~5 MB) so the test runs completely standalone without requiring `data/firex-10G.log`.
   - Output schema must remain identical: no new columns added (no `"extra"` column additions; preserve existing `extra` JSON logic).

4. **Database & Parquet Isolation**:
   - All benchmark scripts (`tune_ingest.py`, `profile_chunk.py`) must use isolated throwaway temporary output directories and throwaway DuckDB instances per run.
   - Never write to `data/parquet` or open/modify the development database `data/casefile.duckdb`.

5. **Disk Space Safety & Scale Test Guard**:
   - Current free disk space on drive C: is **8.14 GB** (less than the required 40 GB).
   - Before running any benchmark, report free disk space, the Parquet-to-log compression ratio from the first 1 GB run, and projected disk needs (raw + Parquet + DuckDB temp) for 15 GB, 30 GB, and 50 GB workloads.
   - Set `duck_temp_directory` to a safe path within available capacity.
   - If free disk space is under 40 GB, stop and notify the user instead of running the optional 13–20 GB scale test.

---

## 3. Step-by-Step Architecture & Execution Plan

### Step 1: Baseline Measurements, Golden Fixture & Pipeline Diagnostics (No Pipeline Code Changes Yet)

- **1.1 Process-Tree RSS Reporting in Runner**:
  - Update `get_peak_rss_mb()` in `backend/app/pipeline/ingest/runner.py` to aggregate RSS across the root process and all child processes recursively via `psutil`.

- **1.2 Pipeline Stage Timing & Rule SQL Profiling**:
  - Measure per-stage baseline on an isolated database: Ingestion, Detection, Incident Linking, and Lateral Reach.
  - Run rule SQL profiling against a temporary DuckDB database with a read-only view over the Parquet store.
  - Write `rule_stats` and intermediate outputs to a temporary directory.
  - **Never** call `boost_multi_tactic_confidences()` or write to `data/casefile.duckdb`.
  - Identify and record the 5 slowest detection rules in `docs/INGEST_TUNING.md`.

- **1.3 Standalone Golden Fixture & Verification Test**:
  - Extract ~20,000 diverse sample lines across `data/firex-10G.log` covering all edge-case categories.
  - Run baseline parser `fortigate_kv.parse_line` and commit the frozen output with raw input strings into `backend/tests/fixtures/golden_sample.json.gz` (< 5 MB).
  - Implement `backend/tests/test_parser_golden.py` asserting exact field-by-field and type-by-type parity.

- **1.4 Staged Benchmarking Harness (`scripts/tune_ingest.py`)**:
  - Benchmark protocol: run each configuration **3 times**, discard the cold-cache first run, and report the median of runs 2 & 3.
  - Record environment state in `docs/INGEST_TUNING.md`:
    - Power scheme: Balanced
    - Battery / plugged-in state: AC plugged in
    - Windows Defender exclusion status: Not elevated / Not detected
  - **Stage A (Workers)**: Fixed 64 MB chunk size on first-1 GB slice with workers $\in \{4, 8, 12\text{ (physical cores)}\}$. Identify winning worker count.
  - **Stage B (Chunk Size)**: Best worker count from Stage A with chunk sizes $\in \{32, 64, 128\}\text{ MB}$. Identify winning chunk size.
  - **Stage C (Middle Slice & Parse-Only)**: Run the winning configuration on:
    1. Middle 1 GB slice of the log file
    2. Parse-only mode (`--parse-only`, parses in memory without writing Parquet) to decouple CPU parsing speed from disk I/O.
  - Measure: Throughput (MB/s), Speed (rows/s), Wall-clock duration (s), and Peak RSS across the entire process tree (sampled every 100 ms via `psutil`).
  - Document all metrics in `docs/INGEST_TUNING.md`.

- **1.5 Single-Chunk `cProfile` Breakdown (`scripts/profile_chunk.py`)**:
  - Profile a single 64 MB chunk in an isolated single process.
  - Report exact time splits:
    1. Line reading / block I/O
    2. Tokenization (`parse_kv`)
    3. Timestamp & timezone conversion
    4. Record dictionary construction & field normalization
    5. PyArrow table conversion (`pa.Table.from_pylist`)
    6. Parquet serialization to disk (`pq.write_table` with zstd)

---

### Step 2: Sequential Ingestion Optimizations (Re-measuring after each, keeping only what helps)

Each optimization is validated against `test_parser_golden.py` and measured against the 1 GB slice:

- **2.1 Sub-Block Reader (~8 MB Newline-Aligned Blocks)**:
  - Read chunks in ~8 MB newline-aligned sub-blocks, carrying a cumulative byte offset.
  - Split on `b"\n"` only; **never** use `str.splitlines()`.
  - Decode per line (`line.decode("utf-8", errors="replace")`) so multi-byte non-ASCII characters preserve exact file start byte offsets.
  - Verify exact byte offsets against the golden fixture.

- **2.2 LRU Timestamp Caching**:
  - Cache `(date_str, time_str, tz_str)` parsing using `@functools.lru_cache(maxsize=8192)`.
  - Exploit high temporal locality across lines in the same second, skipping redundant string slicing, integer parsing, and `datetime` creation.

- **2.3 Precompiled Fast Regex / Split Tokenizer**:
  - Replace character-by-character while loop in `parse_kv` with precompiled regular expressions and index slicing.
  - Preserve exact backslash-escaped quote handling (`\"` $\rightarrow$ `"`) and escaped backslashes (`\\\\` $\rightarrow$ `\\`).
  - Output schema remains identical: no new columns added.
  - Verify 100% equivalence via the golden parser test.

- **2.4 Column-Oriented List Buffers & Explicit PyArrow Schema**:
  - Replace row-oriented list-of-dicts (`records = []`) with column-oriented lists (`dict[str, list]`).
  - Predefine static PyArrow schema (`pa.schema([...])`).
  - Convert directly via `pa.Table.from_arrays([pa.array(...)], schema=schema)`, eliminating schema inference and dict allocation overhead.

- **2.5 Bounded Memory with Streaming Row-Groups (`pq.ParquetWriter`)**:
  - Stream ~50k–100k row groups directly to disk through a single `pq.ParquetWriter` per chunk file.
  - Memory per worker is bounded strictly to the active batch buffer.
  - Benchmark `zstd` (level 1) vs `snappy` compression for throughput vs file size.

- **2.6 Configurable Defaults**:
  - Expose `ingest_workers`, `ingest_chunk_size_mb`, `ingest_batch_rows`, and `ingest_compression` in `backend/app/config.py` defaulting to the winning parameters.

---

### Step 3: DuckDB Analysis Stage & Query Determinism

- **3.1 Deterministic Detection SQL**:
  - Replace non-deterministic SQL expressions:
    - `LIST(event_id)[1:24]` $\rightarrow$ `LIST(event_id ORDER BY ts, source_offset)[1:24]`
    - `list_reverse(LIST(event_id))` $\rightarrow$ `LIST(event_id ORDER BY ts DESC, source_offset DESC)`
    - `ANY_VALUE(event_id)` $\rightarrow$ `arg_min(event_id, source_offset)`
    - `list_sort(list_distinct(...))`
  - Verify `events` view exposes numeric `source_offset` (BIGINT) and add if missing.
  - Implement a determinism test: execute detection twice on the same dataset and assert that the full detections table (`rule_id`, `ts`, `entities`, sorted `event_ids`) matches 100% identically.

- **3.2 DuckDB Resource Tuning**:
  - Expose DuckDB `memory_limit`, `threads`, and `temp_directory` in `backend/app/config.py`.
  - Set `SET preserve_insertion_order=false` on connections once deterministic SQL is verified.
  - Calibrate `memory_limit` so total process-tree peak RSS (DuckDB C++ memory + Python heap) stays safely $\le 8\text{ GB}$.

---

### Step 4: Native TIMESTAMP Storage (Optional Step)

- If profiling indicates `TRY_CAST(timestamp AS TIMESTAMPTZ)` is a bottleneck:
  - Store parsed timestamps directly as `pa.timestamp("us", tz="UTC")` in Parquet.
  - Update `events` view to expose native timestamp without per-query casting.
  - **Correctness Gate**: Require 100% identical detections (rule IDs, counts, event IDs) on the 1 GB slice before and after.

---

### Step 5: Final Report & Disk Verification

- **5.1 Disk Space & Scale Check**:
  - Report drive free space (currently ~8.14 GB). Since free space is $<40\text{ GB}$, report that 13–20 GB scale file generation is skipped due to disk constraints.
- **5.2 Final Performance Report**:
  - Compile Before vs After table in `docs/PERF_REPORT.md`:
    - Ingest throughput (MB/s and rows/s)
    - Ingestion wall-clock seconds
    - Peak RSS memory (full process tree)
    - Pipeline analysis duration (Detect, Link, Reach)
    - Extrapolated projections for 15 GB, 30 GB, and 50 GB workloads.
