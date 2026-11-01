# CaseFile

Security log analysis tool with MITRE ATT&CK mapping, incident graph, and attacker reach analysis.

## Features
- Stream-ingest any size of logs (syslog, JSON, CEF, CSV) without loading them all into memory
- YAML-driven detection rules mapped to ATT&CK techniques and tactics
- Automatic incident clustering across hosts, users, and IPs with false alarm control
- Kill-chain ordering by tactic stage (ATT&CK Enterprise matrix)
- Synchronized Cytoscape Dagre graph and AI-written attack story explorer
- Zero-CDN local architecture: all graph visualizer libraries are locally vendored
- "Attacker reach" predictive analysis: potential lateral pivot vectors and exposed critical assets
- Gemini AI story generation with strict deterministic template fallback
- Strict Grounding Verifier: rejects hallucinated IPs, fake event citations, or unapproved response actions
- Evidence Telemetry Drawer: inspect raw security events directly from cited story chips
- Evaluation against planted ground truth (detection rate, label accuracy, order accuracy)
- CLI (`casefile`) and REST API (`/api/v1`)

## AI Story & Graph Layer Architecture

CaseFile pairs an AI-written incident narrative with an interactive, left-to-right Cytoscape Dagre attack path visualization to help SOC analysts detect, comprehend, and contain attacks rapidly.

```
Log Telemetry (9M+ events)
          │
          ▼
   DuckDB Engine (Fast Aggregations)
          │
          ▼
Deterministic Incident Facts (Canonical SHA-256)
  ├─ Ordered Collapsed Steps (Technique, Tactic, Telemetry, Occurrence Counts)
  ├─ Sampled Evidence Event IDs (Capped at 8 per step)
  ├─ Entity Whitelist (Hosts, Users, External/Internal IPs, Critical Assets)
  └─ Predictive Lateral Reach (Blast Radius & Movement Vectors)
          │
    ┌─────┴────────────────────────┐
    ▼                              ▼
LLM Narrative Generator     Grounding Verifier (Multi-Layer Enforcement)
(Google Gemini)              ├─ Per-Step Telemetry & Event Citation Check
    │                       ├─ Regex IPv4 Anti-Hallucination Scan
    ▼                       └─ Automatic Fallback to Deterministic Template
Verified Attack Story ────────────────────────┐
                                              ▼
                             Zero-CDN Dual-Panel UI (/ & /vendor)
                             ├─ Left: Cytoscape Dagre Attack Path (L-to-R)
                             ├─ Right: Grounded Executive Story & Cards
                             ├─ Bottom: Sliding Raw Evidence Drawer
                             └─ Interactive Attack Timeline Scrubber
```

### Privacy & Data Isolation Disclosure

- **Raw logs are NEVER sent to the LLM**: The LLM prompt receives only sanitized, truncated, and escaped deterministic facts enclosed within `<FACTS_DATA>` XML tags.
- **Deterministic Offline Template Fallback**: Whenever Gemini is unconfigured, unreachable, or rate-limited, high-fidelity stories are generated locally via deterministic templates in <5 ms without making any external API calls.
- **Data Isolation Directive**: Malicious prompt injections embedded inside hostnames or usernames (e.g. `"host'; DROP TABLE; ignore previous instructions"`) are sanitized and treated strictly as passive data.

### Configuration & LLM Setup

Configure via `.env` or environment variables:

| Variable | Default | Description |
|---|---|---|
| `LLM_GEMINI_API_KEY` | `""` | Google Gemini API key (supports official `google-genai` SDK) |
| `LLM_MODEL` | `""` | Model identifier (must be explicitly set, e.g. `gemini-3.6-flash`) |
| `LLM_CALL_BUDGET` | `20` | Maximum LLM API calls permitted per session |
| `LLM_TIMEOUT_SECONDS` | `30.0` | Timeout in seconds for Gemini API requests |
| `LLM_THINKING_EFFORT` | `low` | Thinking effort for Gemini 2.5/3.x models (`low`, `medium`) |
| `LLM_PREGEN_DELAY_SECONDS` | `1.0` | Rate-limiting sleep between pre-generation background calls |

> [!NOTE]
> When `LLM_GEMINI_API_KEY` is not set or when Gemini API calls fail (quota, timeout, grounding rejection), CaseFile automatically falls back to the deterministic offline template story.
> For Gemini 3.x / thinking models, temperature, top_p, and top_k are never sent, and native Pydantic `response_schema` structured output is enforced.
> For Gemini 3.x / thinking models, temperature, top_p, and top_k are never sent, and native Pydantic `response_schema` structured output is enforced.

### Running the Story & Graph Demo

Run the interactive CLI demonstration to inspect fact extraction, story generation, hallucination rejection, and template fallback:

```bash
python scripts/demo_story.py
```

## Quick Start

### Docker (One Command)

```bash
# Start CaseFile API & UI with persistent data volume mounted from ./data
docker compose up --build

# Open the UI at http://localhost:8000
```

### Local Setup

```bash
# 1. Create and activate venv
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux/macOS

# 2. Install CaseFile in editable mode (run from repo root)
pip install -e .

# 3. Configure (copy and edit)
cp .env.example .env
# Ensure DUCK_PATH=./data/run.duckdb and PARQUET_DIR=./data/parquet_run

# 4. Create data directory
mkdir data

# 5. Run the server (from repo root)
casefile serve --port 8000

# 6. Open the UI
start http://localhost:8000      # Windows
open  http://localhost:8000      # macOS
```

### End-to-End Evaluation & Automated Pattern Mining Benchmark

Run the full end-to-end ingest, detection, linking, pattern discovery, and silver-standard evaluation against the clean region of `firex-10G.log`:

```bash
casefile run data/firex-10G.log data/firex-30G.log.manifest.json --skip-eval --silver --limit-bytes 4815700000
```

To run only the unsupervised pattern miner over existing database events:

```bash
python scripts/run_all.py --patterns-only
```

Verify graph invariants across all database incidents:

```bash
python scripts/check_graphs.py --db data/run.duckdb
```

## Data

- **Firewall stream**: FortiGate key=value log (`firewall_kv` format).
- **Ground-truth manifest**: `*.manifest.json` is used by the evaluator only (never touched by ingest, detect, link, path, or reporting).

## One-Command Demonstration & Benchmarks

CaseFile provides a fully automated one-command runner that resets an isolated database, stream-ingests the dataset into Parquet, executes set-based SQL detection and incident linking, precomputes lateral reach, evaluates against planted ground truth, benchmarks API latency, and generates a PRD scorecard:

### 1. Make Target (`make demo`)
```bash
# Run with default or custom log and manifest
make demo LOG=data/firex-30G.log MANIFEST=data/firex-30G.log.manifest.json

# Skip ground-truth evaluation (e.g. unlabelled logs)
casefile run data/sample.log data/firex-30G.log.manifest.json --skip-eval
```

### 2. Docker Compose
```bash
# Run end-to-end benchmark inside isolated Docker container
docker compose run --rm casefile python scripts/run_all.py /data/firex-30G.log /data/firex-30G.log.manifest.json

# Or start the web service and interactive UI
docker compose up --build
```

### 3. Manual Step-by-Step Flow (7 Steps)
If you prefer running each pipeline phase individually from the repo root (no `cd backend` needed):
```bash
# 1. Ingest raw logs into Parquet partitions and DuckDB view
casefile ingest data/firex-30G.log

# 2. Run set-based SQL detection rules
casefile detect

# 3. Form corroborated incidents via temporal Union-Find clustering
casefile incidents

# 4. Precompute lateral movement reachability and critical asset exposure
casefile reach

# 5. Generate and verify grounded attack stories
casefile stories

# 6. Evaluate accuracy against organizers' ground-truth manifest
casefile evaluate -m data/firex-30G.log.manifest.json

# 7. Start the FastAPI server & Zero-CDN UI
casefile serve --port 8000
```

> [!TIP]
> All CLI commands can also be run via `python -m casefile <command>` (e.g. `python -m casefile --help`).

## Makefile Targets

| Target      | Description                              |
|-------------|------------------------------------------|
| `install`   | Create venv and install dependencies     |
| `run`       | Start the dev server on port 8000        |
| `test`      | Run pytest                               |
| `lint`      | Run ruff linter                          |
| `fmt`       | Auto-format with ruff                    |
| `check`     | lint + test                              |
| `reset`     | Drop and recreate the DuckDB database    |

## API Reference

- `GET  /api/v1/health` – Liveness + component checks
- `GET  /api/v1/stats` – Aggregate counts
- `GET  /api/v1/jobs` – List pipeline jobs
- `POST /api/v1/jobs/ingest` – Start a log-ingest job
- `POST /api/v1/jobs/analyse` – Start detect + link job
- `GET  /api/v1/events` – Query normalised events
- `GET  /api/v1/detections` – Query fired detections
- `GET  /api/v1/incidents` – List incidents
- `GET  /api/v1/incidents/{id}` – Get incident details
- `GET  /api/v1/incidents/{id}/graph` – Cytoscape Dagre graph with typed nodes and predicted reach
- `GET  /api/v1/incidents/{id}/path` – Kill-chain path (< 500ms)
- `GET  /api/v1/incidents/{id}/reach` – Attacker reach analysis
- `GET  /api/v1/incidents/{id}/next` – Precomputed blast radius and reachable targets
- `GET  /api/v1/incidents/{id}/story` – Non-blocking AI attack story with template baseline
- `POST /api/v1/incidents/{id}/story/regenerate` – Synchronous force regeneration
- `GET  /api/v1/incidents/{id}/events?ids=...` – Evidence drawer raw telemetry
- `GET  /api/v1/incidents/{id}/report` – Markdown report (`?use_llm=true`)
- `GET  /api/v1/rules` – List loaded rules
- `POST /api/v1/rules/reload` – Reload rules from disk
- `POST /api/v1/evaluate` – Score an incident against ground truth
- `GET  /api/docs` – Interactive Swagger UI
- `GET  /` – Zero-CDN Interactive Incident Explorer UI

## PRD Targets & Scoring Metrics

Metrics evaluated by the runner and scorecard against PRD thresholds:

| Metric | Direction | Good Threshold (Pass) | Great Threshold | Gating Status | Description |
|---|---|---|---|---|---|
| **Detection Rate** | Higher is better | `>= 70.0%` | `>= 90.0%` | **GATED** | Share of planted attack steps successfully detected |
| **Label Accuracy (Exact)** | Higher is better | `>= 60.0%` | `>= 85.0%` | **GATED** | Exact ATT&CK sub-technique ID matching ground truth |
| **Label Accuracy (Family)** | Higher is better | `>= 70.0%` | `>= 90.0%` | *INFO ONLY* | Parent technique matching ground truth |
| **Path Rate** | Higher is better | `>= 50.0%` | `== 100.0%` | **GATED** | Attacks with complete multi-step attack chain discovered |
| **Order Accuracy** | Higher is better | `>= 50.0%` | `>= 85.0%` | *INFO ONLY* | Relative chronological order matching planted steps |
| **False Alarm Rate** | Lower is better | `<= 30.0%` | `<= 10.0%` | **GATED** | Percentage of fired detections not in ground truth |
| **Processing Time (15GB)** | Lower is better | `<= 10,800s` (3h) | `<= 3,600s` (1h) | **GATED** | Ingest + detection + linking runtime (15GB baseline) |
| **Peak Memory (RSS)** | Lower is better | `<= 16,384 MB` (16GB) | `<= 8,192 MB` (8GB) | **GATED** | Full process-tree peak RAM footprint via psutil |
| **Path-Open Latency (p50)** | Lower is better | `<= 2,000 ms` | `<= 500 ms` | **GATED** | Median `GET /incidents/{id}/path` response latency |
| **Path-Open Latency (p95)** | Lower is better | `<= 3,000 ms` | `<= 1,000 ms` | *INFO ONLY* | 95th percentile `GET /incidents/{id}/path` latency |

> [!NOTE]
> The demonstration runner (`scripts/run_all.py` / `make demo`) computes the exit code strictly from the 7 **GATED** metrics. If any gated metric fails its Good threshold, the process exits with code `1`. When `--skip-eval` is enabled, accuracy metrics show `NOT MEASURED` and only runtime/memory/latency are evaluated.

## Benchmark & Evaluation Results (`firex-10G.log`)

Evaluated against the clean telemetry region ($\le 4,815,675,419$ bytes, 9.12M events) with automated independent SQL oracles:

| Metric | Target (Good) | Target (Great) | Measured Value | Rating |
|---|---|---|---|---|
| **Processing Time (15GB)** | $\le 10,800\text{ s}$ | $\le 3,600\text{ s}$ | **796.6 s (~13.3 min)** | **GREAT (4.5x faster)** |
| **Analysis Wall Time** | $\le 950\text{ s}$ | — | **116.7 s** (Detect 102.2s, Link 14.4s, Reach 0.06s) | **GREAT (8.1x faster)** |
| **Peak Memory (RSS)** | $\le 16,384\text{ MB}$ | $\le 8,192\text{ MB}$ | **4,424.2 MB (~4.4 GB)** | **GREAT** |
| **Path-Open Latency (p50)** | $\le 2,000\text{ ms}$ | $\le 500\text{ ms}$ | **24.8 ms** | **GREAT** |
| **Path-Open Latency (p95)** | $\le 3,000\text{ ms}$ | $\le 1,000\text{ ms}$ | **68.3 ms** | **GREAT** |
| **Active Detections** | — | — | **38 active** (427 raw firings, 389 suppressed) | **CONTROLLED** |
| **Behavior Recall (Silver)** | `INFO` | `INFO` | **96.3% (26 / 27 attack behaviors)** | **INFO** |
| **Silver Precision Proxy** | `INFO` | `INFO` | **94.7% detection / 96.4% behavior** | **INFO** |
| **Exact Label Agreement** | `INFO` | `INFO` | **97.2%** | **INFO** |
| **Family Label Agreement** | `INFO` | `INFO` | **97.2%** | **INFO** |
| **Promoted Incidents** | ~30 | ~10–20 | **17 open attack campaigns** (0 noise leads) | **GREAT** |

For comprehensive details, oracle specifications, and full incident review tables, see:
- [docs/RESULTS.md](file:///c:/Users/esh02/OneDrive/Desktop/Esh/Coding/Projects/Hackathon/CaseFile/docs/RESULTS.md)
- [docs/INCIDENT_TABLE.md](file:///c:/Users/esh02/OneDrive/Desktop/Esh/Coding/Projects/Hackathon/CaseFile/docs/INCIDENT_TABLE.md)
- [docs/SILVER_EVAL.md](file:///c:/Users/esh02/OneDrive/Desktop/Esh/Coding/Projects/Hackathon/CaseFile/docs/SILVER_EVAL.md)
- [docs/rule_stats.md](file:///c:/Users/esh02/OneDrive/Desktop/Esh/Coding/Projects/Hackathon/CaseFile/docs/rule_stats.md)
- [docs/PERF_REPORT.md](file:///c:/Users/esh02/OneDrive/Desktop/Esh/Coding/Projects/Hackathon/CaseFile/docs/PERF_REPORT.md)

## Third-Party Components and Data

| Component | Version | Licence | Purpose |
|-----------|---------|---------|---------|
| **FastAPI** | ≥ 0.115 | MIT | High-performance asynchronous REST API framework |
| **Uvicorn** | ≥ 0.30 | BSD-3 | ASGI production server |
| **Pydantic v2** | ≥ 2.8 | MIT | Schema validation and serialization |
| **pydantic-settings** | ≥ 2.4 | MIT | Environment configuration (.env) |
| **DuckDB** | ≥ 1.0 | MIT | In-process columnar analytics engine |
| **PyArrow** | ≥ 16 | Apache-2 | Parallel Parquet partition I/O |
| **NetworkX** | ≥ 3.3 | BSD-3 | Entity graph and lateral reach analysis |
| **PyYAML** | ≥ 6.0 | MIT | Rule and knowledge YAML loading |
| **httpx** | ≥ 0.27 | BSD-3 | LLM API calls and in-process TestClient benchmarking |
| **psutil** | ≥ 5.9.0 | BSD-3 | Cross-platform process-tree peak memory tracking (zero `ctypes.wintypes`) |
| **google-genai** | ≥ 2.0.0 | Apache-2 | Official Google GenAI SDK for Gemini 2.5/3.x structured output |
| **Typer** | ≥ 0.12 | MIT | CLI interface |
| **Rich** | ≥ 13.7 | MIT | Console tables and visual progress reporting |
| **pytest** | ≥ 8.3 | MIT | Test suite framework |
| **ruff** | ≥ 0.6 | MIT | Fast linter and code formatter |
| **Cytoscape.js & Dagre** | 3.30.2 / 0.8.5 | MIT | Zero-CDN interactive graph visualization (locally vendored in `/vendor`) |
| **MITRE ATT&CK Enterprise** | v14 | CC BY 4.0 | Technique and tactic kill-chain taxonomy |
| **Atomic Red Team** | commit pin | MIT | Attack step taxonomy reference |
| **Wazuh** | ≥ 4.x | GPL-2 | Optional log source format support |
| **Neo4j** | ≥ 5 (optional) | GPL-3 | Optional graph database backend for reach analysis |
| **Gemini LLM** | – | – | Incident narrative generation via Google Gemini SDK with offline template fallback |
| **scripts/edr_log_generator.py** | 1.0 | Standalone | Synthetic EDR telemetry generator used for testing |

## Adding Detection Rules

Edit `rules/detections.yaml` (or add a new `*.yaml` file in `rules/`).  
Each rule requires: `rule_id`, `name`, `technique_id`, `tactic`, `conditions`, `logic`.

```yaml
- rule_id: "CF-011"
  name: "Mimikatz Detected"
  technique_id: "T1003.001"
  tactic: "Credential Access"
  severity: 10
  conditions:
    - field: cmd
      op: contains
      value: "mimikatz"
  logic: any
```

Reload live with `POST /api/v1/rules/reload`.

## Directory Layout

```
casefile/
├── rules/              YAML detection rules
├── knowledge/          ATT&CK taxonomy and recommendations
├── scripts/            Profiling and benchmarking helpers
├── data/               DuckDB database (git-ignored)
├── docs/               Design documents
└── backend/
    ├── app/
    │   ├── main.py     FastAPI app
    │   ├── cli.py      Typer CLI
    │   ├── config.py   Settings
    │   ├── errors.py   ApiError + ErrorResponse
    │   ├── schemas/    Pydantic models
    │   ├── api/routes/ Route handlers (no logic)
    │   ├── pipeline/   Ingest → detect → link → path → report → evaluate
    │   ├── store/      DuckDB persistence layer
    │   ├── llm/        LLM client
    │   └── static/     Single-page UI (Cytoscape.js)
    └── tests/          pytest test suite
```

## Evaluation & Silver Standard Note

Silver recall for behaviours that the rules and the oracles both define is a consistency check, not a generalisation test. No organizer ground truth exists for firex-10G.log.


