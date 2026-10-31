# CaseFile

Security log analysis tool with MITRE ATT&CK mapping, incident graph, and attacker reach analysis.

## Features
- Stream-ingest any size of logs (syslog, JSON, CEF, CSV) without loading them all into memory
- YAML-driven detection rules mapped to ATT&CK techniques and tactics
- Automatic incident clustering across hosts, users, and IPs
- Kill-chain ordering by tactic stage (ATT&CK Enterprise matrix)
- Interactive entity graph and attack-path timeline via Cytoscape.js
- "Attacker reach" analysis: what can the attacker pivot to next?
- Optional LLM narrative generation (OpenAI-compatible API)
- Evaluation against planted ground truth (detection rate, label accuracy, order accuracy)
- CLI (`casefile`) and REST API (`/api/v1`)

## Quick Start

```bash
# 1. Create and activate venv
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux/macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure (copy and edit)
cp .env.example .env

# 4. Create data directory
mkdir data

# 5. Run the server
cd backend
uvicorn app.main:app --reload --port 8000

# 6. Open the UI
start http://localhost:8000      # Windows
open  http://localhost:8000      # macOS
```

## CLI Usage

```bash
# Ingest log files
python -m app.cli ingest /path/to/auth.log /path/to/syslog.json

# Run detection + incident linking
python -m app.cli analyse

# List incidents
python -m app.cli incidents

# Show statistics
python -m app.cli stats

# Reset database
python -m app.cli reset
```

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
- `GET  /api/v1/incidents/{id}/graph` – Entity graph (Cytoscape.js)
- `GET  /api/v1/incidents/{id}/path` – Kill-chain path
- `GET  /api/v1/incidents/{id}/reach` – Attacker reach analysis
- `GET  /api/v1/incidents/{id}/report` – Markdown report (`?use_llm=true`)
- `GET  /api/v1/rules` – List loaded rules
- `POST /api/v1/rules/reload` – Reload rules from disk
- `POST /api/v1/evaluate` – Score an incident against ground truth
- `GET  /api/docs` – Interactive Swagger UI

## Scoring Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| Detection rate | Share of planted steps found | Higher is better |
| Label accuracy | Correct ATT&CK technique assigned | Higher is better |
| Order accuracy | Steps found in the right kill-chain order | Higher is better |
| False alarm count | Detections not matched to ground truth | Lower is better |
| Processing time | 15 GB under 1 hour | < 60 min |
| Peak memory | DuckDB `SET memory_limit` via config | < 8 GB |
| Path open time | GET /incidents/{id}/graph | < 500 ms (precomputed) |

## Third-Party Components and Data

| Component | Version | Licence | Purpose |
|-----------|---------|---------|---------|
| **FastAPI** | ≥ 0.115 | MIT | REST API framework |
| **Uvicorn** | ≥ 0.30 | BSD-3 | ASGI server |
| **Pydantic v2** | ≥ 2.8 | MIT | Schema validation |
| **pydantic-settings** | ≥ 2.4 | MIT | Settings from .env |
| **DuckDB** | ≥ 1.0 | MIT | Columnar storage and query |
| **PyArrow** | ≥ 16 | Apache-2 | Parquet I/O via DuckDB |
| **NetworkX** | ≥ 3.3 | BSD-3 | Entity graph and reach analysis |
| **PyYAML** | ≥ 6.0 | MIT | Rule and knowledge YAML loading |
| **httpx** | ≥ 0.27 | BSD-3 | LLM API calls, test client |
| **Typer** | ≥ 0.12 | MIT | CLI |
| **Rich** | ≥ 13.7 | MIT | CLI output formatting |
| **pytest** | ≥ 8.3 | MIT | Test framework |
| **ruff** | ≥ 0.6 | MIT | Linter and formatter |
| **Cytoscape.js** | 3.29 (CDN) | MIT | Interactive graph visualisation (frontend) |
| **MITRE ATT&CK Enterprise** | v14 | CC BY 4.0 | Technique/tactic taxonomy |
| **Atomic Red Team** | commit `placeholder-pin-here` | MIT | Ground-truth attack scripts |
| **Wazuh** | ≥ 4.x | GPL-2 | Optional log source (archive format) |
| **Neo4j** | ≥ 5 (optional) | GPL-3 | Optional graph backend for reach analysis |
| **OpenAI / compatible LLM** | – | – | Optional narrative report generation |
| **scripts/edr_log_generator.py** | 1.0 | Standalone (Python stdlib) | Synthetic EDR log generator (vendor string "Mitigata SimEDR") used for local testing only; produces synthetic endpoint telemetry (ECS JSON / CEF) with pre-tagged ATT&CK metadata without runnable commands |

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

