# CaseFile UI & Full System Implementation Plan

## 1. Overview & Constraints
- **Target Deadline**: Frozen build by 10:15 local time (Submission at 11:00).
- **Zero New CDN Dependencies**: All styling and scripts must use existing vendored assets (`static/vendor/*`).
- **Zero Hardcoded Values**: No dataset-specific IPs, usernames, timestamps, or offsets.
- **DuckDB Concurrency Guard**: Test suites and agents must run against temporary or isolated test databases (`data/run_agentX.duckdb`), never conflicting on `data/run.duckdb`.
- **Integrator Gate**: Router registrations in `app/main.py` and `schemas/__init__.py` will be performed strictly by the Integrator once sub-agents complete.

---

## 2. API Contracts

### 2.1 LLM Status (`GET /api/v1/llm/status`)
- **Response**:
  ```json
  {
    "provider": "mock",
    "model": "gemini-3.6-flash",
    "mode": "mock", // "live" | "mock"
    "key_configured": false,
    "budget_remaining": 20
  }
  ```
  *(Note: API keys are strictly never returned).*

### 2.2 Pattern Mining Trigger (`POST /api/v1/patterns/mine`)
- **Response**:
  ```json
  {
    "job_id": "job_mine_patterns_123456"
  }
  ```
- **Job Status** queried via existing `GET /api/v1/jobs/{job_id}`.

### 2.3 Incident Attack Logs (`GET /api/v1/incidents/{id}/logs`)
- **Query Parameters**:
  - `limit`: int (default 100)
  - `offset`: int (default 0)
  - `severity`: optional filter string (`critical`, `high`, `medium`, `low`, `info`)
- **Response**:
  ```json
  {
    "total": 12,
    "counts": {
      "critical": 2,
      "high": 4,
      "medium": 5,
      "low": 1,
      "info": 0
    },
    "items": [
      {
        "event_id": "ev_0_12345",
        "ts": "2026-10-23T10:52:40Z",
        "src_ip": "10.10.10.44",
        "dst_ip": "10.10.20.20",
        "dst_port": 80,
        "action": "accept",
        "attack": "SQL_Injection",
        "level": "warning",
        "effective_severity": 8,
        "severity_label": "high",
        "detections": [
          {
            "rule_id": "web-payload-sqli",
            "rule_name": "Web SQL Injection Attack",
            "technique_id": "T1190",
            "severity": 8
          }
        ],
        "raw": "log raw string..."
      }
    ]
  }
  ```
- **Severity Mapping**:
  - `effective_severity`: max(highest citing detection severity, mapped FortiGate level).
  - Detection severity: 9-10 `critical`, 7-8 `high`, 4-6 `medium`, 1-3 `low`.
  - Log level: `emergency`/`alert` &rarr; `critical`; `critical`/`error` &rarr; `high`; `warning` &rarr; `medium`; `notice` &rarr; `low`; `information`/`debug` &rarr; `info`.
  - Fallback: If empty, returns 200 with `total: 0` and explanation.

### 2.4 Incident Next Paths (`GET /api/v1/incidents/{id}/next-paths`)
- **Response**:
  ```json
  {
    "predicted": true,
    "disclaimer": "Based on access observed in the logs; a prediction, not an observation.",
    "reason": null,
    "paths": [
      {
        "rank": 1,
        "from_entity": "10.10.10.44",
        "to_entity": "10.10.20.15",
        "service": "RDP",
        "port": 3389,
        "predicted_technique": "T1021.001",
        "predicted_tactic": "lateral_movement",
        "likelihood": 0.85,
        "confidence": "high",
        "evidence": {
          "allowed_connections_observed": 14,
          "last_observed": "2026-10-28T20:30:00Z",
          "asset_criticality": 3,
          "target_already_touched": false,
          "tactic_transition_support": true
        },
        "monitor_or_block": "Block inbound port 3389 on 10.10.20.15 from 10.10.10.44"
      }
    ]
  }
  ```
- **Constraints**: Maximum 3 paths, strictly deterministic evidence ranking, sensitive services only (SMB 445, RDP 3389, SSH 22, DB, admin HTTPS).

### 2.5 Graph Invariants (`GET /api/v1/incidents/{id}/graph`)
- `nodes` and `edges` non-empty.
- Every edge's `source` and `target` must strictly exist in `nodes`.
- Every node has a `data` dictionary with unique `id`.
- Predicted next paths included with `predicted: true` and ghost nodes.

### 2.6 Silver Standard Latest (`GET /api/v1/evaluate/latest`)
- **Response**:
  ```json
  {
    "kind": "silver",
    "behavior_recall": 0.963,
    "row_recall": 0.532,
    "precision_proxy": 0.947,
    "exact_label_agreement": 0.972,
    "caveat": "SILVER STANDARD: agreement with independent SQL oracles on firex-10G.log. No organizer ground truth exists for this file. Not a measure of true accuracy."
  }
  ```

---

## 3. Work Split & Ownership

| Agent / Role | Scope & Files Owned | Key Deliverables |
|---|---|---|
| **Agent A** (Graph & Story Backend) | `backend/app/pipeline/link/entity_graph.py`, `backend/app/pipeline/report/*`, `backend/app/api/routes/incidents.py` (graph & story), `backend/app/api/routes/llm.py` | Fix Cytoscape target attribute overwrite bug (`ak, av`); story CIDR grounding fix (`71.54.76.0/24` subnet and base address matching); `/api/v1/llm/status`; story metadata; `scripts/check_graphs.py` and `backend/tests/test_graph_invariants.py`. |
| **Agent B** (Patterns Engine & Job) | `backend/app/pipeline/patterns/*`, `backend/app/api/routes/patterns.py`, `backend/app/api/routes/jobs.py`, `scripts/run_all.py` | `POST /api/v1/patterns/mine` background job; population guard in miners (suppress end-of-file burst window from flooding top 20); server database synchronization; `run_all.py --patterns-only` mode. |
| **Agent C** (Attack Logs Endpoint) | `backend/app/schemas/logs.py`, `backend/app/api/routes/logs.py`, `backend/tests/test_attack_logs.py` | `GET /api/v1/incidents/{id}/logs` with pagination, counts, filtering, severity calculation from detection & FortiGate logs. |
| **Agent D** (Next Paths & Reach) | `backend/app/schemas/next_paths.py`, `backend/app/pipeline/path/reach/*`, `backend/app/api/routes/next_paths.py`, `backend/tests/test_next_paths.py` | `GET /api/v1/incidents/{id}/next-paths`; deterministic ranking of top 3 sensitive next steps; caching (<500ms); ghost nodes in `/graph`. |
| **Agent E** (UI Frontend) | `static/index.html` (Exclusive owner) | Error banner in graph pane; cytoscape selector fix `edge[?predicted]`; single change listener; "Incident" title naming; AI story source badge & spinner; "Attack Logs" table with severity badges and bidirectional graph highlighting; "Possible next paths" card; Silver eval pill; Patterns tab "Run discovery". |
| **Integrator** (Parent) | `backend/app/main.py`, `backend/app/schemas/__init__.py`, verification scripts, documentation | Register routes, run `scripts/check_graphs.py`, execute mining on `data/run.duckdb`, verify end-to-end stack, update `docs/UI_TASKS.md`, run pytest and ruff. |

