# UI & Backend Parallel Implementation Tasks

## Agent A: Graph & Story Backend
- [x] A.1 Fix `graph_to_cytoscape` inner loop variable collision (`ak, av` and safe target variable) in `entity_graph.py`
- [x] A.2 Check all other `for k, v in ...` loops in graph builders
- [x] A.3 Fix CIDR subnet and base address matching in `pipeline/report/verifier.py` (allow base address and contained IPs)
- [x] A.4 Add tests for CIDR verifier acceptance/rejection
- [x] A.5 Implement `GET /api/v1/llm/status` in `api/routes/llm.py`
- [x] A.6 Add story metadata (provider, model, generated_at, source, fallback_reason)
- [x] A.7 Create `scripts/check_graphs.py` and `backend/tests/test_graph_invariants.py` asserting all graph invariants across all incidents

## Agent B: Pattern Discovery & Jobs
- [x] B.1 Implement `POST /api/v1/patterns/mine` background job trigger
- [x] B.2 Apply detection population guard to miners so end-of-file burst does not saturate top 20
- [x] B.3 Support `scripts/run_all.py --patterns-only`
- [x] B.4 Ensure pattern mining saves directly to active DB configured by `settings.duck_path`

## Agent C: Attack Logs
- [x] C.1 Define Pydantic schema in `backend/app/schemas/logs.py`
- [x] C.2 Implement `GET /api/v1/incidents/{id}/logs` in `backend/app/api/routes/logs.py` (pagination, severity counts, combined effective_severity, empty-events graceful fallback)
- [x] C.3 Unit tests in `backend/tests/test_attack_logs.py` (7 tests passed in 3.47s)

## Agent D: Predictive Next Paths
- [x] D.1 Define Pydantic schema in `backend/app/schemas/next_paths.py`
- [x] D.2 Implement reach service deterministic ranking in `pipeline/path/reach/service.py` (max 3 paths, sensitive ports, next tactic support)
- [x] D.3 Implement `GET /api/v1/incidents/{id}/next-paths` with in-memory caching (<500ms)
- [x] D.4 Inject predicted edges and ghost nodes into `/api/v1/incidents/{id}/graph`
- [x] D.5 Unit tests in `backend/tests/test_next_paths.py` (9 tests passed in 4.31s)

## Agent E: UI Interface (`static/index.html`)
- [x] E.1 Graph pane error banner and selector fix (`edge[?predicted]`, `edge[label = "predicted_reach"]`)
- [x] E.2 Ensure single incident change listener registration
- [x] E.3 Rename "Active Campaign" to "Incident" with title formatting, severity, time span, and tooltip
- [x] E.4 Story header source badge (AI / Mock / Template), provider/model, and LLM status notice
- [x] E.5 "Attack Logs" interactive panel under the graph with severity styling and bidirectional graph highlighting
- [x] E.6 "Possible next paths" card in story panel with likelihood bar, confidence, and action
- [x] E.7 Replace hard-coded pill with `GET /api/v1/evaluate/latest` dynamic silver summary
- [x] E.8 Patterns tab "Run discovery" button, job state indicator, and refresh

## Integrator: Assembly & Final Acceptance
- [x] I.1 Register new routers (`logs.py`, `next_paths.py`, `evaluate.py`) in `backend/app/main.py` and `schemas/__init__.py`
- [x] I.2 Ensure server startup logs active `DUCK_PATH` and `PARQUET_DIR`
- [x] I.3 Run pattern mining on `data/run.duckdb`
- [x] I.4 Execute `scripts/check_graphs.py` across all incidents
- [x] I.5 Run complete `pytest` (214 passed) and `ruff check .` (All checks passed!)
- [x] I.6 Freeze build and generate final audit report

## Final Code Freeze (10:40 Freeze / 11:00 Submission)
- [x] F.1 Mock LLM removal: completely deleted `MockLLMClient`, `USE_MOCK_LLM`, and `LLM_PROVIDER=mock`. Gemini is exclusive provider.
- [x] F.2 Persona: passed senior security engineer SOC brief system instruction to Gemini with strict facts containment.
- [x] F.3 Deterministic Template Story fallback labeled `Template (Gemini unavailable: <reason>)` on missing key, quota, or error.
- [x] F.4 Cytoscape Dagre horizontal spine layout (`rankDir: 'LR'`, `ranker: 'network-simplex'`, step nodes on spine, entity lanes, ghost nodes on right).
- [x] F.5 Single `NODE_STYLE` constant driving both Cytoscape styling and dynamic visual SVG legend with node hover tooltips.
- [x] F.6 Scrubber timeline device coloring (Not seen: gray, Touched: amber, Compromised: red + pulse, Predicted: purple) with dynamic compromise counter.
- [x] F.7 Updated `.env.example` and `README.md` removing all mock text and documenting Gemini + Template fallback.
- [x] F.8 Final integration verification: `scripts/check_graphs.py` (0 violations), `pytest` (214 passed), `ruff check .` (0 errors), `scripts/verify_live_api.py` (all 10 contracts verified).


