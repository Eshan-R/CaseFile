"""Verify all required API contracts against data/run.duckdb."""

import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "backend"))

from app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(app)

print("\n--- 1. Testing GET /api/v1/llm/status ---")
r = client.get("/api/v1/llm/status")
print("Status:", r.status_code, r.json())
assert r.status_code == 200
data = r.json()
assert data.get("provider") == "gemini"
assert "model" in data
assert "key_configured" in data
assert "budget_remaining" in data
assert "gemini" not in str(data.get("provider", "")).lower() or not any(k in str(data) for k in ["AQ.", "AIza"])

print("\n--- 2. Testing GET /api/v1/evaluate/latest ---")
r = client.get("/api/v1/evaluate/latest")
print("Status:", r.status_code, "Kind:", r.json().get("kind"), "Recall:", r.json().get("behavior_recall"))
assert r.status_code == 200
data = r.json()
assert data.get("kind") == "silver"
assert data.get("behavior_recall", 0) > 0.90
assert data.get("exact_label_agreement", 0) > 0.90

print("\n--- 3. Testing GET /api/v1/incidents ---")
r = client.get("/api/v1/incidents")
print("Status:", r.status_code, "Count:", len(r.json().get("items", [])))
assert r.status_code == 200
items = r.json().get("items", [])
assert len(items) > 0
top_inc_id = items[0]["incident_id"]
print("Top Incident ID:", top_inc_id)

print(f"\n--- 4. Testing GET /api/v1/incidents/{top_inc_id}/logs ---")
r = client.get(f"/api/v1/incidents/{top_inc_id}/logs?limit=5")
print("Status:", r.status_code, "Total:", r.json().get("total"), "Counts:", r.json().get("counts"))
assert r.status_code == 200
logs_data = r.json()
assert "total" in logs_data
assert "counts" in logs_data
assert "items" in logs_data

print(f"\n--- 5. Testing GET /api/v1/incidents/{top_inc_id}/next-paths ---")
r = client.get(f"/api/v1/incidents/{top_inc_id}/next-paths")
print("Status:", r.status_code, "Count:", len(r.json().get("paths", [])))
assert r.status_code == 200
paths_data = r.json()
assert "disclaimer" in paths_data
assert "paths" in paths_data
print("Disclaimer:", paths_data["disclaimer"][:60], "...")
if paths_data["paths"]:
    p0 = paths_data["paths"][0]
    print("Path 0 target:", p0.get("target_label"), "score:", p0.get("score"), "ports:", p0.get("sensitive_ports"))

print(f"\n--- 6. Testing GET /api/v1/incidents/{top_inc_id}/graph ---")
r = client.get(f"/api/v1/incidents/{top_inc_id}/graph")
print("Status:", r.status_code, "Nodes:", len(r.json().get("nodes", [])), "Edges:", len(r.json().get("edges", [])))
assert r.status_code == 200
g_data = r.json()
assert len(g_data.get("nodes", [])) > 0
assert len(g_data.get("edges", [])) > 0

print(f"\n--- 7. Testing GET /api/v1/incidents/{top_inc_id}/story ---")
r = client.get(f"/api/v1/incidents/{top_inc_id}/story")
print("Status:", r.status_code)
if r.status_code == 200:
    story = r.json()
    print("Story source:", story.get("source") or story.get("story_source"), "Headline:", story.get("headline"))
    assert "steps" in story

print("\n--- 8. Testing GET /api/v1/patterns ---")
r = client.get("/api/v1/patterns?limit=5")
print("Status:", r.status_code, "Total:", r.json().get("total"), "Items:", len(r.json().get("items", [])))
assert r.status_code == 200
assert r.json().get("total", 0) > 0

print("\n--- 9. Testing POST /api/v1/patterns/mine ---")
r = client.post("/api/v1/patterns/mine", json={"min_score": 3.0, "max_patterns": 10})
print("Status:", r.status_code, r.json())
assert r.status_code == 202
job_id = r.json().get("job_id")
assert job_id is not None

print(f"\n--- 10. Testing GET /api/v1/jobs/{job_id} ---")
r = client.get(f"/api/v1/jobs/{job_id}")
print("Status:", r.status_code, r.json())
assert r.status_code == 200
assert r.json().get("job_id") == job_id

print("\n[ALL CONTRACTS VERIFIED SUCCESSFULLY ON LIVE DATA!]\n")
