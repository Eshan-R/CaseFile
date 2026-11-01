"""Tests for incident story API endpoints, caching, evidence drawer, and latency."""

import time
from pathlib import Path

import pytest
from app.config import settings
from app.main import app
from app.schemas.story import AttackStory, StoryAction, StoryStep
from app.store import duck
from fastapi.testclient import TestClient


class FakeTestLLMClient:
    """Test boundary fake client simulating Gemini story generation."""

    def __init__(self):
        self.provider = "gemini"
        self.model = "gemini-3.6-flash"

    def generate_story(self, facts):
        story_steps = []
        for s in facts.steps:
            target_str = ", ".join(s.hosts) if s.hosts else "the target"
            story_steps.append(
                StoryStep(
                    step_order=s.step_order,
                    technique_id=s.technique_id,
                    technique_name=s.technique_name,
                    tactic=s.tactic,
                    headline=f"{s.technique_name} on {target_str}",
                    narrative=f"Observed {s.technique_name} on {target_str}.",
                    cited_event_ids=s.evidence_event_ids[:2],
                    entities_mentioned=[h for h in s.hosts if h],
                    event_count=s.event_count,
                    first_seen=s.first_seen,
                    last_seen=s.last_seen,
                )
            )
        actions = []
        if facts.hosts:
            actions.append(
                StoryAction(
                    priority=1,
                    action="isolate_host",
                    target=facts.hosts[0],
                    rationale=f"Isolate host {facts.hosts[0]}.",
                )
            )
        return AttackStory(
            incident_id=facts.incident_id,
            headline=f"AI Story on {', '.join(facts.hosts)}",
            executive_summary=f"Incident {facts.incident_id} under analysis.",
            attack_path_summary="Kill chain steps executed.",
            steps=story_steps,
            blast_radius_assessment="Contained.",
            recommended_actions=actions,
            story_source="llm",
            source="ai",
            provider="gemini",
            model="gemini-3.6-flash",
            facts_sha256=facts.facts_sha256,
            generated_at="2026-10-31T12:00:00Z",
        )


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def target_incident_id() -> str:
    # Fetch an existing incident from the database or data/run.duckdb
    inc_list = duck.list_incidents()
    inc_items = inc_list[1] if isinstance(inc_list[0], int) else inc_list[0]
    if not inc_items:
        run_db = Path("data/run.duckdb")
        if run_db.exists():
            if duck._conn:
                duck._conn.close()
                duck._conn = None
            settings.duck_path = str(run_db)
            duck.init_db()
            inc_list = duck.list_incidents()
            inc_items = inc_list[1] if isinstance(inc_list[0], int) else inc_list[0]
    if not inc_items:
        pytest.skip("No incidents available in test DuckDB database")
    return inc_items[0]["incident_id"]


def test_get_story_endpoint(client: TestClient, target_incident_id: str):
    start = time.perf_counter()
    resp = client.get(f"/api/v1/incidents/{target_incident_id}/story")
    elapsed = time.perf_counter() - start

    assert resp.status_code == 200
    # Must be non-blocking and fast (well under 500ms)
    assert elapsed < 0.500

    data = resp.json()
    assert data["incident_id"] == target_incident_id
    assert "headline" in data
    assert "executive_summary" in data
    assert "steps" in data
    assert "recommended_actions" in data
    assert data["story_source"] in ("llm", "template")
    assert len(data["facts_sha256"]) == 64


def test_regenerate_story_endpoint(client: TestClient, target_incident_id: str, monkeypatch):
    import app.llm.client as llm_client_mod

    monkeypatch.setattr(llm_client_mod, "get_llm_client", lambda: FakeTestLLMClient())
    resp = client.post(f"/api/v1/incidents/{target_incident_id}/story/regenerate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == target_incident_id
    assert data["story_source"] == "llm"


def test_regenerate_story_template_fallback(client: TestClient, target_incident_id: str, monkeypatch):
    import app.llm.client as llm_client_mod

    monkeypatch.setattr(llm_client_mod, "get_llm_client", lambda: None)
    resp = client.post(f"/api/v1/incidents/{target_incident_id}/story/regenerate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == target_incident_id
    assert data["story_source"] == "template"
    assert "Gemini unavailable" in data.get("fallback_reason", "")


def test_get_story_cache_hit(client: TestClient, target_incident_id: str, monkeypatch):
    import app.llm.client as llm_client_mod

    monkeypatch.setattr(llm_client_mod, "get_llm_client", lambda: FakeTestLLMClient())
    client.post(f"/api/v1/incidents/{target_incident_id}/story/regenerate")

    # After regeneration, GET /story should return cached verified story instantly
    start = time.perf_counter()
    resp = client.get(f"/api/v1/incidents/{target_incident_id}/story")
    elapsed = time.perf_counter() - start

    assert resp.status_code == 200
    assert elapsed < 0.100  # Sub-100ms on cache hit
    data = resp.json()
    assert data["story_source"] == "llm"


def test_get_incident_events_endpoint(client: TestClient, target_incident_id: str):
    # First get story to obtain cited event IDs
    story_resp = client.get(f"/api/v1/incidents/{target_incident_id}/story")
    assert story_resp.status_code == 200
    story_data = story_resp.json()

    cited_ids = []
    for step in story_data.get("steps", []):
        cited_ids.extend(step.get("cited_event_ids", []))

    if cited_ids:
        query_ids = ",".join(cited_ids[:3])
        events_resp = client.get(f"/api/v1/incidents/{target_incident_id}/events?ids={query_ids}")
        assert events_resp.status_code == 200
        events_data = events_resp.json()
        assert isinstance(events_data, list)


def test_get_path_latency(client: TestClient, target_incident_id: str):
    # Strict requirement: GET /incidents/{id}/path must stay under 500ms
    start = time.perf_counter()
    resp = client.get(f"/api/v1/incidents/{target_incident_id}/path")
    elapsed = time.perf_counter() - start

    assert resp.status_code == 200
    assert elapsed < 0.500, f"Path latency {elapsed:.3f}s exceeded 500ms target"
