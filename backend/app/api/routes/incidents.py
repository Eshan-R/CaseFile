"""Incident endpoints: list, get, graph, reach, path."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query

from app.config import settings
from app.pipeline.path.path_builder import build_path
from app.pipeline.path.reach.engine import get_or_compute_reach
from app.pipeline.report.facts import build_incident_facts
from app.pipeline.report.llm_report import add_narrative, generate_template_story
from app.pipeline.report.template import render as render_report
from app.pipeline.report.verifier import generate_and_verify_story
from app.schemas.facts import IncidentFacts
from app.schemas.graph import IncidentGraph, ReachResponse
from app.schemas.incident import Incident, IncidentList
from app.schemas.reach import NextReach
from app.schemas.report import ReportResponse
from app.schemas.story import AttackStory
from app.store import duck
from app.store.duck import utc_now

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _parse_json_field(val, default):
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return default
    return val if val is not None else default


def _row_to_incident(row: dict) -> Incident:
    steps_raw = _parse_json_field(row["steps"], [])
    # Rebuild AttackStep objects
    from app.schemas.incident import AttackStep
    steps = [AttackStep(**s) for s in steps_raw] if steps_raw else []

    return Incident(
        incident_id=row["incident_id"],
        title=row["title"],
        severity=row["severity"],
        risk_score=float(row.get("risk_score", 0.0) or 0.0),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        hosts=_parse_json_field(row["hosts"], []),
        users=_parse_json_field(row["users"], []),
        src_ips=_parse_json_field(row["src_ips"], []),
        techniques=_parse_json_field(row["techniques"], []),
        steps=steps,
        detection_ids=_parse_json_field(row["detection_ids"], []),
        detection_count=int(row.get("detection_count", 0) or 0),
        event_count=row.get("event_count", 0),
        status=row.get("status", "open"),
        ips_context=_parse_json_field(row.get("ips_context"), []),
    )


@router.get("", response_model=IncidentList, summary="List incidents")
def list_incidents(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    show_leads: bool = Query(False, description="Include lead rows (status=lead)"),
    status: str | None = Query(None, description="Filter by status (open, alert, lead, closed)"),
) -> IncidentList:
    total, rows = duck.list_incidents(offset=offset, limit=limit, show_leads=show_leads, status=status)
    return IncidentList(total=total, items=[_row_to_incident(r) for r in rows])


@router.get("/{incident_id}", response_model=Incident, summary="Get one incident")
def get_incident(incident_id: str) -> Incident:
    row = duck.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    return _row_to_incident(row)


@router.get("/{incident_id}/graph", response_model=IncidentGraph, summary="Entity + attack path graph")
def get_graph(incident_id: str) -> IncidentGraph:
    row = duck.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    graph_json = row.get("graph_json")
    if not graph_json:
        raise HTTPException(status_code=404, detail="Graph not yet computed for this incident")
    data = json.loads(graph_json)

    # Merge precomputed reach edges if available
    reach_row = duck.get_incident_next(incident_id)
    if reach_row and "data" in reach_row:
        reach_data = json.loads(reach_row["data"]) if isinstance(reach_row["data"], str) else reach_row["data"]
        existing_node_ids = {n["id"] for n in data.get("nodes", [])}
        existing_edge_ids = {e["id"] for e in data.get("edges", [])}
        seed_hosts = reach_data.get("compromised_nodes", [])
        primary_seed = seed_hosts[0] if seed_hosts else (list(existing_node_ids)[0] if existing_node_ids else None)
        crit_assets = set(reach_data.get("blast_radius", {}).get("critical_assets_reached", []))

        if primary_seed and primary_seed not in existing_node_ids:
            seed_type = "critical_asset" if primary_seed in crit_assets else "internal_host"
            data.setdefault("nodes", []).append({
                "id": primary_seed,
                "label": primary_seed,
                "kind": seed_type,
                "data": {"id": primary_seed, "label": primary_seed, "kind": seed_type, "type": seed_type},
            })
            existing_node_ids.add(primary_seed)

        for t in reach_data.get("reachable_targets", [])[:15]:
            tgt_id = str(t.get("target_label", t.get("target_id", "")))
            if not tgt_id or not primary_seed:
                continue
            if tgt_id not in existing_node_ids:
                tgt_type = "critical_asset" if tgt_id in crit_assets else "internal_host"
                data.setdefault("nodes", []).append({
                    "id": tgt_id,
                    "label": tgt_id,
                    "kind": tgt_type,
                    "data": {"id": tgt_id, "label": tgt_id, "kind": tgt_type, "type": tgt_type},
                })
                existing_node_ids.add(tgt_id)

            e_id = f"e_{primary_seed}_{tgt_id}"
            if e_id not in existing_edge_ids:
                data.setdefault("edges", []).append({
                    "id": e_id,
                    "source": primary_seed,
                    "target": tgt_id,
                    "label": "predicted_reach",
                    "data": {
                        "id": e_id,
                        "source": primary_seed,
                        "target": tgt_id,
                        "label": "predicted_reach",
                        "predicted": True,
                        "reason": str(t.get("reason", "")),
                        "priority": str(t.get("priority", "medium")),
                        "hops": int(t.get("hops", 1)),
                    },
                })
                existing_edge_ids.add(e_id)

    from app.schemas.graph import GraphEdge, GraphNode
    return IncidentGraph(
        incident_id=incident_id,
        nodes=[GraphNode(**n) for n in data.get("nodes", [])],
        edges=[GraphEdge(**e) for e in data.get("edges", [])],
    )


@router.get("/{incident_id}/reach", response_model=ReachResponse, summary="Attacker reach from current foothold")
def get_reach(incident_id: str) -> ReachResponse:
    row = duck.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    data = get_or_compute_reach(incident_id)
    from app.schemas.graph import ReachNode
    return ReachResponse(
        incident_id=incident_id,
        seed_hosts=data.get("seed_hosts", []),
        reachable=[ReachNode(**n) for n in data.get("reachable", [])],
    )


@router.get("/{incident_id}/next", response_model=NextReach, summary="Precomputed next reach & predicted attack paths")
def get_incident_next(incident_id: str) -> NextReach:
    """Return precomputed reach analysis for an incident.
    
    Results are strictly precomputed into incident_next; never computed on request.
    """
    row = duck.get_incident_next(incident_id)
    if not row:
        inc = duck.get_incident(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
        raise HTTPException(
            status_code=404,
            detail=f"Reach analysis not precomputed for incident {incident_id!r}. Results must be precomputed into incident_next.",
        )

    data = json.loads(row["data"]) if isinstance(row["data"], str) else row["data"]
    return NextReach(**data)


@router.get("/{incident_id}/path", summary="Ordered kill-chain attack path")
def get_path(incident_id: str) -> dict:
    row = duck.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    steps = build_path(incident_id)
    return {"incident_id": incident_id, "steps": steps, "total": len(steps)}


@router.get("/{incident_id}/report", response_model=ReportResponse, summary="Generate Markdown report")
def get_report(incident_id: str, use_llm: bool = Query(False)) -> ReportResponse:
    row = duck.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    content = render_report(incident_id)
    if use_llm:
        content = add_narrative(content)
    return ReportResponse(
        incident_id=incident_id,
        content=content,
        generated_at=utc_now(),
        llm_used=use_llm,
    )


def _bg_generate_story(facts: IncidentFacts) -> None:
    try:
        story = generate_and_verify_story(facts)
        duck.save_incident_story(
            facts.incident_id,
            story.model_dump_json(),
            story.story_source,
            facts.facts_sha256,
            story.generated_at,
        )
    except Exception as exc:
        logger.warning("Background story generation failed for %s: %s", facts.incident_id, exc)


@router.get("/{incident_id}/story", response_model=AttackStory, summary="Get AI-written attack story")
def get_story(incident_id: str, background_tasks: BackgroundTasks) -> AttackStory:
    row = duck.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    facts = build_incident_facts(incident_id)

    cached = duck.get_incident_story(incident_id)
    if cached and cached.get("facts_sha256") == facts.facts_sha256:
        try:
            story = AttackStory.model_validate_json(cached["story_json"])
            if not story.provider:
                story.provider = "gemini" if story.story_source == "llm" else "template"
            if not story.model:
                story.model = settings.llm_model
            if not story.source:
                story.source = "template" if story.story_source == "template" else "ai"
            if not story.generated_at:
                story.generated_at = cached.get("generated_at") or utc_now()
            return story
        except Exception:
            pass

    # Generate deterministic template story immediately
    template_story = generate_template_story(facts)
    # Trigger background generation for LLM story
    background_tasks.add_task(_bg_generate_story, facts)
    return template_story


@router.post(
    "/{incident_id}/story/regenerate",
    response_model=AttackStory,
    summary="Force synchronous regeneration of AI attack story",
)
def regenerate_story(incident_id: str) -> AttackStory:
    row = duck.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    facts = build_incident_facts(incident_id)
    story = generate_and_verify_story(facts)
    duck.save_incident_story(
        incident_id,
        story.model_dump_json(),
        story.story_source,
        facts.facts_sha256,
        story.generated_at,
    )
    return story


@router.get("/{incident_id}/events", summary="Get raw telemetry events for incident evidence drawer")
def get_incident_events(
    incident_id: str, ids: str = Query(..., description="Comma-separated event IDs")
) -> list[dict]:
    row = duck.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    event_ids = [eid.strip() for eid in ids.split(",") if eid.strip()]
    return duck.get_events_batch(event_ids)


