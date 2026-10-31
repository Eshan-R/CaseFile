"""Incident endpoints: list, get, graph, reach, path."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query

from app.pipeline.path.path_builder import build_path
from app.pipeline.path.reach.engine import get_or_compute_reach
from app.pipeline.report.llm_report import add_narrative
from app.pipeline.report.template import render as render_report
from app.schemas.graph import IncidentGraph, ReachResponse
from app.schemas.incident import Incident, IncidentList
from app.schemas.report import ReportResponse
from app.store import duck
from app.store.duck import utc_now

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
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        hosts=_parse_json_field(row["hosts"], []),
        users=_parse_json_field(row["users"], []),
        src_ips=_parse_json_field(row["src_ips"], []),
        techniques=_parse_json_field(row["techniques"], []),
        steps=steps,
        detection_ids=_parse_json_field(row["detection_ids"], []),
        event_count=row.get("event_count", 0),
        status=row.get("status", "open"),
    )


@router.get("", response_model=IncidentList, summary="List incidents")
def list_incidents(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> IncidentList:
    total, rows = duck.list_incidents(offset=offset, limit=limit)
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

