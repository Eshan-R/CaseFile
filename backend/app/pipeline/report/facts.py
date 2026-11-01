"""Deterministic incident fact extraction for grounded narrative and graph visualization."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.schemas.facts import FactStep, IncidentFacts, ReachFacts, ReachFactTarget
from app.store import duck

logger = logging.getLogger(__name__)

# MITRE ATT&CK technique ID to human-readable name mapping
TECHNIQUE_NAMES: dict[str, str] = {
    "T1003": "OS Credential Dumping",
    "T1021": "Remote Services",
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1068": "Exploitation for Privilege Escalation",
    "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts",
    "T1087": "Account Discovery",
    "T1090": "Proxy",
    "T1110": "Brute Force",
    "T1190": "Exploit Public-Facing Application",
    "T1204": "User Execution",
    "T1499": "Endpoint Denial of Service",
    "T1505": "Server Software Component",
    "T1566": "Phishing",
}


def get_technique_name(technique_id: str) -> str:
    """Return friendly name for a technique ID, falling back to ID if unmapped."""
    base_id = technique_id.split(".")[0].strip()
    return TECHNIQUE_NAMES.get(base_id, technique_id)


def sample_evidence_event_ids(event_ids: list[str], max_sample: int = 8) -> list[str]:
    """Sample up to max_sample event IDs preserving first and last occurrences."""
    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for eid in event_ids:
        if eid and eid not in seen:
            seen.add(eid)
            deduped.append(eid)

    if len(deduped) <= max_sample:
        return deduped

    half = max_sample // 2
    first_half = deduped[:half]
    remaining = [e for e in deduped[-half:] if e not in first_half]
    combined = first_half + remaining
    return combined[:max_sample]


def build_incident_facts(
    incident_id: str,
    incident_dict: dict[str, Any] | None = None,
    reach_dict: dict[str, Any] | None = None,
) -> IncidentFacts:
    """Extract deterministic, fully grounded facts for an incident.

    Args:
        incident_id: Unique incident identifier.
        incident_dict: Optional pre-loaded incident record (useful for testing).
        reach_dict: Optional pre-loaded reach data (useful for testing).

    Returns:
        IncidentFacts object with stable facts_sha256.
    """
    if incident_dict is None:
        incident_dict = duck.get_incident(incident_id)

    if not incident_dict:
        raise ValueError(f"Incident {incident_id} not found")

    def _parse_json(val: Any, default: Any) -> Any:
        if val is None:
            return default
        if isinstance(val, list | dict):
            return val
        if isinstance(val, str):
            try:
                return json.loads(val)
            except Exception:
                return default
        return default

    hosts: list[str] = _parse_json(incident_dict.get("hosts"), [])
    users: list[str] = _parse_json(incident_dict.get("users"), [])
    src_ips: list[str] = _parse_json(incident_dict.get("src_ips"), [])
    steps_raw: list[dict[str, Any]] = _parse_json(incident_dict.get("steps"), [])
    detection_ids: list[str] = _parse_json(incident_dict.get("detection_ids"), [])

    # Map detection_id to its event_ids from duckdb detections table if available
    det_event_map: dict[str, list[str]] = {}
    if detection_ids:
        try:
            with duck.cursor() as con:
                # Query in batches or directly
                placeholders = ", ".join(["?" for _ in detection_ids])
                query = f"SELECT detection_id, event_ids FROM detections WHERE detection_id IN ({placeholders})"
                rows = con.execute(query, detection_ids).fetchall()
                for d_id, eids_raw in rows:
                    eids = _parse_json(eids_raw, [])
                    if isinstance(eids, list):
                        det_event_map[d_id] = [str(x) for x in eids if x]
        except Exception as exc:
            logger.debug("Could not batch-query detections for incident %s: %s", incident_id, exc)

    all_event_ids_collected: list[str] = []
    fact_steps: list[FactStep] = []

    for idx, s in enumerate(steps_raw, 1):
        step_order = int(s.get("step_order", idx))
        tech_id = str(s.get("technique_id", "T1000"))
        tech_name = get_technique_name(tech_id)
        tactic = str(s.get("tactic", "unknown"))
        stage = str(s.get("kill_chain_stage") or tactic)
        first_seen = str(s.get("first_seen", incident_dict.get("first_seen", "")))
        last_seen = str(s.get("last_seen", incident_dict.get("last_seen", "")))
        step_hosts = [str(h) for h in s.get("hosts", []) if h]
        step_count = int(s.get("count", 1))

        # Collect event IDs for this step
        step_eids: list[str] = []
        step_det_ids = s.get("detection_ids", [])
        if isinstance(step_det_ids, list):
            for d_id in step_det_ids:
                step_eids.extend(det_event_map.get(d_id, []))

        # If no event IDs found from detection mapping, check step's direct evidence_event_ids
        if not step_eids and "evidence_event_ids" in s:
            direct_eids = s.get("evidence_event_ids", [])
            if isinstance(direct_eids, list):
                step_eids.extend([str(x) for x in direct_eids if x])

        # Step event count is total collected events, or step_count fallback
        step_event_count = len(step_eids) if step_eids else step_count
        sampled_eids = sample_evidence_event_ids(step_eids, max_sample=8)
        all_event_ids_collected.extend(sampled_eids)

        fact_steps.append(
            FactStep(
                step_order=step_order,
                technique_id=tech_id,
                technique_name=tech_name,
                tactic=tactic,
                kill_chain_stage=stage,
                first_seen=first_seen,
                last_seen=last_seen,
                hosts=step_hosts,
                users=[],
                src_ips=[],
                occurrence_count=step_count,
                event_count=step_event_count,
                evidence_event_ids=sampled_eids,
            )
        )

    # Sort steps by step_order
    fact_steps.sort(key=lambda st: st.step_order)

    # Process reach data
    reach_facts: ReachFacts | None = None
    reach_entity_targets: list[str] = []
    if reach_dict is None:
        reach_row = duck.get_incident_next(incident_id)
        if reach_row and "data" in reach_row:
            reach_dict = _parse_json(reach_row["data"], {})

    if reach_dict:
        blast = reach_dict.get("blast_radius", {})
        seed_hosts = [str(h) for h in reach_dict.get("compromised_nodes", []) if h]
        crit_assets = [str(a) for a in blast.get("critical_assets_reached", []) if a]
        raw_targets = reach_dict.get("reachable_targets", [])

        reach_targets: list[ReachFactTarget] = []
        for t in raw_targets[:15]:
            tgt_lbl = str(t.get("target_label", t.get("target_id", "")))
            if tgt_lbl:
                reach_entity_targets.append(tgt_lbl)
                reason = str(t.get("reason", ""))
                # Collect evidence event IDs if provided in reach
                tgt_eids = t.get("evidence_event_ids", [])
                if isinstance(tgt_eids, list):
                    all_event_ids_collected.extend([str(x) for x in tgt_eids if x])

                reach_targets.append(
                    ReachFactTarget(
                        target=tgt_lbl,
                        kind=str(t.get("target_kind", "host")),
                        hops=int(t.get("hops", 1)),
                        priority=str(t.get("priority", "medium")),
                        reason=reason,
                    )
                )

        reach_facts = ReachFacts(
            seed_hosts=seed_hosts,
            hosts_count=int(blast.get("hosts_count", 0)),
            users_count=int(blast.get("users_count", 0)),
            critical_assets=crit_assets,
            reachable_targets=reach_targets,
        )

    # Whitelist of all known entities for grounding and anti-hallucination verification
    all_entities: set[str] = set()
    for h in hosts:
        if h and str(h).strip():
            all_entities.add(str(h).strip())
    for u in users:
        if u and str(u).strip():
            all_entities.add(str(u).strip())
    for s in src_ips:
        if s and str(s).strip():
            all_entities.add(str(s).strip())
    for fs in fact_steps:
        for h in fs.hosts:
            if h and str(h).strip():
                all_entities.add(str(h).strip())
    for rt in reach_entity_targets:
        if rt and str(rt).strip():
            all_entities.add(str(rt).strip())
    if reach_facts:
        for ca in reach_facts.critical_assets:
            if ca and str(ca).strip():
                all_entities.add(str(ca).strip())

    sorted_known_entities = sorted(list(all_entities))
    unique_all_event_ids = sorted(list(dict.fromkeys(all_event_ids_collected)))

    risk_score = float(incident_dict.get("risk_score", 0.0) or 0.0)
    det_count = int(incident_dict.get("detection_count", len(detection_ids)) or 0)
    ev_count = int(incident_dict.get("event_count", len(unique_all_event_ids)) or 0)

    facts = IncidentFacts(
        incident_id=incident_id,
        title=str(incident_dict.get("title", f"Incident {incident_id}")),
        severity=int(incident_dict.get("severity", 5)),
        risk_score=risk_score,
        status=str(incident_dict.get("status", "open")),
        detection_count=det_count,
        event_count=ev_count,
        first_seen=str(incident_dict.get("first_seen", "")),
        last_seen=str(incident_dict.get("last_seen", "")),
        known_entities=sorted_known_entities,
        hosts=[str(h) for h in hosts if h],
        users=[str(u) for u in users if u],
        src_ips=[str(s) for s in src_ips if s],
        steps=fact_steps,
        reach=reach_facts,
        all_event_ids=unique_all_event_ids,
    )

    return facts

