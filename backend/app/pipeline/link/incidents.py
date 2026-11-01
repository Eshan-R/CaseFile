"""Incident builder: clusters related detections into incidents using Union-Find."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from app.config import settings
from app.pipeline.link.entity_graph import build_entity_graph, graph_to_cytoscape
from app.pipeline.path.risk import score_incident
from app.store import duck

logger = logging.getLogger(__name__)


def _to_epoch(ts: Any) -> float:
    """Parse timestamp into POSIX epoch seconds."""
    if isinstance(ts, int | float):
        return float(ts)
    if isinstance(ts, datetime):
        return ts.timestamp()
    if ts:
        try:
            clean = str(ts).replace("Z", "+00:00")
            return datetime.fromisoformat(clean).timestamp()
        except Exception:
            pass
    return 0.0


def _normalize_entity(val: Any) -> str:
    """Normalize entity value for comparison."""
    if not val:
        return ""
    return str(val).strip().lower()


def _is_internal_ip(ip: str) -> bool:
    """Check if IP belongs to private RFC1918 internal address space."""
    import re
    return bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", str(ip)))


TACTIC_ORDER = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]
TACTIC_MAP = {t: i for i, t in enumerate(TACTIC_ORDER)}


def _get_tactic_stage(tactic_str: str) -> int:
    """Map tactic name to integer stage index (0-13) in ATT&CK kill-chain order."""
    clean = str(tactic_str or "").strip().lower().replace(" ", "_").replace("-", "_")
    for t, idx in TACTIC_MAP.items():
        if t in clean:
            return idx
    return -1


def _is_c2_or_exfil(d: dict[str, Any]) -> bool:
    """Check if detection represents command and control or exfiltration."""
    tac = str(d.get("tactic", "")).lower()
    r_id = str(d.get("rule_id", "")).lower()
    return (
        "exfiltration" in tac
        or "command_and_control" in tac
        or "c2" in tac
        or r_id in ("beaconing", "dns-tunnel", "staged-exfil", "dns-tunneling")
    )


class DisjointSet:
    """Union-Find disjoint-set data structure with path compression and rank."""

    def __init__(self, size: int):
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, i: int) -> int:
        if self.parent[i] != i:
            self.parent[i] = self.find(self.parent[i])
        return self.parent[i]

    def union(self, i: int, j: int) -> None:
        root_i = self.find(i)
        root_j = self.find(j)
        if root_i != root_j:
            if self.rank[root_i] < self.rank[root_j]:
                self.parent[root_i] = root_j
            elif self.rank[root_i] > self.rank[root_j]:
                self.parent[root_j] = root_i
            else:
                self.parent[root_j] = root_i
                self.rank[root_i] += 1


HIGH_FIDELITY_RULES = {
    "failed-admin-burst",
    "slow-credential-stuffing",
    "login-success-after-failures",
    "admin-login-external",
    "vpn-impossible-travel",
    "config-logging-disabled",
    "rogue-admin-account",
    "virus-detected-not-blocked",
    "port-scan",
    "lateral-fanout",
    "dns-tunnel",
    "beaconing",
    "staged-exfil",
    "web-payload-sqli",
    "web-payload-xss",
    "web-payload-traversal",
    "web-payload-cmdi",
    "web-shell-upload-path",
    "syn-flood",
    "http-flood",
    "dns-amplification",
}


def build_incidents() -> dict[str, Any]:
    """Read un-grouped detections and form incidents using entity Union-Find clustering.

    Detections sharing an entity within `incident_link_window_seconds` merge into the
    same cluster. Hub entities and firewall devnames are excluded from linking.
    Clusters are filtered and promoted based on tactic breadth and corroborated severity.
    """
    rule_hf_map: dict[str, bool] = {}
    rule_name_map: dict[str, str] = {}
    try:
        from app.pipeline.detect.rule_loader import load_rules
        loaded = load_rules(include_disabled=True)
        rule_hf_map = {r.id: r.high_fidelity for r in loaded}
        rule_name_map = {r.id: r.name for r in loaded}
    except Exception:
        pass

    _, all_dets = duck.list_detections(limit=None)
    all_dets = [d for d in all_dets if not d.get("suppressed")]
    if not all_dets:
        return {"incidents_created": 0, "alerts_created": 0, "total_clusters": 0}

    # Sort detections chronologically
    all_dets.sort(key=lambda d: _to_epoch(d["ts"]))
    det_epochs = [_to_epoch(d["ts"]) for d in all_dets]

    # Bulk fetch entities from events table in a single query
    bulk_entities = duck.get_detection_entities_bulk()

    # Pre-build excluded entities set
    exclude_set = {_normalize_entity(e) for e in settings.incident_exclude_entities if e}

    # Fetch background prevalence detections for IPS context enrichment
    bg_dets: list[dict[str, Any]] = []
    try:
        with duck.cursor() as con:
            rows = con.execute("""
                SELECT detection_id, rule_id, rule_name, technique_id, tactic, host, ts
                FROM detections
                WHERE suppress_reason = 'background-prevalence'
            """).fetchall()
            for r in rows:
                bg_dets.append({
                    "detection_id": r[0],
                    "rule_id": r[1],
                    "rule_name": r[2],
                    "technique_id": r[3],
                    "tactic": r[4],
                    "host": str(r[5] or ""),
                    "ts": str(r[6]),
                    "epoch": _to_epoch(r[6]),
                })
    except Exception as exc:
        logger.debug("Could not fetch background detections for enrichment: %s", exc)

    # Extract clean candidate entities, internal hosts, and external destinations per detection
    det_entities: list[set[str]] = []
    det_internal_hosts: list[set[str]] = []
    det_ext_dsts: list[set[str]] = []

    for d in all_dets:
        d_id = d["detection_id"]
        bulk = bulk_entities.get(d_id, {})

        candidates: set[str] = set()
        internal_hosts: set[str] = set()
        ext_dsts: set[str] = set()

        # Source IPs
        for ip in bulk.get("src_ips", []):
            norm = _normalize_entity(ip)
            if norm and norm not in exclude_set:
                candidates.add(norm)
                if _is_internal_ip(norm):
                    internal_hosts.add(norm)
                else:
                    ext_dsts.add(norm)

        # Destination IPs
        for ip in bulk.get("dst_ips", []):
            norm = _normalize_entity(ip)
            if norm and norm not in exclude_set:
                if _is_internal_ip(norm):
                    candidates.add(norm)
                    internal_hosts.add(norm)
                else:
                    ext_dsts.add(norm)

        # Users
        for u in bulk.get("users", []):
            norm = _normalize_entity(u)
            if norm and norm not in exclude_set:
                candidates.add(norm)

        # Hosts
        for h in bulk.get("hosts", []):
            norm = _normalize_entity(h)
            if norm and norm not in exclude_set:
                candidates.add(norm)
                if _is_internal_ip(norm):
                    internal_hosts.add(norm)

        # Detection-level host
        d_host = _normalize_entity(d.get("host"))
        if d_host and d_host not in exclude_set:
            candidates.add(d_host)
            if _is_internal_ip(d_host):
                internal_hosts.add(d_host)

        # Detection-level src/dst if present
        for fld in ("src_ip", "dst_ip"):
            val = _normalize_entity(d.get(fld))
            if val and val not in exclude_set:
                if _is_internal_ip(val):
                    candidates.add(val)
                    internal_hosts.add(val)
                else:
                    ext_dsts.add(val)

        det_entities.append(candidates)
        det_internal_hosts.append(internal_hosts)
        det_ext_dsts.append(ext_dsts)

    # Hub Cap: an entity that co-occurs with more than N distinct other entities
    # (e.g. a shared server hit by many different clients/attackers),
    # whereas an attacker IP that generates many detections against the same victim is not a hub.
    co_occurring: dict[str, set[str]] = {}
    for ents in det_entities:
        for ent in ents:
            if ent not in co_occurring:
                co_occurring[ent] = set()
            co_occurring[ent].update(ents - {ent})

    hub_threshold = settings.incident_link_hub_threshold
    hubs = {ent for ent, co_ents in co_occurring.items() if len(co_ents) > hub_threshold}
    if hubs:
        logger.info("Excluding %d hub entities from incident linking: %s", len(hubs), hubs)

    # Filter out hub entities from merge sets
    det_valid_entities = [ents - hubs for ents in det_entities]

    # Dual-window Union-Find clustering:
    # 1. 30-minute window for same-rule or same-tactic detections
    # 2. 72-hour window: share internal host IP, different rules, tactic stage does not go backwards by > 1 stage, non-hub (<= 50 detections)
    # 3. Shared external destination for exfiltration or beaconing
    uf = DisjointSet(len(all_dets))
    det_stages = [_get_tactic_stage(d.get("tactic", "")) for d in all_dets]
    det_c2_exfil = [_is_c2_or_exfil(d) for d in all_dets]

    for j in range(len(all_dets)):
        t_j = det_epochs[j]
        d_j = all_dets[j]
        ents_j = det_valid_entities[j]
        internal_j = det_internal_hosts[j] - hubs
        ext_dst_j = det_ext_dsts[j] - hubs
        s_j = det_stages[j]
        is_c2_j = det_c2_exfil[j]

        for i in range(j - 1, -1, -1):
            t_i = det_epochs[i]
            delta_t = t_j - t_i
            if delta_t > 259200.0:  # 72 hours maximum
                break

            d_i = all_dets[i]
            same_rule = (d_i.get("rule_id") == d_j.get("rule_id"))
            same_tactic = (
                bool(d_i.get("tactic"))
                and d_i.get("tactic") == d_j.get("tactic")
            )

            # 1. 30-minute window (<= 1800s) for same-rule or same-tactic detections sharing an entity
            if delta_t <= 1800.0:
                if same_rule or same_tactic or (ents_j & det_valid_entities[i]):
                    if ents_j & det_valid_entities[i]:
                        uf.union(i, j)
                        continue

            # 2. 72-hour window: share internal host IP, different rules, tactic stage does not go backwards by > 1
            if not same_rule and not same_tactic:
                shared_internal = internal_j & (det_internal_hosts[i] - hubs)
                if shared_internal:
                    s_i = det_stages[i]
                    if s_i == -1 or s_j == -1 or s_j >= s_i - 1:
                        uf.union(i, j)
                        continue

            # 3. Shared external destination for exfiltration or beaconing
            if is_c2_j and det_c2_exfil[i]:
                shared_ext = ext_dst_j & (det_ext_dsts[i] - hubs)
                if shared_ext:
                    uf.union(i, j)
                    continue

    # Group detections by root cluster index
    clusters_map: dict[int, list[dict]] = {}
    for i, d in enumerate(all_dets):
        root = uf.find(i)
        clusters_map.setdefault(root, []).append(d)

    incidents_created = 0
    alerts_created = 0
    all_detection_updates: list[tuple[str, str]] = []

    for grp in clusters_map.values():
        if not grp:
            continue

        inc_id = duck.new_id("inc")
        hosts = sorted(list({d["host"] for d in grp if d.get("host") and _normalize_entity(d["host"]) not in exclude_set}))
        if not hosts:
            # Fallback to distinct hosts from group
            hosts = sorted(list({d["host"] for d in grp if d.get("host")})) or ["network"]

        techniques = list(dict.fromkeys(d["technique_id"] for d in grp))
        det_ids = [d["detection_id"] for d in grp]
        first_seen = min(d["ts"] for d in grp)
        last_seen = max(d["ts"] for d in grp)
        severity = max(d["severity"] for d in grp)

        # Collect entities and compute total distinct raw event count
        users: set[str] = set()
        src_ips: set[str] = set()
        total_raw_events = 0
        all_event_ids: list[str] = []

        for d in grp:
            d_id = d["detection_id"]
            bulk = bulk_entities.get(d_id, {})
            total_raw_events += bulk.get("event_count", 0)
            users.update(bulk.get("users", []))
            src_ips.update(bulk.get("src_ips", []))

            # Retrieve event IDs for incident event linking
            eids = d.get("event_ids", [])
            if isinstance(eids, str):
                try:
                    eids = json.loads(eids)
                except Exception:
                    eids = []
            if isinstance(eids, list):
                all_event_ids.extend(eids)

        # If bulk event count is 0 (e.g. synthetic test without events table), fallback to event_ids count
        if total_raw_events == 0:
            total_raw_events = len(dict.fromkeys(all_event_ids)) or len(grp)

        # Build collapsed attack steps (collapse same technique and host entity)
        collapsed_steps_map: dict[tuple[str, str], dict[str, Any]] = {}
        for det in grp:
            tech_id = det["technique_id"]
            host = det.get("host") or ""
            key = (tech_id, host)
            det_ts_str = str(det["ts"])
            if key not in collapsed_steps_map:
                collapsed_steps_map[key] = {
                    "technique_id": tech_id,
                    "tactic": det.get("tactic", ""),
                    "kill_chain_stage": det.get("kill_chain_stage", ""),
                    "detection_ids": [det["detection_id"]],
                    "first_seen": det_ts_str,
                    "last_seen": det_ts_str,
                    "hosts": [host] if host else [],
                    "count": 1,
                }
            else:
                existing = collapsed_steps_map[key]
                existing["detection_ids"].append(det["detection_id"])
                existing["count"] += 1
                if det_ts_str < existing["first_seen"]:
                    existing["first_seen"] = det_ts_str
                if det_ts_str > existing["last_seen"]:
                    existing["last_seen"] = det_ts_str
                if host and host not in existing["hosts"]:
                    existing["hosts"].append(host)

        # Sort collapsed steps by kill-chain stage order, then chronologically
        steps = []
        for i, step_dict in enumerate(
            sorted(collapsed_steps_map.values(), key=lambda s: (_get_tactic_stage(s.get("tactic", "")), s.get("first_seen", ""))), 1
        ):
            step_dict["step_order"] = i
            steps.append(step_dict)

        # Incident promotion policy:
        # Promote if contains any active detection from high_fidelity rule OR severity >= 7 OR >= 2 distinct tactics.
        # Leads are only incidents whose active detections are all severity < 7 and not high_fidelity.
        has_high_fidelity = any(rule_hf_map.get(d.get("rule_id"), False) or (d.get("rule_id") in HIGH_FIDELITY_RULES) for d in grp)
        max_rule_sev = max(int(d.get("severity", 5)) for d in grp)
        distinct_tactics_set = {d.get("tactic") for d in grp if d.get("tactic")}
        extra_tactics = max(0, len(distinct_tactics_set) - 1)

        sorted_grp = sorted(grp, key=lambda d: _to_epoch(d["ts"]))
        stage_seq = [_get_tactic_stage(d.get("tactic", "")) for d in sorted_grp]
        stage_seq = [s for s in stage_seq if s >= 0]
        ordered_stages = sum(1 for a, b in zip(stage_seq[:-1], stage_seq[1:]) if b >= a) if len(stage_seq) >= 2 else 0

        promo_score = max_rule_sev + 2 * extra_tactics + (2 if has_high_fidelity else 0) + ordered_stages

        is_promoted = has_high_fidelity or (max_rule_sev >= 7) or (len(distinct_tactics_set) >= 2)
        status = "open" if is_promoted else "lead"

        # Determine main entity: first host, or user, or src_ip
        main_entity = (hosts[0] if hosts else None) or (sorted(list(users))[0] if users else None) or (sorted(list(src_ips))[0] if src_ips else "Unknown Host")
        # Identify prime rule name (highest severity, earliest seen)
        sorted_by_sev = sorted(grp, key=lambda d: (-int(d.get("severity", 5)), _to_epoch(d.get("ts"))))
        prime_d = sorted_by_sev[0]
        r_id = prime_d.get("rule_id", "")
        r_name = rule_name_map.get(r_id, prime_d.get("rule_name") or r_id.replace("-", " ").title())

        if is_promoted:
            if len(techniques) > 1:
                title = f"{r_name} (+{len(techniques)-1} stages) on {main_entity}"
            else:
                title = f"{r_name} on {main_entity}"
        else:
            title = f"Lead: {r_name} on {main_entity}"

        # Attach background prevalence detections as ips_context if sharing entity and overlapping time (+/- 1h)
        inc_entities = set(hosts) | users | src_ips
        t_first_sec = _to_epoch(first_seen) - 3600.0
        t_last_sec = _to_epoch(last_seen) + 3600.0
        attached_ips = []
        for bg in bg_dets:
            if bg["host"] in inc_entities and t_first_sec <= bg["epoch"] <= t_last_sec:
                attached_ips.append({
                    "rule_id": bg["rule_id"],
                    "rule_name": bg["rule_name"],
                    "technique_id": bg["technique_id"],
                    "host": bg["host"],
                    "ts": bg["ts"],
                })
                if len(attached_ips) >= 50:
                    break

        inc = {
            "incident_id": inc_id,
            "title": title,
            "severity": severity,
            "risk_score": 0.0,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "hosts": hosts,
            "users": sorted(list(users)),
            "src_ips": sorted(list(src_ips)),
            "techniques": techniques,
            "steps": steps,
            "detection_ids": det_ids,
            "detection_count": len(det_ids),
            "event_count": total_raw_events,
            "status": status,
            "ips_context": attached_ips,
        }

        # Compute dynamic risk score
        inc["risk_score"] = score_incident(inc)

        # Pre-compute Cytoscape entity graph
        try:
            G = build_entity_graph(grp, bulk_entities=bulk_entities, steps=steps)
            graph_dict = graph_to_cytoscape(G, inc_id)
            inc["graph_json"] = json.dumps(graph_dict)
        except Exception as exc:
            logger.warning("Failed to build entity graph for %s: %s", inc_id, exc)
            inc["graph_json"] = "{}"

        # Collect detection updates for batched execution
        for det in grp:
            all_detection_updates.append((inc_id, det["detection_id"]))
        duck.link_incident_events(inc_id, list(dict.fromkeys(all_event_ids)))

        # Upsert incident
        duck.upsert_incident(inc)

        # Print summary for incident: entities, rule list in kill-chain order, time span
        t_span_start = str(first_seen)
        t_span_end = str(last_seen)
        span_hours = max(0.0, (_to_epoch(last_seen) - _to_epoch(first_seen)) / 3600.0)
        rule_order_chain = " -> ".join(f"{s['technique_id']} ({s.get('tactic', '')})" for s in steps)
        print(
            f"\n[INCIDENT] {inc_id} ({status.upper()}) - {title}\n"
            f"  Time Span : {t_span_start} to {t_span_end} ({span_hours:.1f} hours)\n"
            f"  Entities  : hosts={hosts}, users={sorted(list(users))}, src_ips={sorted(list(src_ips))}\n"
            f"  Kill Chain: {rule_order_chain}\n"
            f"  Score     : {promo_score} (Detections: {len(det_ids)}, Severity: {severity}, Risk: {inc['risk_score']:.1f})"
        )

        # Precompute reach analysis only for promoted incidents
        if is_promoted:
            try:
                from app.pipeline.path.reach.service import precompute_reach_for_incident
                precompute_reach_for_incident(inc_id)
            except Exception as exc:
                logger.exception("Failed to precompute reach for incident %s: %s", inc_id, exc)
            incidents_created += 1
        else:
            alerts_created += 1

    # Batch update detections with incident_id in a single query
    if all_detection_updates:
        with duck.cursor() as con:
            con.executemany(
                "UPDATE detections SET incident_id=? WHERE detection_id=?",
                all_detection_updates,
            )

    # Pre-generate stories for top promoted incidents
    try:
        import time

        from app.pipeline.report.facts import build_incident_facts
        from app.pipeline.report.verifier import generate_and_verify_story

        with duck.cursor() as con:
            top_rows = con.execute(
                "SELECT incident_id FROM incidents WHERE status='open' ORDER BY risk_score DESC LIMIT 5"
            ).fetchall()
        for (top_inc_id,) in top_rows:
            try:
                facts = build_incident_facts(top_inc_id)
                story = generate_and_verify_story(facts)
                duck.save_incident_story(
                    top_inc_id,
                    story.model_dump_json(),
                    story.story_source,
                    facts.facts_sha256,
                    story.generated_at,
                )
                if settings.llm_gemini_api_key and settings.llm_pregen_delay_seconds > 0:
                    time.sleep(settings.llm_pregen_delay_seconds)
            except Exception as e:
                logger.debug("Failed pre-generating story for %s: %s", top_inc_id, e)
    except Exception as exc:
        logger.warning("Error in incident story pre-generation hook: %s", exc)

    print(
        f"\n[INCIDENT PROMOTION SUMMARY]\n"
        f"  Total clusters formed  : {len(clusters_map)}\n"
        f"  Promoted (status=open) : {incidents_created}\n"
        f"  Leads (status=lead)    : {alerts_created}\n"
    )

    return {
        "incidents_created": incidents_created,
        "promoted_incidents": incidents_created,
        "alerts_created": alerts_created,
        "leads_created": alerts_created,
        "lead_incidents": alerts_created,
        "total_clusters": len(clusters_map),
    }
