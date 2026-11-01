"""Incident Table Generator for Silver Standard and Incident Analysis Review.

Generates docs/INCIDENT_TABLE.md covering:
1. Main Incident Table (promoted & lead)
2. Uncovered Merged Oracle Behaviors
3. Multi-Class Incidents with chronological tactic ordering analysis
4. Chain Check (Promoted incident pairs sharing host or destination within 72h)
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import duckdb

LOCAL_TZ = timezone(timedelta(hours=5, minutes=30))  # +05:30 wall clock

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
TACTIC_MAP = {t: idx for idx, t in enumerate(TACTIC_ORDER)}


def _to_epoch(ts: Any) -> float:
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


def _format_time_both(ts: Any) -> str:
    """Format timestamp into UTC and +05:30 strings."""
    ep = _to_epoch(ts)
    if ep <= 0:
        return "N/A"
    dt_utc = datetime.fromtimestamp(ep, tz=UTC)
    dt_loc = datetime.fromtimestamp(ep, tz=LOCAL_TZ)
    utc_str = dt_utc.strftime("%Y-%m-%d %H:%M:%S")
    loc_str = dt_loc.strftime("%H:%M:%S")
    return f"{utc_str} UTC<br>({loc_str} +05:30)"


def _is_internal_ip(ip: str) -> bool:
    import re
    return bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", str(ip)))


def generate_incident_table_markdown(
    db_path: str | None = None,
    output_path: str = "docs/INCIDENT_TABLE.md",
    silver_res: dict[str, Any] | None = None,
    con: duckdb.DuckDBPyConnection | None = None,
) -> str:
    """Generate docs/INCIDENT_TABLE.md from DuckDB and silver oracle evaluation data."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # 1. Connect to DuckDB
    close_con = False
    if con is not None:
        active_con = con
    elif db_path and os.path.exists(db_path):
        try:
            active_con = duckdb.connect(db_path, read_only=True)
            close_con = True
        except Exception:
            from app.store import duck
            active_con = duck.get_connection()
    else:
        from app.store import duck
        active_con = duck.get_connection()

    try:
        # Load silver eval results if not passed
        if silver_res is None:
            json_path = "docs/silver_oracles.json"
            if os.path.exists(json_path):
                try:
                    with open(json_path, encoding="utf-8") as f:
                        silver_res = json.load(f)
                except Exception:
                    silver_res = None

        all_behaviors = silver_res.get("all_behaviors", []) if silver_res else []
        all_oracle_rows = silver_res.get("all_oracle_rows", []) if silver_res else []

        # Fetch incidents
        incidents_query = """
            SELECT incident_id, title, status, severity, risk_score, first_seen, last_seen,
                   hosts, users, src_ips, techniques, steps, detection_ids, detection_count, event_count
            FROM incidents
            ORDER BY risk_score DESC, first_seen ASC
        """
        raw_incidents = active_con.execute(incidents_query).fetchall()
        inc_cols = [c[0] for c in active_con.description]
        incidents = [dict(zip(inc_cols, row, strict=False)) for row in raw_incidents]

        # Fetch active detections
        det_cols_check = {c[0].lower() for c in active_con.execute("DESCRIBE detections").fetchall()}
        where_sup = "WHERE suppressed = false" if "suppressed" in det_cols_check else ""
        det_query = f"""
            SELECT detection_id, rule_id, rule_name, technique_id, tactic, severity, host, ts,
                   event_ids, incident_id, confidence, suppressed, suppress_reason
            FROM detections
            {where_sup}
            ORDER BY ts ASC
        """
        raw_dets = active_con.execute(det_query).fetchall()
        det_cols = [c[0] for c in active_con.description]
        active_dets = [dict(zip(det_cols, row, strict=False)) for row in raw_dets]

        # Fetch detection entities from detection_events & events if available
        det_entities_map: dict[str, dict[str, Any]] = {}
        try:
            bulk_ent_query = """
                SELECT de.detection_id,
                       list_distinct(list(e.src_ip) FILTER (WHERE e.src_ip IS NOT NULL AND e.src_ip != '')) as src_ips,
                       list_distinct(list(e.dst_ip) FILTER (WHERE e.dst_ip IS NOT NULL AND e.dst_ip != '')) as dst_ips,
                       list_distinct(list(COALESCE(e.user, e.user_raw)) FILTER (WHERE COALESCE(e.user, e.user_raw) IS NOT NULL AND COALESCE(e.user, e.user_raw) != '')) as users,
                       list_distinct(list(e.host) FILTER (WHERE e.host IS NOT NULL AND e.host != '')) as hosts
                FROM detection_events de
                JOIN events e ON de.event_id = e.event_id
                GROUP BY de.detection_id
            """
            for r in active_con.execute(bulk_ent_query).fetchall():
                det_entities_map[r[0]] = {
                    "src_ips": [str(x) for x in (r[1] or []) if x],
                    "dst_ips": [str(x) for x in (r[2] or []) if x],
                    "users": [str(x) for x in (r[3] or []) if x],
                    "hosts": [str(x) for x in (r[4] or []) if x],
                }
        except Exception:
            pass

        # Build map incident_id -> active detections
        inc_active_dets: dict[str, list[dict]] = {}
        for d in active_dets:
            iid = d.get("incident_id")
            if iid:
                inc_active_dets.setdefault(iid, []).append(d)

        # Build mapping of detection_id -> matched oracle behavior / oracle row
        det_matched_oracles: dict[str, set[str]] = {}
        behavior_matched_incidents: dict[str, set[str]] = {}  # behavior_key -> set of inc_ids

        # If silver_res available, correlate detections with oracle behaviors
        for b in all_behaviors:
            b_key = f"{b.get('oracle_id')}:{b.get('entity')}:{b.get('t_start')}"
            b_start = _to_epoch(b.get("t_start")) - 600.0  # 10m slack
            b_end = _to_epoch(b.get("t_end")) + 600.0
            b_ent = str(b.get("entity", "")).strip().lower()

            for d in active_dets:
                d_id = d["detection_id"]
                d_ts = _to_epoch(d.get("ts"))
                if not (b_start <= d_ts <= b_end):
                    continue

                # Check entity
                bulk = det_entities_map.get(d_id, {})
                d_ents = {str(d.get("host", "")).lower()}
                d_ents.update(str(x).lower() for x in bulk.get("src_ips", []))
                d_ents.update(str(x).lower() for x in bulk.get("dst_ips", []))
                d_ents.update(str(x).lower() for x in bulk.get("users", []))
                d_ents.discard("")

                if b_ent in d_ents or not b_ent:
                    det_matched_oracles.setdefault(d_id, set()).add(b.get("oracle_id", "unknown"))
                    iid = d.get("incident_id")
                    if iid:
                        behavior_matched_incidents.setdefault(b_key, set()).add(iid)

        # Also fallback to direct oracle rows match
        for o in all_oracle_rows:
            o_start = _to_epoch(o.get("t_start")) - 300.0
            o_end = _to_epoch(o.get("t_end")) + 300.0
            o_ent = str(o.get("src_ip") or o.get("dst_ip") or o.get("user") or "").strip().lower()
            for d in active_dets:
                d_id = d["detection_id"]
                d_ts = _to_epoch(d.get("ts"))
                if o_start <= d_ts <= o_end:
                    bulk = det_entities_map.get(d_id, {})
                    d_ents = {str(d.get("host", "")).lower()}
                    d_ents.update(str(x).lower() for x in bulk.get("src_ips", []))
                    d_ents.update(str(x).lower() for x in bulk.get("dst_ips", []))
                    d_ents.update(str(x).lower() for x in bulk.get("users", []))
                    if o_ent in d_ents:
                        det_matched_oracles.setdefault(d_id, set()).add(o.get("oracle_id", "unknown"))

        lines: list[str] = [
            "# Comprehensive Incident Review & Verification Table\n",
            "> [!NOTE]\n",
            "> This table documents all formed clusters (both **PROMOTED** incidents and **LEAD** clusters) across the evaluated dataset. Timestamps are reported in both UTC and local time (+05:30).\n",
            "## 1. Incidents Table (Promoted & Leads)\n",
            "| ID | Status | Score | First Seen (UTC / +05:30) | Last Seen (UTC / +05:30) | Entities (max 5) | Rule Sequence (Techniques) | Tactic Stages | Active Dets | Oracle Behavior Match |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]

        # Populate Incident rows
        for inc in incidents:
            iid = inc["incident_id"]
            status = "PROMOTED" if inc.get("status") == "open" else "LEAD"
            score = f"{float(inc.get('risk_score', 0.0)):.1f}"
            t_first = _format_time_both(inc.get("first_seen"))
            t_last = _format_time_both(inc.get("last_seen"))

            # Entities
            hosts = json.loads(inc["hosts"]) if isinstance(inc.get("hosts"), str) else (inc.get("hosts") or [])
            users = json.loads(inc["users"]) if isinstance(inc.get("users"), str) else (inc.get("users") or [])
            src_ips = json.loads(inc["src_ips"]) if isinstance(inc.get("src_ips"), str) else (inc.get("src_ips") or [])
            all_ents = []
            for h in hosts:
                if h and h != "network" and h not in all_ents:
                    all_ents.append(h)
            for u in users:
                if u and u not in all_ents:
                    all_ents.append(u)
            for s in src_ips:
                if s and s not in all_ents:
                    all_ents.append(s)
            ent_str = ", ".join(f"`{e}`" for e in all_ents[:5]) if all_ents else "`none`"
            if len(all_ents) > 5:
                ent_str += f" *(+{len(all_ents)-5} more)*"

            # Rule sequence with techniques
            steps = json.loads(inc["steps"]) if isinstance(inc.get("steps"), str) else (inc.get("steps") or [])
            rule_seq_items = []
            seen_step = set()
            for s in steps:
                r_name = s.get("rule_name") or s.get("technique_name") or "step"
                t_id = s.get("technique_id") or ""
                pair = f"{r_name} [{t_id}]" if t_id else r_name
                if pair not in seen_step:
                    seen_step.add(pair)
                    rule_seq_items.append(pair)
            rule_seq_str = " &rarr; ".join(rule_seq_items) if rule_seq_items else "-"

            # Tactic stages
            tactics = []
            for s in steps:
                tac = s.get("tactic")
                if tac and tac not in tactics:
                    tactics.append(tac)
            tactic_str = " &rarr; ".join(f"`{t}`" for t in tactics) if tactics else "-"

            # Active detections count
            cur_active_dets = inc_active_dets.get(iid, [])
            active_cnt = len(cur_active_dets)

            # Oracle Behavior Match
            matched_classes = set()
            for d in cur_active_dets:
                for oc in det_matched_oracles.get(d["detection_id"], []):
                    matched_classes.add(oc)
            if matched_classes:
                oracle_match_str = ", ".join(f"`{c}`" for c in sorted(matched_classes))
            else:
                oracle_match_str = "*-*"

            lines.append(
                f"| `{iid}` | **{status}** | {score} | {t_first} | {t_last} | {ent_str} | {rule_seq_str} | {tactic_str} | {active_cnt} | {oracle_match_str} |"
            )

        # -------------------------------------------------------------------
        # 2. Uncovered Merged Oracle Behaviors
        # -------------------------------------------------------------------
        lines.extend([
            "\n---\n",
            "## 2. Uncovered Merged Oracle Behaviors\n",
            "> [!NOTE]\n",
            "> Independent SQL oracle behaviors that have NO matching active detection within a PROMOTED incident (status='open').\n",
            "| Oracle Class | Entity | Window Start (UTC) | Window End (UTC) | Expected Technique | Expected Tactic | Uncovered Reason |",
            "|---|---|---|---|---|---|---|",
        ])

        promoted_inc_ids = {inc["incident_id"] for inc in incidents if inc.get("status") == "open"}
        uncovered_behaviors_count = 0

        for b in all_behaviors:
            b_key = f"{b.get('oracle_id')}:{b.get('entity')}:{b.get('t_start')}"
            matched_incs = behavior_matched_incidents.get(b_key, set())
            matched_promoted = matched_incs & promoted_inc_ids

            if not matched_promoted:
                uncovered_behaviors_count += 1
                reason = "No active detection fired"
                if matched_incs:
                    reason = f"Only matched in Lead cluster ({', '.join(sorted(matched_incs))})"
                lines.append(
                    f"| `{b.get('oracle_id')}` | `{b.get('entity')}` | {b.get('t_start')} | {b.get('t_end')} | `{b.get('expected_technique')}` | `{b.get('expected_tactic')}` | {reason} |"
                )

        if uncovered_behaviors_count == 0:
            lines.append("| *All merged oracle behaviors are covered by promoted incidents* | - | - | - | - | - | None |")

        # -------------------------------------------------------------------
        # 3. Multi-Class Incidents & Tactic Progression Analysis
        # -------------------------------------------------------------------
        lines.extend([
            "\n---\n",
            "## 3. Multi-Class Incidents: Chronological Detections & Tactic Progression\n",
            "> [!NOTE]\n",
            "> Incidents spanning $\\ge 2$ distinct tactics. Detections are listed in strict chronological order with tactic order breaks annotated.\n",
        ])

        multi_class_found = 0
        for inc in incidents:
            iid = inc["incident_id"]
            d_list = inc_active_dets.get(iid, [])
            distinct_tactics = {d.get("tactic") for d in d_list if d.get("tactic")}
            if len(distinct_tactics) < 2:
                continue

            multi_class_found += 1
            status_tag = "PROMOTED" if inc.get("status") == "open" else "LEAD"
            lines.append(f"\n### Incident `{iid}` ({status_tag}) &mdash; {inc.get('title')}\n")
            lines.append("| Time (UTC) | Rule ID | Technique ID | Tactic | Stage Order Transition |")
            lines.append("|---|---|---|---|---|")

            # Sort detections by ts
            sorted_dets = sorted(d_list, key=lambda x: _to_epoch(x.get("ts")))
            prev_tactic = None
            prev_stage = -1

            for d in sorted_dets:
                t_str = _format_time_both(d.get("ts")).replace("<br>", " ")
                r_id = d.get("rule_id", "")
                tech_id = d.get("technique_id", "")
                tactic = d.get("tactic", "")
                curr_stage = TACTIC_MAP.get(tactic, -1)

                if prev_stage == -1 or curr_stage == -1 or curr_stage >= prev_stage:
                    trans = f"OK (`{prev_tactic}` &rarr; `{tactic}`)" if prev_tactic and prev_tactic != tactic else "Sequential / Concurrent"
                else:
                    trans = f"**[BREAK: Backwards]** `{prev_tactic}` &rarr; `{tactic}` (Stage {prev_stage} &rarr; {curr_stage})"

                lines.append(f"| {t_str} | `{r_id}` | `{tech_id}` | `{tactic}` | {trans} |")
                prev_tactic = tactic
                prev_stage = curr_stage

        if multi_class_found == 0:
            lines.append("*No multi-class incidents detected.*\n")

        # -------------------------------------------------------------------
        # 4. Chain Check (Promoted incident pairs sharing host or destination within 72h)
        # -------------------------------------------------------------------
        lines.extend([
            "\n---\n",
            "## 4. Chain Check: Independent Promoted Incidents Within 72h\n",
            "> [!NOTE]\n",
            "> For each pair of promoted incidents sharing an internal host IP or external destination within 72 hours, explains why the incident linking engine kept them separate without modifying graph linking logic.\n",
            "| Incident Pair | Shared Entity | Time Gap | Reason Kept Separate |",
            "|---|---|---|---|",
        ])

        promoted_incs = [inc for inc in incidents if inc.get("status") == "open"]
        pairs_analyzed = 0

        # Build entity sets for promoted incidents
        inc_ent_summary: dict[str, dict[str, Any]] = {}
        for inc in promoted_incs:
            iid = inc["incident_id"]
            d_list = inc_active_dets.get(iid, [])
            internal_hosts = set()
            ext_dsts = set()
            for d in d_list:
                bulk = det_entities_map.get(d["detection_id"], {})
                for ip in bulk.get("src_ips", []):
                    if _is_internal_ip(ip):
                        internal_hosts.add(ip)
                    else:
                        ext_dsts.add(ip)
                for ip in bulk.get("dst_ips", []):
                    if _is_internal_ip(ip):
                        internal_hosts.add(ip)
                    else:
                        ext_dsts.add(ip)
                for h in bulk.get("hosts", []):
                    if _is_internal_ip(h):
                        internal_hosts.add(h)
                d_host = d.get("host")
                if d_host and _is_internal_ip(d_host):
                    internal_hosts.add(d_host)

            inc_ent_summary[iid] = {
                "first": _to_epoch(inc.get("first_seen")),
                "last": _to_epoch(inc.get("last_seen")),
                "internal": internal_hosts,
                "external": ext_dsts,
                "rules": {d.get("rule_id") for d in d_list},
                "tactics": {d.get("tactic") for d in d_list if d.get("tactic")},
            }

        # Check all pairs
        for i in range(len(promoted_incs)):
            inc_a = promoted_incs[i]
            iid_a = inc_a["incident_id"]
            info_a = inc_ent_summary[iid_a]

            for j in range(i + 1, len(promoted_incs)):
                inc_b = promoted_incs[j]
                iid_b = inc_b["incident_id"]
                info_b = inc_ent_summary[iid_b]

                # Check shared entities
                shared_int = info_a["internal"] & info_b["internal"]
                shared_ext = info_a["external"] & info_b["external"]

                if not shared_int and not shared_ext:
                    continue

                # Check time window (within 72h = 259200s)
                time_gap = max(0.0, max(info_b["first"] - info_a["last"], info_a["first"] - info_b["last"]))
                if time_gap > 259200.0:
                    continue

                pairs_analyzed += 1
                hours_gap = time_gap / 3600.0
                shared_str = ", ".join(f"`{e}`" for e in (list(shared_int) + list(shared_ext))[:3])

                # Determine why not merged
                reasons = []
                if hours_gap > 0.5 and (info_a["rules"] & info_b["rules"] or info_a["tactics"] & info_b["tactics"]):
                    reasons.append("Same rule/tactic window exceeded (> 30 min)")
                if shared_ext and not shared_int:
                    reasons.append("Shared external destination without shared internal victim host")
                if not reasons:
                    reasons.append("Distinct attack stages across non-overlapping execution paths")

                lines.append(
                    f"| `{iid_a}` &amp; `{iid_b}` | {shared_str} | {hours_gap:.1f}h | {'; '.join(reasons)} |"
                )

        if pairs_analyzed == 0:
            lines.append("| *None* | - | - | *No promoted incident pairs share an entity within 72h* |")

        # Write to file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return output_path

    finally:
        if close_con:
            active_con.close()


if __name__ == "__main__":
    generate_incident_table_markdown()
