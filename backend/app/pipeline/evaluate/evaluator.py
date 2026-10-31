"""Ground-truth evaluator for CaseFile.

Scores detections and incidents against the organizers' manifest (*.manifest.json).
This module is strictly isolated: only the evaluation subsystem may access manifests.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import settings
from app.schemas.evaluation import EvaluationResult, GroundTruthStep, StepScore
from app.store import duck

PRD_THRESHOLDS = {
    "detection_rate": {"pass": 0.70, "great": 0.90, "format": "pct"},
    "label_accuracy_exact": {"pass": 0.60, "great": 0.85, "format": "pct"},
    "path_rate": {"pass": 0.50, "great": 1.00, "format": "pct"},
    "false_alarm_rate": {"pass": 0.30, "great": 0.10, "format": "pct_lower"},
    "processing_seconds": {"pass": 10800, "great": 3600, "format": "time"},
    "peak_memory_mb": {"pass": 16384, "great": 8192, "format": "mem"},
    "path_open_ms": {"pass": 2000, "great": 500, "format": "latency"},
}


def parse_manifest_timestamp(ts_str: str, tz_offset_hours: float = 5.5) -> datetime:
    """Parse local wall-clock timestamp string from manifest into UTC datetime."""
    # Format e.g. "2026-10-28 14:41:50"
    ts_clean = ts_str.strip()
    if "T" in ts_clean:
        dt = datetime.fromisoformat(ts_clean.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC) - timedelta(hours=tz_offset_hours)
        return dt.astimezone(UTC)
    else:
        # Assume YYYY-MM-DD HH:MM:SS
        parts = ts_clean.split(" ")
        d_parts = [int(x) for x in parts[0].split("-")]
        t_parts = [int(x) for x in parts[1].split(":")]
        local_dt = datetime(d_parts[0], d_parts[1], d_parts[2], t_parts[0], t_parts[1], t_parts[2])
        utc_dt = local_dt - timedelta(hours=tz_offset_hours)
        return utc_dt.replace(tzinfo=UTC)


def parse_attack_techniques(attack_str: str) -> list[str]:
    """Extract individual technique IDs from attack string (e.g. 'T1110.001, T1078' or chain)."""
    # Split by comma or arrow
    raw_tokens = re.split(r",|->", attack_str)
    techniques = []
    for t in raw_tokens:
        clean = t.strip()
        if clean:
            techniques.append(clean)
    return techniques


def is_family_match(tech_a: str, tech_b: str) -> bool:
    """Check if two technique IDs match exactly or share the same parent technique."""
    if tech_a == tech_b:
        return True
    parent_a = tech_a.split(".")[0]
    parent_b = tech_b.split(".")[0]
    return parent_a == parent_b


def load_and_verify_manifest(
    manifest_path: str,
    log_file_size: int | None = None,
) -> dict[str, Any]:
    """Load manifest and check file size.
    
    If manifest declared bytes differ from actual log file size,
    prints 'MANIFEST DOES NOT MATCH THIS FILE' and aborts.
    """
    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    declared_bytes = manifest.get("bytes")
    if log_file_size is not None and declared_bytes is not None:
        if log_file_size != declared_bytes:
            print("MANIFEST DOES NOT MATCH THIS FILE")
            sys.exit(3)

    return manifest


def evaluate_manifest(
    manifest_path: str,
    log_file_path: str | None = None,
) -> dict[str, Any]:
    """Score detections and incidents against the ground-truth manifest."""
    real_file_size: int | None = None
    if log_file_path and os.path.exists(log_file_path):
        real_file_size = os.path.getsize(log_file_path)

    manifest = load_and_verify_manifest(manifest_path, log_file_size=real_file_size)

    # Timezone offset from config
    tz_str = getattr(settings, "manifest_timezone", "Asia/Kolkata")
    tz_offset_hours = 5.5 if "kolkata" in tz_str.lower() or "+0530" in tz_str else 0.0

    # Retrieve all detections from DuckDB
    duck.init_db()
    duck.ensure_events_view()
    _, all_detections = duck.list_detections(limit=500_000)
    _, all_incidents = duck.list_incidents(limit=50_000)

    # Index detections by evidence event_ids
    # Each detection has event_ids: ["ev_0_12345", ...]
    det_by_event: dict[str, list[dict]] = {}
    for d in all_detections:
        eids = d.get("event_ids", [])
        if isinstance(eids, str):
            try:
                eids = json.loads(eids)
            except Exception:
                eids = []
        for eid in eids:
            det_by_event.setdefault(eid, []).append(d)

    # Parse planted incidents & steps
    planted_incidents = manifest.get("incidents", [])
    classes = ["easy", "medium", "hard", "insane"]

    per_class_stats: dict[str, dict[str, Any]] = {
        c: {
            "planted_incidents": 0,
            "hit_incidents": 0,
            "planted_steps": 0,
            "hit_steps": 0,
            "exact_label_matches": 0,
            "family_label_matches": 0,
            "path_scores": [],
        }
        for c in classes
    }

    incident_results: list[dict[str, Any]] = []
    matched_detection_ids: set[str] = set()
    matched_incident_ids: set[str] = set()

    for p_inc in planted_incidents:
        inc_id = p_inc["id"]
        inc_class = p_inc.get("class", "medium")
        inc_name = p_inc.get("name", f"incident_{inc_id}")
        is_chain = "stages" in p_inc and bool(p_inc["stages"])

        if inc_class not in per_class_stats:
            per_class_stats[inc_class] = {
                "planted_incidents": 0,
                "hit_incidents": 0,
                "planted_steps": 0,
                "hit_steps": 0,
                "exact_label_matches": 0,
                "family_label_matches": 0,
                "path_scores": [],
            }

        per_class_stats[inc_class]["planted_incidents"] += 1

        # Build planted 'at' event IDs set: ev_<stream>_<byte>
        at_triples = p_inc.get("at", [])
        planted_event_ids = {f"ev_{triple[2]}_{triple[1]}" for triple in at_triples if len(triple) >= 3}

        # Check which of our detections hit this incident
        hitting_dets: list[dict] = []
        for eid in planted_event_ids:
            if eid in det_by_event:
                for d in det_by_event[eid]:
                    hitting_dets.append(d)
                    matched_detection_ids.add(d["detection_id"])
                    if d.get("incident_id"):
                        matched_incident_ids.add(d["incident_id"])

        incident_hit = len(hitting_dets) > 0
        if incident_hit:
            per_class_stats[inc_class]["hit_incidents"] += 1

        # Planted steps evaluation
        planted_steps: list[dict[str, Any]] = []
        if is_chain:
            stages = p_inc["stages"]
            # Stages list in order
            for i, st in enumerate(stages):
                st_attack = st.get("attack", "")
                st_start = parse_manifest_timestamp(st["at"], tz_offset_hours)
                # Next stage start or incident 'to' + 5 min
                if i + 1 < len(stages):
                    st_end = parse_manifest_timestamp(stages[i + 1]["at"], tz_offset_hours)
                else:
                    inc_to_str = p_inc.get("to")
                    if inc_to_str:
                        st_end = parse_manifest_timestamp(inc_to_str, tz_offset_hours) + timedelta(minutes=5)
                    else:
                        st_end = st_start + timedelta(hours=2)

                planted_steps.append({
                    "step_num": st.get("n", i + 1),
                    "technique_id": st_attack,
                    "tactic": st.get("tactic", ""),
                    "start_utc": st_start,
                    "end_utc": st_end,
                })
        else:
            techs = parse_attack_techniques(p_inc.get("attack", ""))
            for i, tech in enumerate(techs):
                planted_steps.append({
                    "step_num": i + 1,
                    "technique_id": tech,
                    "tactic": p_inc.get("tactic", ""),
                    "start_utc": None,
                    "end_utc": None,
                })

        per_class_stats[inc_class]["planted_steps"] += len(planted_steps)

        # Match steps
        steps_hit = 0
        exact_labels = 0
        family_labels = 0
        chain_stage_orders: list[int] = []

        for st in planted_steps:
            st_tech = st["technique_id"]
            st_start = st["start_utc"]
            st_end = st["end_utc"]

            step_matched = False
            label_exact = False
            label_family = False

            if incident_hit:
                for d in hitting_dets:
                    d_tech = d.get("technique_id", "")
                    d_ts_raw = d.get("ts")
                    d_ts: datetime | None = None
                    if d_ts_raw:
                        if isinstance(d_ts_raw, datetime):
                            d_ts = d_ts_raw.astimezone(UTC)
                        else:
                            try:
                                d_ts = datetime.fromisoformat(str(d_ts_raw).replace("Z", "+00:00")).astimezone(UTC)
                            except Exception:
                                pass

                    # Time window check for chain stages
                    time_ok = True
                    if st_start and st_end and d_ts:
                        time_ok = (st_start <= d_ts < st_end)

                    if time_ok:
                        if d_tech == st_tech:
                            step_matched = True
                            label_exact = True
                            label_family = True
                            break
                        elif is_family_match(d_tech, st_tech):
                            step_matched = True
                            label_family = True
                            # keep looking for exact match
                            break

            if step_matched:
                steps_hit += 1
                if label_exact:
                    exact_labels += 1
                if label_family:
                    family_labels += 1
                chain_stage_orders.append(st["step_num"])

        per_class_stats[inc_class]["hit_steps"] += steps_hit
        per_class_stats[inc_class]["exact_label_matches"] += exact_labels
        per_class_stats[inc_class]["family_label_matches"] += family_labels

        # Path rate calculation
        if is_chain:
            # Check sequential order of stages found
            if len(chain_stage_orders) == len(planted_steps):
                path_score = 1.0
            else:
                # Half-credit share of chain stages found in order
                path_score = len(chain_stage_orders) / len(planted_steps) if planted_steps else 0.0
        else:
            path_score = 1.0 if steps_hit > 0 else 0.0

        per_class_stats[inc_class]["path_scores"].append(path_score)

        incident_results.append({
            "id": inc_id,
            "name": inc_name,
            "class": inc_class,
            "hit": incident_hit,
            "planted_steps": len(planted_steps),
            "steps_hit": steps_hit,
            "exact_labels": exact_labels,
            "family_labels": family_labels,
            "path_score": round(path_score, 2),
            "hitting_detections_count": len(hitting_dets),
        })

    # Overall metrics
    total_planted_incidents = len(planted_incidents)
    total_hit_incidents = sum(s["hit_incidents"] for s in per_class_stats.values())
    total_planted_steps = sum(s["planted_steps"] for s in per_class_stats.values())
    total_hit_steps = sum(s["hit_steps"] for s in per_class_stats.values())
    total_exact_labels = sum(s["exact_label_matches"] for s in per_class_stats.values())
    total_family_labels = sum(s["family_label_matches"] for s in per_class_stats.values())

    all_path_scores = [score for s in per_class_stats.values() for score in s["path_scores"]]
    overall_path_rate = (sum(all_path_scores) / len(all_path_scores)) if all_path_scores else None

    # False alarms: detections not matching any planted incident
    total_our_detections = len(all_detections)
    total_our_incidents = len(all_incidents)
    unhit_our_incidents = [inc for inc in all_incidents if inc["incident_id"] not in matched_incident_ids]
    false_alarm_incidents_count = len(unhit_our_incidents)
    false_alarm_rate = (false_alarm_incidents_count / total_our_incidents) if total_our_incidents > 0 else None

    # False detections per rule
    rule_hits: dict[str, int] = Counter()
    rule_false_alarms: dict[str, int] = Counter()
    for d in all_detections:
        r_id = d.get("rule_id", "unknown")
        if d["detection_id"] in matched_detection_ids:
            rule_hits[r_id] += 1
        else:
            rule_false_alarms[r_id] += 1

    # Processing stats from DuckDB or manifest
    proc_time_stat = duck.get_stat("last_ingest_time_seconds")
    processing_seconds = float(proc_time_stat) if proc_time_stat else None

    # Measure path-open latency (p50 and p95) across sample incidents
    path_latencies_ms: list[float] = []
    sample_incs = all_incidents[:20] if all_incidents else []
    for inc in sample_incs:
        t0 = time.perf_counter()
        _ = duck.get_incident(inc["incident_id"])
        t1 = time.perf_counter()
        path_latencies_ms.append((t1 - t0) * 1000)

    p50_latency = None
    p95_latency = None
    if path_latencies_ms:
        path_latencies_ms.sort()
        idx_50 = int(len(path_latencies_ms) * 0.50)
        idx_95 = min(len(path_latencies_ms) - 1, int(len(path_latencies_ms) * 0.95))
        p50_latency = round(path_latencies_ms[idx_50], 2)
        p95_latency = round(path_latencies_ms[idx_95], 2)

    # Missed incidents
    missed_incidents = [res for res in incident_results if not res["hit"]]

    return {
        "manifest": os.path.basename(manifest_path),
        "total_planted_incidents": total_planted_incidents,
        "total_hit_incidents": total_hit_incidents,
        "incident_detection_rate": (total_hit_incidents / total_planted_incidents) if total_planted_incidents else None,
        "total_planted_steps": total_planted_steps,
        "total_hit_steps": total_hit_steps,
        "detection_rate": (total_hit_steps / total_planted_steps) if total_planted_steps else None,
        "label_accuracy_exact": (total_exact_labels / total_hit_steps) if total_hit_steps else None,
        "label_accuracy_family": (total_family_labels / total_hit_steps) if total_hit_steps else None,
        "path_rate": overall_path_rate,
        "false_alarm_rate": false_alarm_rate,
        "false_alarm_count": false_alarm_incidents_count,
        "total_our_incidents": total_our_incidents,
        "total_our_detections": total_our_detections,
        "processing_seconds": processing_seconds,
        "peak_memory_mb": None,
        "path_open_ms": {"p50": p50_latency, "p95": p95_latency} if p50_latency is not None else None,
        "per_class": {
            cls_name: {
                "incident_detection_rate": (
                    st["hit_incidents"] / st["planted_incidents"] if st["planted_incidents"] else None
                ),
                "detection_rate": (
                    st["hit_steps"] / st["planted_steps"] if st["planted_steps"] else None
                ),
                "label_accuracy_exact": (
                    st["exact_label_matches"] / st["hit_steps"] if st["hit_steps"] else None
                ),
                "label_accuracy_family": (
                    st["family_label_matches"] / st["hit_steps"] if st["hit_steps"] else None
                ),
                "path_rate": (
                    sum(st["path_scores"]) / len(st["path_scores"]) if st["path_scores"] else None
                ),
            }
            for cls_name, st in per_class_stats.items()
        },
        "missed_incidents": missed_incidents,
        "top_false_alarms": unhit_our_incidents[:20],
        "rule_stats": {
            r: {"hits": rule_hits[r], "false_alarms": rule_false_alarms[r]}
            for r in set(rule_hits) | set(rule_false_alarms)
        },
        "incident_breakdown": incident_results,
    }


def evaluate_incident(
    incident_id: str,
    ground_truth: list[GroundTruthStep],
) -> EvaluationResult:
    """Compare stored incident steps to ground truth (single-incident evaluation)."""
    inc = duck.get_incident(incident_id)
    if not inc:
        return EvaluationResult(
            incident_id=incident_id,
            ground_truth_steps=len(ground_truth),
            detected_steps=0,
            matched_steps=0,
        )

    steps = json.loads(inc["steps"]) if isinstance(inc["steps"], str) else inc["steps"]
    detected_techs: list[str] = [s["technique_id"] for s in steps]

    step_scores: list[StepScore] = []
    matched = 0
    correct_labels = 0
    correct_order = 0
    last_order: int | None = None

    for gt in ground_truth:
        found_idx: int | None = None
        for j, dt in enumerate(detected_techs):
            if is_family_match(dt, gt.technique_id):
                found_idx = j
                break

        is_match = found_idx is not None
        label_ok = is_match
        order_ok: bool | None = None

        if is_match:
            matched += 1
            correct_labels += 1
            if last_order is None or found_idx >= last_order:
                order_ok = True
                correct_order += 1
                last_order = found_idx
            else:
                order_ok = False

        step_scores.append(
            StepScore(
                technique_id=gt.technique_id,
                matched=is_match,
                label_correct=label_ok,
                order_correct=order_ok,
            )
        )

    total_gt = len(ground_truth)
    total_det = len(detected_techs)

    det_rate = matched / total_gt if total_gt else 0.0
    label_acc = correct_labels / matched if matched else 0.0
    path_corr = correct_order / matched if matched else 0.0
    fa_count = total_det - matched
    fa_rate = fa_count / total_det if total_det else 0.0

    return EvaluationResult(
        incident_id=incident_id,
        ground_truth_steps=total_gt,
        detected_steps=total_det,
        matched_steps=matched,
        detection_rate=round(det_rate, 4),
        label_accuracy=round(label_acc, 4),
        path_correctness=round(path_corr, 4),
        false_alarm_rate=round(fa_rate, 4),
        step_scores=step_scores,
    )
