"""Dynamic risk scoring for incidents based on kill-chain progression, tactic breadth, asset criticality, and volume."""

from __future__ import annotations

import json
import math
from typing import Any

from app.pipeline.path.path_builder import normalise_tactic
from app.pipeline.path.reach.assets import DEFAULT_PATTERNS

# Kill chain stage progression severity weights (later attack stages score higher)
_TACTIC_PROGRESSION_WEIGHTS: dict[str, float] = {
    "reconnaissance": 2.5,
    "resource_development": 3.0,
    "initial_access": 4.5,
    "execution": 5.5,
    "persistence": 6.5,
    "privilege_escalation": 7.0,
    "defense_evasion": 7.0,
    "credential_access": 7.5,
    "discovery": 6.0,
    "lateral_movement": 8.5,
    "collection": 7.5,
    "command_and_control": 8.5,
    "exfiltration": 9.0,
    "impact": 10.0,
}

_BASE_TECHNIQUE_SCORES: dict[str, float] = {
    "T1078": 7.5,   # Valid Accounts
    "T1053": 7.0,   # Scheduled Task
    "T1059": 7.0,   # Command & Scripting
    "T1082": 5.0,   # System Information Discovery
    "T1003": 9.0,   # OS Credential Dumping
    "T1110": 8.0,   # Brute Force
    "T1190": 8.5,   # Exploit Public-Facing Application
    "T1046": 6.0,   # Network Service Discovery
    "T1048": 8.5,   # Exfiltration Over Alternative Protocol
    "T1204": 7.5,   # User Execution (Malware)
    "T1071": 8.0,   # Application Layer Protocol (C2/DNS)
    "T1021": 8.0,   # Remote Services (Lateral)
    "T1136": 7.5,   # Create Account
    "T1098": 8.0,   # Account Manipulation
    "T1070": 8.0,   # Indicator Removal
    "T1087": 6.0,   # Account Discovery
    "T1486": 10.0,  # Data Encrypted for Impact (Ransomware)
}


def score_incident(incident: dict[str, Any]) -> float:
    """Compute a composite 1.0 - 10.0 dynamic risk score for an incident.

    Components:
    1. Kill chain progression depth (later tactics = higher risk)
    2. Tactic breadth (campaign breadth bonus across multiple distinct tactics)
    3. Asset criticality (reachable or compromised domain controllers, databases, critical hosts)
    4. Detection and evidence event volume (corroboration weighting)
    """
    raw_techniques = incident.get("techniques", [])
    if isinstance(raw_techniques, str):
        try:
            techniques = json.loads(raw_techniques)
        except Exception:
            techniques = [raw_techniques]
    else:
        techniques = list(raw_techniques or [])

    steps = incident.get("steps", [])
    if isinstance(steps, str):
        try:
            steps = json.loads(steps)
        except Exception:
            steps = []

    # 1. Kill chain progression depth
    progression_scores: list[float] = []
    tactics_seen: set[str] = set()

    for step in steps:
        tactic_norm = normalise_tactic(step.get("tactic", ""))
        if tactic_norm:
            tactics_seen.add(tactic_norm)
            progression_scores.append(_TACTIC_PROGRESSION_WEIGHTS.get(tactic_norm, 5.0))

    depth_score = max(progression_scores) if progression_scores else 5.0

    # 2. Tactic breadth bonus (attacks spanning multiple tactics are coordinated campaigns)
    breadth_bonus = min(2.0, (len(tactics_seen) - 1) * 0.5) if len(tactics_seen) > 1 else 0.0

    # 3. Technique severity average
    tech_scores = [
        _BASE_TECHNIQUE_SCORES.get(t.split(".")[0], 6.0)
        for t in techniques if t
    ]
    tech_avg = sum(tech_scores) / len(tech_scores) if tech_scores else 5.0

    # 4. Asset criticality bonus (from incident hosts or reach data)
    crit_bonus = 0.0
    hosts = incident.get("hosts", [])
    if isinstance(hosts, str):
        try:
            hosts = json.loads(hosts)
        except Exception:
            hosts = [hosts]

    for h in hosts:
        h_low = str(h).lower()
        if any(pat in h_low for pat in DEFAULT_PATTERNS):
            crit_bonus = 1.5
            break

    # If reach data shows critical assets reached
    reach_crit = incident.get("critical_assets")
    if reach_crit:
        crit_bonus = max(crit_bonus, 1.5)

    # 5. Detection volume bonus (logarithmic scaling)
    det_count = int(incident.get("detection_count", len(incident.get("detection_ids", []))) or 1)
    vol_bonus = min(1.0, math.log2(det_count + 1) * 0.25)

    # Composite weighted score
    composite = (depth_score * 0.45) + (tech_avg * 0.35) + breadth_bonus + crit_bonus + vol_bonus

    # Clamp to [1.0, 10.0]
    final_score = max(1.0, min(10.0, composite))
    return round(final_score, 2)
