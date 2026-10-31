"""Risk scoring for incidents and detections."""

from __future__ import annotations

import json

_BASE_TECHNIQUE_SCORES: dict[str, float] = {
    "T1078": 8.0,   # Valid Accounts
    "T1053": 7.5,   # Scheduled Task
    "T1059": 7.0,   # Command & Scripting
    "T1082": 5.0,   # System Information Discovery
    "T1003": 9.0,   # OS Credential Dumping
    "T1486": 10.0,  # Data Encrypted for Impact (ransomware)
}


def score_incident(incident: dict) -> float:
    """Compute a composite 1-10 risk score for an incident.

    Score = weighted average of technique severity + breadth bonus.
    """
    techniques = json.loads(incident["techniques"]) if isinstance(incident["techniques"], str) else incident["techniques"]
    if not techniques:
        return float(incident.get("severity", 5))

    scores = [_BASE_TECHNIQUE_SCORES.get(t[:5], float(incident.get("severity", 5)))
              for t in techniques]
    avg = sum(scores) / len(scores)
    breadth_bonus = min(len(techniques) * 0.2, 2.0)
    return round(min(avg + breadth_bonus, 10.0), 2)

