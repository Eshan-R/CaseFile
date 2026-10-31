"""Attack path builder: orders attack steps into a kill chain timeline."""

from __future__ import annotations

import json
from typing import Any

from app.store import duck

# Canonical tactic order per ATT&CK Enterprise matrix
_TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def _tactic_rank(tactic: str) -> int:
    t = tactic.lower().replace(" ", "-")
    try:
        return _TACTIC_ORDER.index(t)
    except ValueError:
        return len(_TACTIC_ORDER)


def build_path(incident_id: str) -> list[dict[str, Any]]:
    """Return ordered attack steps for *incident_id*.

    Primary sort: tactic kill-chain order.
    Secondary sort: first_seen timestamp.
    """
    inc = duck.get_incident(incident_id)
    if not inc:
        return []
    steps = json.loads(inc["steps"]) if isinstance(inc["steps"], str) else inc["steps"]
    steps.sort(key=lambda s: (
        _tactic_rank(s.get("tactic", "")),
        s.get("first_seen", ""),
    ))
    for i, step in enumerate(steps, 1):
        step["step_order"] = i
    return steps

