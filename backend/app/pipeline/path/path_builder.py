"""Attack path builder: orders attack steps into a kill chain timeline."""

from __future__ import annotations

import json
from typing import Any

from app.store import duck

# Canonical tactic order per MITRE ATT&CK Enterprise matrix
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


def normalise_tactic(tactic: str) -> str:
    """Normalize tactic name: lowercase, strip, and treat '_', '-', and spaces identically."""
    if not tactic:
        return ""
    t = str(tactic).strip().lower()
    return t.replace("_", "-").replace(" ", "-")


def _tactic_rank(tactic: str) -> int:
    """Return the 0-based rank of the tactic in the canonical kill chain."""
    t = normalise_tactic(tactic)
    try:
        return _TACTIC_ORDER.index(t)
    except ValueError:
        return len(_TACTIC_ORDER)


def build_path(incident_id: str) -> list[dict[str, Any]]:
    """Return ordered attack steps for *incident_id*.

    Primary sort: first_seen timestamp (chronological attack sequence matching ground truth).
    Secondary sort: tactic kill-chain order (tie-break for simultaneous detections).
    Exposes both tactic and kill_chain_stage on every step.
    """
    inc = duck.get_incident(incident_id)
    if not inc:
        return []
    steps = json.loads(inc["steps"]) if isinstance(inc["steps"], str) else inc["steps"]

    # Sort primarily chronological (as attacks unfold), secondarily by tactic kill chain order
    steps.sort(key=lambda s: (
        str(s.get("first_seen", "")),
        _tactic_rank(s.get("tactic", "")),
    ))

    for i, step in enumerate(steps, 1):
        step["step_order"] = i
        # Ensure tactic and kill_chain_stage are always present
        step["tactic"] = normalise_tactic(step.get("tactic", ""))
        step["kill_chain_stage"] = step.get("kill_chain_stage") or ""

    return steps
