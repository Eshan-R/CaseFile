"""Markdown report template (no LLM required)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from app.store import duck


def render(incident_id: str) -> str:
    """Render a Markdown incident report from stored data."""
    inc = duck.get_incident(incident_id)
    if not inc:
        return f"# Incident Not Found\n\nID: {incident_id}"

    hosts = json.loads(inc["hosts"]) if isinstance(inc["hosts"], str) else inc["hosts"]
    techniques = json.loads(inc["techniques"]) if isinstance(inc["techniques"], str) else inc["techniques"]
    steps = json.loads(inc["steps"]) if isinstance(inc["steps"], str) else inc["steps"]
    users = json.loads(inc["users"]) if isinstance(inc["users"], str) else inc["users"]
    src_ips = json.loads(inc["src_ips"]) if isinstance(inc["src_ips"], str) else inc["src_ips"]

    lines: list[str] = [
        f"# Incident Report: {inc['title']}",
        "",
        f"**Incident ID:** `{incident_id}`  ",
        f"**Severity:** {inc['severity']}/10  ",
        f"**Status:** {inc['status']}  ",
        f"**First seen:** {inc['first_seen']}  ",
        f"**Last seen:** {inc['last_seen']}  ",
        "",
        "## Affected Entities",
        "",
        f"- **Hosts:** {', '.join(hosts) or 'none'}",
        f"- **Users:** {', '.join(users) or 'none'}",
        f"- **Source IPs:** {', '.join(src_ips) or 'none'}",
        "",
        "## Kill Chain",
        "",
    ]

    for step in steps:
        lines.append(
            f"### Step {step.get('step_order', '?')}: "
            f"`{step.get('technique_id', '?')}` – {step.get('tactic', '?')}"
        )
        lines.append(f"- First seen: {step.get('first_seen', '?')}")
        lines.append(f"- Last seen: {step.get('last_seen', '?')}")
        lines.append(f"- Hosts: {', '.join(step.get('hosts', []))}")
        lines.append("")

    lines += [
        "## Techniques (ordered)",
        "",
        "\n".join(f"- {t}" for t in techniques),
        "",
        f"---\n*Generated at {datetime.now(UTC).isoformat()}*",
    ]

    return "\n".join(lines)

