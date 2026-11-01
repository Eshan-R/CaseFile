"""Behavioral Rule Candidate Generator and Noise Guard Dry-Run."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import yaml

from app.pipeline.detect.engine import compile_rule_to_sql
from app.pipeline.patterns.base import PatternCandidate
from app.schemas.rule import Rule, RuleCondition
from app.store import duck

if TYPE_CHECKING:
    import duckdb

logger = logging.getLogger(__name__)


def pattern_to_rule_candidate(p: PatternCandidate | dict) -> Rule | None:
    """Translate a discovered threat pattern into a valid behavioral Rule model.

    STRICT CONSTRAINTS:
    - Never hardcode specific attacker IPs, victim IPs, or domain names into rule conditions.
    - Specific IPs and domains belong in iocs.csv only.
    - Emit threshold, rarity, or behavioral match rules.
    """
    data = p.__dict__ if hasattr(p, "__dict__") and not isinstance(p, dict) else dict(p)
    pid = data.get("pattern_id", "pat_unknown")
    kind = data.get("kind", "")
    details = data.get("details_json", {})
    if isinstance(details, str):
        try:
            import json
            details = json.loads(details)
        except Exception:
            details = {}

    rule_id = f"disc_{pid.replace('pat_', '')}"
    severity = 8 if float(data.get("score", 5.0)) >= 8.0 else 5

    # 1. Burst Patterns -> Threshold Rules
    if kind == "burst":
        event_class = str(details.get("event_class", "")).lower()
        if "auth" in event_class or "login" in event_class:
            return Rule(
                id=rule_id,
                name=f"Discovered: High-Rate Authentication Burst ({pid})",
                description="Behavioral threshold rule detecting sudden bursts of failed authentication attempts from any single source.",
                type="threshold",
                technique_id="T1110",
                tactic="Credential Access",
                severity=severity,
                conditions=[
                    RuleCondition(field="logid", op="in", value=["0100032002", "auth_failure"]),
                ],
                logic="all",
                group_by=["src_ip"],
                window_seconds=300,
                min_count=20,
            )
        elif int(details.get("distinct_dst_ports", 0)) >= 5 or int(details.get("distinct_dst_ips", 0)) >= 5:
            return Rule(
                id=rule_id,
                name=f"Discovered: Port Sweep / Network Discovery ({pid})",
                description="Behavioral threshold rule detecting a single source sweeping multiple destination ports or hosts.",
                type="threshold",
                technique_id="T1046",
                tactic="Discovery",
                severity=severity,
                conditions=[
                    RuleCondition(field="action", op="in", value=["deny", "block", "drop"]),
                ],
                logic="all",
                group_by=["src_ip"],
                window_seconds=300,
                min_count=10,
                min_distinct_field="dst_port",
                min_distinct=5,
            )
        else:
            return Rule(
                id=rule_id,
                name=f"Discovered: Volumetric Traffic Spike ({pid})",
                description="Behavioral threshold rule detecting sudden high-volume event surges from a single source.",
                type="threshold",
                technique_id="T1498",
                tactic="Impact",
                severity=severity,
                conditions=[
                    RuleCondition(field="action", op="in", value=["deny", "block", "drop"]),
                ],
                logic="all",
                group_by=["src_ip"],
                window_seconds=300,
                min_count=30,
            )

    # 2. Rarity Patterns -> Behavioral Signature Matches
    elif kind == "rarity":
        dim = details.get("dimension")
        val = details.get("value")
        if dim == "virus" and val:
            return Rule(
                id=rule_id,
                name=f"Discovered: Malware Signature Match ({pid})",
                description=f"Behavioral detection matching anomalous malware family '{val}'.",
                type="match",
                technique_id="T1204",
                tactic="Execution",
                severity=severity,
                conditions=[
                    RuleCondition(field="virus", op="eq", value=val),
                ],
                logic="all",
            )
        elif dim == "attack" and val:
            return Rule(
                id=rule_id,
                name=f"Discovered: Exploit Attempt ({pid})",
                description=f"Behavioral detection matching anomalous attack signature '{val}'.",
                type="match",
                technique_id="T1190",
                tactic="Initial Access",
                severity=severity,
                conditions=[
                    RuleCondition(field="attack", op="eq", value=val),
                ],
                logic="all",
            )

    # 3. Novel Edges -> Lateral Movement Thresholds
    elif kind == "novel_edges":
        dst_port = details.get("dst_port")
        is_lateral = details.get("is_lateral", False)
        if dst_port and is_lateral:
            return Rule(
                id=rule_id,
                name=f"Discovered: Internal Lateral Connection on Port {dst_port} ({pid})",
                description="Behavioral rule alerting on internal-to-internal lateral connections over sensitive ports.",
                type="threshold",
                technique_id="T1021",
                tactic="Lateral Movement",
                severity=severity,
                conditions=[
                    RuleCondition(field="dst_port", op="eq", value=int(dst_port)),
                    RuleCondition(field="action", op="in", value=["accept", "allow", "pass"]),
                ],
                logic="all",
                group_by=["src_ip", "dst_ip"],
                window_seconds=600,
                min_count=1,
            )

    # 4. Coordinated Patterns -> Distributed Thresholds
    elif kind == "coordinated":
        return Rule(
            id=rule_id,
            name=f"Discovered: Coordinated Multi-Source Ingress ({pid})",
            description="Behavioral rule detecting multiple distributed sources hitting the same destination.",
            type="threshold",
            technique_id="T1190",
            tactic="Initial Access",
            severity=severity,
            conditions=[
                RuleCondition(field="action", op="in", value=["deny", "block", "drop"]),
            ],
            logic="all",
            group_by=["dst_ip"],
            window_seconds=600,
            min_count=6,
            min_distinct_field="src_ip",
            min_distinct=2,
        )

    return None


def dry_run_rule(rule: Rule, con: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    """Dry-run a candidate rule against the DuckDB events view and evaluate noise guard."""
    try:
        rows = con.execute("DESCRIBE events").fetchall()
        cols = {r[0].lower() for r in rows}
    except Exception:
        cols = duck.get_events_columns()
    compiled_sql = compile_rule_to_sql(rule, valid_columns=cols)
    if not compiled_sql:
        return {"passed": False, "match_count": 0, "reason": "Failed to compile rule SQL"}

    try:
        count_query = f"SELECT COUNT(*) FROM ({compiled_sql})"
        match_count = con.execute(count_query).fetchone()[0]
    except Exception as exc:
        return {"passed": False, "match_count": 0, "reason": f"Execution error: {exc}"}

    # Noise Guard constraints:
    # Match rules: reject if > 1,000 matches
    # Threshold rules: reject if > 500 firing groups
    max_threshold = 1000 if rule.type == "match" else 500
    if match_count > max_threshold:
        return {
            "passed": False,
            "match_count": match_count,
            "reason": f"Noise guard triggered: {match_count} matches exceeds limit ({max_threshold})",
        }

    return {"passed": True, "match_count": match_count, "reason": "Passed noise guard"}


def export_discovered_rules(rules: list[Rule], output_path: str = "rules/discovered.yaml") -> str:
    """Export approved candidate rules to rules/discovered.yaml."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    clean_dicts = []
    for r in rules:
        d = r.model_dump(exclude_none=True)
        # Clean up empty or default fields
        if not d.get("min_distinct_field"):
            d.pop("min_distinct_field", None)
            d.pop("min_distinct", None)
        clean_dicts.append(d)

    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(clean_dicts, f, sort_keys=False)
    return output_path
