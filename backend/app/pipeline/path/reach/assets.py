"""Asset classification and criticality evaluation based on rules/assets.yaml."""

from __future__ import annotations

import math
import os
from typing import Any

import yaml

DEFAULT_PATTERNS = ["dc", "domain", "ad", "fs", "file", "sql", "db", "backup"]
DEFAULT_EXPLICIT = {
    "dc-01",
    "dc-02",
    "dc-server",
    "ad-primary",
    "fs-01",
    "file-server",
    "db-server",
    "sql-prod",
    "backup-vault",
}
DEFAULT_ADMIN_PCT = 0.05


def load_asset_rules(yaml_path: str = "rules/assets.yaml") -> dict[str, Any]:
    """Load asset patterns and explicit critical hosts from YAML."""
    if not os.path.exists(yaml_path):
        return {
            "patterns": DEFAULT_PATTERNS,
            "explicit_hosts": DEFAULT_EXPLICIT,
            "auto_critical_admin_pct": DEFAULT_ADMIN_PCT,
        }

    try:
        with open(yaml_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        data = {}

    patterns = [str(p).strip().lower() for p in data.get("patterns", DEFAULT_PATTERNS) if p]
    explicit = {str(h).strip().lower() for h in data.get("explicit_hosts", DEFAULT_EXPLICIT) if h}
    admin_pct = float(data.get("auto_critical_admin_pct", DEFAULT_ADMIN_PCT))

    return {
        "patterns": patterns,
        "explicit_hosts": explicit,
        "auto_critical_admin_pct": admin_pct,
    }


def identify_critical_assets(
    all_hosts: set[str],
    access_edges: list[dict[str, Any]],
    asset_rules: dict[str, Any] | None = None,
) -> set[str]:
    """Identify which hosts qualify as critical assets.

    Rules applied:
    1. Explicit list match from rules/assets.yaml
    2. Name pattern match (dc, domain, ad, fs, file, sql, db, backup)
    3. Automatic rule: top 5% of hosts by distinct admin users
    """
    rules = asset_rules or load_asset_rules()
    patterns: list[str] = rules.get("patterns", DEFAULT_PATTERNS)
    explicit_hosts: set[str] = rules.get("explicit_hosts", DEFAULT_EXPLICIT)
    auto_admin_pct: float = rules.get("auto_critical_admin_pct", DEFAULT_ADMIN_PCT)

    critical: set[str] = set()

    # Rule 1 & Rule 2: Explicit match & pattern match
    for host in all_hosts:
        h_lower = host.lower()
        if h_lower in explicit_hosts:
            critical.add(host)
            continue
        for pat in patterns:
            if pat in h_lower:
                critical.add(host)
                break

    # Rule 3: Top N% of hosts by distinct admin users
    admin_users_by_host: dict[str, set[str]] = {}
    for edge in access_edges:
        if edge.get("is_admin") or edge.get("kind") == "admin":
            tgt = edge.get("target")
            src = edge.get("source")
            if tgt and src:
                admin_users_by_host.setdefault(tgt, set()).add(src)

    if admin_users_by_host and all_hosts:
        # Sort hosts with admin users descending by distinct admin user count
        sorted_hosts = sorted(
            admin_users_by_host.keys(),
            key=lambda h: len(admin_users_by_host[h]),
            reverse=True,
        )
        cutoff = max(1, math.ceil(len(all_hosts) * auto_admin_pct))
        for top_host in sorted_hosts[:cutoff]:
            critical.add(top_host)

    return critical
