"""Base types, helper macros, and constants for automated pattern discovery."""

from __future__ import annotations

import hashlib
import ipaddress
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# High-value lateral administration ports
SENSITIVE_PORTS = {
    22: "SSH",
    88: "Kerberos",
    389: "LDAP",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    27017: "MongoDB",
}

PUBLIC_WEB_PORTS = {80, 443, 8080, 8443}


def generate_pattern_id(kind: str, canonical_key: str) -> str:
    """Generate a stable, deterministic pattern ID using SHA-256."""
    raw = f"{kind}:{canonical_key}".strip().lower()
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"pat_{digest}"


def is_rfc1918_ip(ip: str | None) -> bool:
    """Return True if ip is a valid RFC1918 private IPv4 address."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
        return addr.version == 4 and addr.is_private and not addr.is_loopback
    except ValueError:
        return False


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy (in bits) of a string."""
    if not s:
        return 0.0
    s_lower = s.strip().lower()
    length = len(s_lower)
    if length <= 1:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s_lower:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


@dataclass
class PatternCandidate:
    """Represents a discovered threat pattern candidate."""

    pattern_id: str
    kind: str
    title: str
    support: int
    score: float
    first_seen: datetime | str | None = None
    last_seen: datetime | str | None = None
    entities: list[str] = field(default_factory=list)
    example_event_ids: list[str] = field(default_factory=list)
    suggested_technique: str | None = None
    suggested_tactic: str | None = None
    status: str = "new"
    details_json: dict[str, Any] = field(default_factory=dict)

