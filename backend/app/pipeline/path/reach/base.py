"""Abstract base class for reach engines and common exceptions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.schemas.reach import NextReach


class NotConfigured(RuntimeError):
    """Raised when a reach engine backend is not configured or available."""

    pass


class ReachEngine(ABC):
    """Abstract base class for computing what an attacker can reach next."""

    name: str = "base"

    @abstractmethod
    def compute(
        self,
        incident: dict[str, Any],
        access_edges: list[dict[str, Any]],
        config: dict[str, Any] | None = None,
    ) -> NextReach:
        """Compute the NextReach projection from an incident and observed access edges.

        Args:
            incident: Incident dictionary with keys like incident_id, hosts, users, first_seen.
            access_edges: List of access edge dicts (source, target, kind, is_admin, count, last_seen).
            config: Optional configuration overrides (max_hops, time_budget, etc.).

        Returns:
            NextReach instance with blast radius, predicted paths, and reachable targets.
        """
        pass
