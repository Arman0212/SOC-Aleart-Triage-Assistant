"""Explainability for correlation: why alerts were grouped, and which entities were hubs.

These are in-memory results, not part of the data contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nullpunkt.core.config import CorrelationConfig
from nullpunkt.core.schema import Incident

_KIND_LABEL = {"host": "host", "user": "user", "ip": "IP"}


def split_entity(entity: str) -> tuple[str, str]:
    """'user:jill.rhodes' -> ('user', 'jill.rhodes')."""
    kind, _, value = entity.partition(":")
    return kind, value


def _gap_text(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)} s apart"
    if seconds < 3600:
        return f"{round(seconds / 60)} min apart"
    return f"{seconds / 3600:.1f} h apart"


@dataclass(frozen=True)
class Link:
    """One union made by the correlator: ``alert_id`` joined ``linked_to``'s incident."""

    alert_id: str
    linked_to: str
    reason: str  # "entity", "target", "recurrence" or "routine"
    entity: str  # e.g. "user:jill.rhodes", "host:WEB02", "ip:192.0.2.83"
    gap_seconds: float
    rule_name: str | None = None  # set for recurrence

    def describe(self) -> str:
        kind, value = split_entity(self.entity)
        label = f"{_KIND_LABEL.get(kind, kind)} {value}"
        gap = _gap_text(self.gap_seconds)
        if self.reason == "entity":
            return f"same {label}, {gap}"
        if self.reason == "target":
            return f"activity on {label} after it was targeted, {gap}"
        if self.reason == "recurrence":
            return f"'{self.rule_name}' recurring on {label}, {gap}"
        return f"routine activity of hub {label}, {gap}"


@dataclass(frozen=True)
class HubStat:
    entity: str
    alerts: int
    share: float
    distinct_users: int
    fanout: int
    reasons: tuple[str, ...]


@dataclass
class CorrelationResult:
    incidents: list[Incident]
    links: dict[str, list[Link]]  # incident_id -> the links that built it
    hubs: list[HubStat]
    config: CorrelationConfig
    incident_of: dict[str, str] = field(default_factory=dict)  # alert_id -> incident_id

    def explain(self, incident_id: str) -> list[str]:
        return [
            f"{link.alert_id} + {link.linked_to}: {link.describe()}"
            for link in self.links[incident_id]
        ]
