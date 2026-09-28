"""Correlation quality against ground truth. Evaluation only: this module reads labels."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nullpunkt.core.schema import Alert, Asset, GroundTruth, Incident

LARGE_INCIDENT_SHARE = 0.05


@dataclass(frozen=True)
class ScenarioScore:
    scenario_id: str
    alerts: int
    incident_id: str  # the incident holding most of the scenario's alerts
    captured: int
    incident_size: int

    @property
    def completeness(self) -> float:
        """Share of the scenario's alerts that are in its best incident."""
        return self.captured / self.alerts

    @property
    def purity(self) -> float:
        """Share of that incident's alerts that belong to the scenario."""
        return self.captured / self.incident_size


@dataclass(frozen=True)
class CorrelationMetrics:
    alerts: int
    incidents: int
    largest_incident: int
    scenarios: dict[str, ScenarioScore]

    @property
    def reduction_ratio(self) -> float:
        """Alerts per incident."""
        return self.alerts / self.incidents

    @property
    def largest_share(self) -> float:
        return self.largest_incident / self.alerts


def correlation_metrics(
    incidents: list[Incident], labels: dict[str, GroundTruth]
) -> CorrelationMetrics:
    incident_of = {a: inc.incident_id for inc in incidents for a in inc.alert_ids}
    size = {inc.incident_id: len(inc.alert_ids) for inc in incidents}
    by_scenario: dict[str, list[str]] = {}
    for label in labels.values():
        if label.scenario_id:
            by_scenario.setdefault(label.scenario_id, []).append(label.alert_id)

    scores = {}
    for scenario_id in sorted(by_scenario):
        members = by_scenario[scenario_id]
        counts = Counter(incident_of[a] for a in members)
        # Most scenario alerts first; ties go to the smaller, then earlier, incident.
        best, captured = min(counts.items(), key=lambda kv: (-kv[1], size[kv[0]], kv[0]))
        scores[scenario_id] = ScenarioScore(scenario_id, len(members), best, captured, size[best])
    return CorrelationMetrics(
        alerts=len(incident_of),
        incidents=len(incidents),
        largest_incident=max(size.values()),
        scenarios=scores,
    )


def is_single_activity(
    incident: Incident, alerts: dict[str, Alert], assets: dict[str, Asset]
) -> bool:
    """True if every alert shares one actor (user or source) or one target host, and the
    incident involves at most one user. Incidents above 5 % of a batch must satisfy this."""
    if len(incident.users) > 1:
        return False
    host_of_ip = {asset.ip: host for host, asset in assets.items()}

    def entities(a: Alert) -> set[str]:
        out = {f"host:{a.host}"}
        if a.user:
            out.add(f"user:{a.user}")
        if a.src_ip:
            out.add(f"host:{host_of_ip[a.src_ip]}" if a.src_ip in host_of_ip else f"ip:{a.src_ip}")
        return out

    common = set.intersection(*(entities(alerts[a]) for a in incident.alert_ids))
    return bool(common)
