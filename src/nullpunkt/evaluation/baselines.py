"""Naive orderings of the same incidents, to compare our risk score against."""

from __future__ import annotations

from nullpunkt.core.schema import SEVERITY_WEIGHT, Alert, Incident


def by_severity(incidents: list[Incident], alerts_by_id: dict[str, Alert]) -> list[Incident]:
    """What a SIEM queue does: highest alert severity first, then most alerts."""

    def key(inc: Incident) -> tuple:
        severity = max(SEVERITY_WEIGHT[alerts_by_id[a].severity] for a in inc.alert_ids)
        return (-severity, -len(inc.alert_ids), inc.first_seen, inc.incident_id)

    return sorted(incidents, key=key)


def by_alert_count(incidents: list[Incident]) -> list[Incident]:
    """Biggest incidents first."""
    return sorted(incidents, key=lambda inc: (-len(inc.alert_ids), inc.first_seen, inc.incident_id))
