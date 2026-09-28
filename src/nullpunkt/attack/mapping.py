"""Map incidents to MITRE ATT&CK techniques through the detection rule catalog.

Every alert's rule names one technique and the tactic it detects it in. An incident's techniques
are those of its alerts, in order of first appearance, deduplicated by (technique, tactic) so
that T1078 used for initial access and for stealth stays two entries. Rules missing from the
catalog produce no technique and are reported as unmapped; Phase 5 may suggest a technique for
them with ``confirmed=False``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nullpunkt.attack.reference import AttackReference, load_reference
from nullpunkt.core.detection_rules import RULES_BY_NAME
from nullpunkt.core.schema import Alert, Incident, Technique


@dataclass
class MappingResult:
    techniques: dict[str, list[Technique]]  # incident_id -> techniques
    unmapped: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    """incident_id -> {rule_name: [alert_id, ...]} for rules not in the catalog."""
    attack_version: str = ""


def _map(
    incident: Incident, alerts_by_id: dict[str, Alert], reference: AttackReference
) -> tuple[list[Technique], dict[str, list[str]]]:
    techniques: list[Technique] = []
    seen: set[tuple[str, str]] = set()
    unmapped: dict[str, list[str]] = {}
    for alert_id in incident.alert_ids:
        alert = alerts_by_id[alert_id]
        rule = RULES_BY_NAME.get(alert.rule_name)
        if rule is None:
            unmapped.setdefault(alert.rule_name, []).append(alert_id)
            continue
        key = (rule.technique, rule.tactic)
        if key in seen:
            continue
        seen.add(key)
        techniques.append(
            Technique(
                technique_id=rule.technique,
                name=reference.techniques[rule.technique].name,
                tactic=rule.tactic,
                confirmed=True,
            )
        )
    return techniques, unmapped


def map_incident(incident: Incident, alerts_by_id: dict[str, Alert]) -> list[Technique]:
    """Techniques for one incident, in order of first appearance."""
    return _map(incident, alerts_by_id, load_reference())[0]


def map_incidents(incidents: list[Incident], alerts_by_id: dict[str, Alert]) -> MappingResult:
    reference = load_reference()
    result = MappingResult(techniques={}, attack_version=reference.version)
    for incident in incidents:
        techniques, unmapped = _map(incident, alerts_by_id, reference)
        result.techniques[incident.incident_id] = techniques
        if unmapped:
            result.unmapped[incident.incident_id] = unmapped
    return result
