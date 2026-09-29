"""Build the compact, structured incident summary a brief is written from.

The model never sees raw alert dumps. It sees:

- a headline from the scoring detail (asset at risk, key alert, tactics reached), so the brief
  leads with what made the incident risky rather than with its noisiest alerts;
- assets at risk (resolved as in scoring) separately from relay hosts that only carried traffic;
- evidence alerts one by one, in time order, and routine alerts collapsed into one line per rule
  ("46 × Failed login, 09:08–18:35 IST, routine");
- the playbook entries for the tactics reached, most urgent first.

Times are shown in the company time zone. Alert messages come from the outside world and are
marked ``message_untrusted``. ``trusted`` holds the identifiers that come from structured alert
fields, which is what the validator allows a brief to mention; text that only appears inside a
message is never trusted.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from zoneinfo import ZoneInfo

from nullpunkt.briefing.playbook import playbook_for
from nullpunkt.core.config import ScoringConfig
from nullpunkt.core.detection_rules import RULES_BY_NAME
from nullpunkt.core.schema import Alert, Asset, Incident
from nullpunkt.scoring.engine import BatchContext, ScoreDetail, asset_at_risk

MAX_EVIDENCE_ROWS = 12


@dataclass(frozen=True)
class Trusted:
    """Identifiers a brief may mention: they come from structured fields, never from messages."""

    hosts: frozenset[str]
    users: frozenset[str]
    ips: frozenset[str]
    techniques: frozenset[str]
    tactics: frozenset[str]
    other: frozenset[str]  # incident id and similar tokens
    known_users: frozenset[str] = field(default=frozenset())  # every user in the batch


@dataclass(frozen=True)
class BriefContext:
    """One incident prepared for briefing: the JSON the model sees and the trusted facts the
    validator checks against."""

    incident: Incident
    data: dict  # the JSON the model sees
    trusted: Trusted
    evidence_tactics: tuple[str, ...]
    evidence_rules: int  # distinct rules among evidence alerts
    routine_only: bool

    @property
    def incident_id(self) -> str:
        return self.incident.incident_id


def _clock(ts: datetime, tz: ZoneInfo) -> str:
    return ts.astimezone(tz).strftime("%H:%M")


def build_context(
    incident: Incident,
    detail: ScoreDetail,
    rank: int,
    tier: str,
    alerts_by_id: dict[str, Alert],
    assets: dict[str, Asset],
    batch: BatchContext,
    scoring: ScoringConfig,
    timezone: str,
    known_users: frozenset[str] = frozenset(),
) -> BriefContext:
    """The compact context for briefing one ranked incident: headline, assets, users, techniques,
    grouped evidence timeline, routine activity and playbook."""
    if incident.score is None:
        raise ValueError(f"{incident.incident_id} must be scored before it is briefed")
    tz = ZoneInfo(timezone)
    zone = incident.first_seen.astimezone(tz).tzname() or timezone  # e.g. IST
    alerts = [alerts_by_id[a] for a in incident.alert_ids]
    evidence_ids = set(detail.evidence) if detail.evidence else set(incident.alert_ids)
    host_of_ip = batch.asset_by_ip

    # Consecutive evidence alerts with the same rule, host and user are one row with a count
    # (a brute-force burst is one step of the story, not eight).
    bursts: list[list[Alert]] = []
    routine: OrderedDict[str, list[Alert]] = OrderedDict()
    for a in alerts:
        if a.alert_id not in evidence_ids:
            routine.setdefault(a.rule_name, []).append(a)
            continue
        last = bursts[-1][-1] if bursts else None
        if last and (last.rule_name, last.host, last.user) == (a.rule_name, a.host, a.user):
            bursts[-1].append(a)
        else:
            bursts.append([a])
    evidence: list[dict] = []
    for burst in bursts:
        a = burst[0]
        rule = RULES_BY_NAME.get(a.rule_name)
        start, end = _clock(a.timestamp, tz), _clock(burst[-1].timestamp, tz)
        row = {
            "time": start if start == end else f"{start}–{end}",
            "count": len(burst) if len(burst) > 1 else None,
            "rule": a.rule_name,
            "severity": a.severity.value,
            "technique": rule.technique if rule else None,
            "host": a.host,
            "user": a.user,
            "from": (host_of_ip.get(a.src_ip) or a.src_ip) if a.src_ip else None,
            "to": (host_of_ip.get(a.dst_ip) or a.dst_ip) if a.dst_ip else None,
            "message_untrusted": a.message,
        }
        evidence.append({k: v for k, v in row.items() if v is not None})
    omitted = 0
    if len(evidence) > MAX_EVIDENCE_ROWS:
        omitted = len(evidence) - MAX_EVIDENCE_ROWS
        evidence = evidence[:MAX_EVIDENCE_ROWS]

    # Only hosts of this incident: an account owner's endpoint that the incident never touched
    # (the scoring fallback for source-side alerts) is not something the brief may list.
    incident_hosts = set(incident.hosts)
    at_risk: dict[str, int] = {}
    for alert_id in detail.evidence or incident.alert_ids:
        host, criticality = asset_at_risk(alerts_by_id[alert_id], assets, batch, scoring)
        if host and host in incident_hosts:
            at_risk[host] = max(criticality, at_risk.get(host, 0))
    ordered_risk = sorted(at_risk.items(), key=lambda kv: (-kv[1], kv[0]))
    peak = alerts_by_id[detail.peak_alert]
    score = incident.score

    data = {
        "incident_id": incident.incident_id,
        "rank": rank,
        "tier": tier,
        "risk_score": score.risk_score,
        "window": f"{_clock(incident.first_seen, tz)}-{_clock(incident.last_seen, tz)} {zone}",
        "timezone": zone,
        "headline": {
            "asset_at_risk": detail.asset,
            "asset_type": assets[detail.asset].asset_type.value if detail.asset else None,
            "criticality": score.asset_criticality,
            "key_alert": peak.rule_name,
            "key_alert_time": _clock(peak.timestamp, tz),
            "tactics_reached": list(detail.tactics),
        },
        "score_explanation": score.explanation,
        "assets_at_risk": [
            {"host": h, "type": assets[h].asset_type.value, "criticality": c}
            for h, c in ordered_risk
        ],
        "other_hosts_seen": [h for h in incident.hosts if h not in at_risk],
        "users": list(incident.users),
        "techniques": [
            {"id": t.technique_id, "name": t.name, "tactic": t.tactic} for t in incident.techniques
        ],
        "evidence_timeline": evidence,
        "routine_activity": [
            f"{len(group)} × {rule}, {_clock(group[0].timestamp, tz)}–"
            f"{_clock(group[-1].timestamp, tz)} {zone}, routine"
            for rule, group in routine.items()
        ],
        "playbook_most_urgent_first": playbook_for(detail.tactics),
    }
    if omitted:
        data["evidence_omitted"] = omitted

    evidence_alerts = [alerts_by_id[a] for a in (detail.evidence or incident.alert_ids)]
    trusted = Trusted(
        hosts=frozenset(incident.hosts) | ({detail.asset} if detail.asset else set()),
        users=frozenset(incident.users),
        ips=frozenset(incident.ips),
        techniques=frozenset(t.technique_id for t in incident.techniques),
        tactics=frozenset(detail.tactics),
        other=frozenset({incident.incident_id, tier}),
        known_users=known_users,
    )
    return BriefContext(
        incident=incident,
        data=data,
        trusted=trusted,
        evidence_tactics=tuple(detail.tactics),
        evidence_rules=len({a.rule_name for a in evidence_alerts}),
        routine_only=detail.routine_only,
    )
