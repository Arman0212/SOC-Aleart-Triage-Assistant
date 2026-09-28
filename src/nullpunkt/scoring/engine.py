"""Risk scoring: one transparent formula, bounded to 0-100 by construction.

    risk = 100 x (S x C / 20) x (M / M_max) x N

S x C   Severity weight (1-4) x criticality (1-5) of the riskiest single alert-on-asset in the
        incident's evidence. Severity and criticality always come from the same alert.
M       Stage multiplier 1 + stage_step x (T - 1), where T is the number of distinct ATT&CK
        tactics in the evidence, capped at tactic_cap. M / M_max is in (0, 1].
N       Noise penalty in (0, 1]: the informativeness of the most informative evidence rule
        (rules that fire all the time carry little information), times routine_penalty if every
        alert in the incident is routine.

Evidence is the incident's non-routine alerts. A (rule, actor) pair is routine when it fires in
at least routine_min_hours different hours of the batch: a user's typo bursts, a service
account's sessions, a scanner. If an incident has no evidence, all of its alerts are used and
the incident is penalised. Nothing here reads labels: every statistic comes from the batch.

Asset at risk: each rule says whether its alerts threaten the host or the source. Source-side
alerts resolve to the source asset, else to the endpoint the account owns, else to the host,
except that relay infrastructure (DC as authenticator, proxy, mail gateway, VPN concentrator)
never lends its criticality: an unresolved source-side alert on a relay has criticality 1.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass

from nullpunkt.attack.reference import load_reference
from nullpunkt.core.config import ScoringConfig
from nullpunkt.core.detection_rules import RULES_BY_NAME
from nullpunkt.core.schema import SEVERITY_WEIGHT, Alert, Asset, AssetType, Incident, ScoreBreakdown

UNKNOWN_CRITICALITY = 1
CRITICALITY_WORD = {5: "critical", 4: "high-value", 3: "important", 2: "standard", 1: "low-value"}
SEVERITY_WORD = {1: "low", 2: "medium", 3: "high", 4: "critical"}


def actor_of(alert: Alert) -> str:
    """Who performed the activity: the user, else the source address, else the host."""
    return alert.user or alert.src_ip or alert.host


@dataclass(frozen=True)
class BatchContext:
    """Batch-level statistics the score depends on. Built once per batch, never from labels."""

    n_alerts: int
    informativeness: dict[str, float]  # rule_name -> (0, 1]
    routine_hours: dict[tuple[str, str], int]  # (rule_name, actor) -> distinct hours
    routine_min_hours: int
    asset_by_ip: dict[str, str]
    owned_endpoint: dict[str, str]  # user -> host they own

    def is_routine(self, alert: Alert) -> bool:
        hours = self.routine_hours.get((alert.rule_name, actor_of(alert)), 0)
        return hours >= self.routine_min_hours


def build_context(
    alerts: list[Alert], assets: dict[str, Asset], config: ScoringConfig
) -> BatchContext:
    n = len(alerts)
    per_rule = Counter(a.rule_name for a in alerts)
    log_n = math.log(n) if n > 1 else 0.0
    informativeness = {
        rule: (1 + math.log(n / count)) / (1 + log_n) for rule, count in per_rule.items()
    }
    start = min((a.timestamp for a in alerts), default=None)
    hours: dict[tuple[str, str], set[int]] = defaultdict(set)
    for a in alerts:
        hour = int((a.timestamp - start).total_seconds() // 3600) if start else 0
        hours[(a.rule_name, actor_of(a))].add(hour)
    endpoint_types = {AssetType.WORKSTATION, AssetType.LAPTOP}
    owned = {}
    for host in sorted(assets):
        asset = assets[host]
        if asset.asset_type in endpoint_types:
            owned.setdefault(asset.owner, host)
    return BatchContext(
        n_alerts=n,
        informativeness=informativeness,
        routine_hours={k: len(v) for k, v in hours.items()},
        routine_min_hours=config.routine_min_hours,
        asset_by_ip={asset.ip: host for host, asset in assets.items()},
        owned_endpoint=owned,
    )


def asset_at_risk(
    alert: Alert, assets: dict[str, Asset], context: BatchContext, config: ScoringConfig
) -> tuple[str | None, int]:
    """(asset, criticality) this alert threatens. The asset is None when it cannot be resolved."""
    rule = RULES_BY_NAME.get(alert.rule_name)
    if rule is not None and rule.asset_at_risk == "source":
        source = context.asset_by_ip.get(alert.src_ip) if alert.src_ip else None
        resolved = source or (context.owned_endpoint.get(alert.user) if alert.user else None)
        if resolved:
            return resolved, assets[resolved].criticality
        host_asset = assets.get(alert.host)
        if host_asset is not None and host_asset.asset_type in config.relay_asset_types:
            return None, UNKNOWN_CRITICALITY
    host_asset = assets.get(alert.host)
    if host_asset is None:
        return None, UNKNOWN_CRITICALITY
    return alert.host, host_asset.criticality


@dataclass(frozen=True)
class ScoreDetail:
    """Everything behind one score, for the UI and for tests."""

    score: ScoreBreakdown
    asset: str | None
    peak_alert: str
    evidence: tuple[str, ...]  # alert ids
    tactics: tuple[str, ...]  # short names, kill-chain order
    routine_only: bool


def _tactic_label(shortname: str) -> str:
    return shortname.replace("-", " ")


def score_incident(
    incident: Incident,
    alerts_by_id: dict[str, Alert],
    assets: dict[str, Asset],
    context: BatchContext,
    config: ScoringConfig | None = None,
) -> ScoreDetail:
    cfg = config or ScoringConfig()
    reference = load_reference()
    alerts = [alerts_by_id[a] for a in incident.alert_ids]
    evidence = [a for a in alerts if not context.is_routine(a)]
    routine_only = not evidence
    basis = evidence or alerts

    # Riskiest alert-on-asset: severity and criticality from the same alert.
    peak, asset, severity, criticality = None, None, 0, 0
    for a in basis:
        where, crit = asset_at_risk(a, assets, context, cfg)
        sev = SEVERITY_WEIGHT[a.severity]
        if (sev * crit, crit) > (severity * criticality, criticality):
            peak, asset, severity, criticality = a, where, sev, crit
    assert peak is not None

    known = [RULES_BY_NAME[a.rule_name] for a in basis if a.rule_name in RULES_BY_NAME]
    tactics = tuple(sorted({r.tactic for r in known}, key=reference.tactic_index))
    counted = min(max(len(tactics), 1), cfg.tactic_cap)
    stage = 1 + cfg.stage_step * (counted - 1)
    stage_max = 1 + cfg.stage_step * (cfg.tactic_cap - 1)

    rarest = max(basis, key=lambda a: context.informativeness.get(a.rule_name, 1.0))
    info = context.informativeness.get(rarest.rule_name, 1.0)
    penalty = info * (cfg.routine_penalty if routine_only else 1.0)

    risk = 100 * (severity * criticality / 20) * (stage / stage_max) * penalty
    where = f"asset {asset}" if asset else "unresolved asset"
    tactic_text = " → ".join(_tactic_label(t) for t in tactics) or "no mapped tactic"
    n_tactics = f"{len(tactics)} tactic{'s' if len(tactics) != 1 else ''}"
    if len(tactics) > cfg.tactic_cap:
        n_tactics += f" ({cfg.tactic_cap} counted)"
    explanation = (
        f"{CRITICALITY_WORD[criticality]} {where} ({criticality}) × "
        f"{SEVERITY_WORD[severity]} severity ({peak.rule_name}) × "
        f"{n_tactics}: {tactic_text}; rarest evidence: {rarest.rule_name}"
    )
    if routine_only:
        explanation += f"; routine activity (every alert repeats in ≥{cfg.routine_min_hours} hours)"
    score = ScoreBreakdown(
        severity_weight=severity,
        asset_criticality=criticality,
        stage_multiplier=round(stage, 4),
        noise_penalty=round(penalty, 4),
        risk_score=round(risk, 2),
        explanation=explanation,
    )
    return ScoreDetail(
        score=score,
        asset=asset,
        peak_alert=peak.alert_id,
        evidence=tuple(a.alert_id for a in evidence),
        tactics=tactics,
        routine_only=routine_only,
    )


def priority_tier(risk_score: float, config: ScoringConfig | None = None) -> str:
    """P1-P4 from fixed score thresholds (not ranks), so a quiet shift has no P1."""
    p1, p2, p3 = (config or ScoringConfig()).tier_thresholds
    if risk_score >= p1:
        return "P1"
    if risk_score >= p2:
        return "P2"
    if risk_score >= p3:
        return "P3"
    return "P4"


def rank(incidents: list[Incident]) -> list[Incident]:
    """Highest risk first; ties by criticality, then first_seen, then incident_id."""

    def key(inc: Incident) -> tuple:
        if inc.score is None:
            raise ValueError(f"{inc.incident_id} has no score")
        return (
            -inc.score.risk_score,
            -inc.score.asset_criticality,
            inc.first_seen,
            inc.incident_id,
        )

    return sorted(incidents, key=key)
