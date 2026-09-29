"""Deterministic fallback brief, built from the same context the model sees.

Used when the model is unreachable, times out or fails validation twice. It states only facts
from the context, so it passes validation by construction.
"""

from __future__ import annotations

from nullpunkt.briefing.context import BriefContext
from nullpunkt.briefing.validation import BriefDraft
from nullpunkt.core.schema import Confidence

MAX_TIMELINE = 6

STAKE = {
    "impact": "availability and backups are at risk",
    "exfiltration": "data may already have left",
    "collection": "data is being gathered",
    "command-and-control": "an attacker may have remote control",
    "lateral-movement": "the attacker is spreading between hosts",
    "credential-access": "credentials are at risk",
    "discovery": "the attacker is mapping the network",
    "privilege-escalation": "the attacker may hold elevated rights",
    "persistence": "the attacker may have a foothold",
    "stealth": "a valid account is likely being misused",
    "defense-impairment": "security controls may be disabled",
    "execution": "suspicious code ran",
    "initial-access": "an entry point was likely used",
    "reconnaissance": "the environment is being probed",
    "resource-development": "attacker infrastructure is involved",
}


def _label(tactic: str) -> str:
    return tactic.replace("-", " ")


def _pick_timeline(rows: list[dict]) -> list[dict]:
    """First, last and key rows first; fill with the rest, keep time order."""
    if len(rows) <= MAX_TIMELINE:
        return rows
    keep = {0, len(rows) - 1}
    for i in range(1, len(rows) - 1):
        if len(keep) >= MAX_TIMELINE:
            break
        keep.add(i)
    return [rows[i] for i in sorted(keep)]


def template_brief(ctx: BriefContext, confidence: Confidence) -> BriefDraft:
    data = ctx.data
    head = data["headline"]
    zone = data["timezone"]
    rows = data["evidence_timeline"]
    asset = head["asset_at_risk"]
    tactics = head["tactics_reached"]

    furthest = tactics[-1] if tactics else None
    if asset:
        exposed = (
            f"{head['asset_type']} {asset} (criticality {head['criticality']}) "
            "is the most exposed asset"
        )
    else:
        exposed = "the exposed asset could not be resolved"
    if furthest:
        line1 = (
            f"{data['tier']}: likely compromise that reached {_label(furthest)}, so "
            f"{STAKE.get(furthest, 'the activity needs review')}; {exposed}."
        )
    else:
        line1 = f"{data['tier']}: suspicious activity with no mapped tactic; {exposed}."

    if rows:
        first = rows[0]
        who = f" by {first['user']}" if first.get("user") else ""
        line2 = f"It began at {first['time']} {zone} with {first['rule']} on {first['host']}{who}"
    else:
        line2 = "No single alert stands out"
    routine = len(data["routine_activity"])
    if routine:
        line2 += f", alongside {routine} collapsed routine pattern{'s' if routine != 1 else ''}"
    line2 += "."

    timeline = [
        f"{r['time']} {zone} - "
        + (f"{r['count']} × " if r.get("count") else "")
        + f"{r['rule']} on {r['host']}"
        + (f" ({r['user']})" if r.get("user") else "")
        for r in _pick_timeline(rows)
    ]
    timeline += data["routine_activity"][:1]
    if not timeline:
        timeline = [f"{data['window']} - {head['key_alert']}"]

    actions = [entry["action"] for entry in data["playbook_most_urgent_first"][:2]]
    target = f" Start with {asset}." if asset else ""
    next_action = " ".join(actions) + target if actions else f"Review {head['key_alert']}.{target}"

    assets = [a["host"] for a in data["assets_at_risk"]]
    if not assets:
        assets = [asset] if asset in ctx.incident.hosts else list(ctx.incident.hosts[:3])
    return BriefDraft(
        summary=f"{line1}\n{line2}",
        affected_assets=assets,
        techniques=list(dict.fromkeys(t["id"] for t in data["techniques"])),
        timeline=timeline,
        next_action=next_action,
        confidence=confidence,
    )
