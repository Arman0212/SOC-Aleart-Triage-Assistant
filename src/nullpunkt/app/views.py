"""Presentation helpers shared by the Streamlit pages and the report (no Streamlit import here,
so everything is unit-testable)."""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from nullpunkt.attack.reference import load_reference
from nullpunkt.core.schema import Brief

TIER_COLOURS = {"P1": "#e5484d", "P2": "#f5a524", "P3": "#3b82f6", "P4": "#6b7280"}
TIER_MEANING = {
    "P1": "act now",
    "P2": "triage this shift",
    "P3": "review if time allows",
    "P4": "routine / low",
}
STATUS_LABEL = {"open": "open", "approved": "approved", "dismissed": "dismissed (FP)",
                "escalated": "escalated"}  # fmt: skip
TACTIC_SHORT = {
    "reconnaissance": "RC", "resource-development": "RD", "initial-access": "IA",
    "execution": "EX", "persistence": "PS", "privilege-escalation": "PE", "stealth": "ST",
    "defense-impairment": "DI", "credential-access": "CA", "discovery": "DS",
    "lateral-movement": "LM", "collection": "CO", "command-and-control": "C2",
    "exfiltration": "EF", "impact": "IM",
}  # fmt: skip


def tactic_name(shortname: str) -> str:
    """ATT&CK display name of a tactic shortname (title-cased if unknown)."""
    try:
        return load_reference().tactic(shortname).name
    except KeyError:
        return shortname.replace("-", " ").title()


def tactic_chain(tactics: tuple[str, ...] | list[str]) -> str:
    """Tactics as short tags joined by ›, for the queue."""
    return " › ".join(TACTIC_SHORT.get(t, t[:2].upper()) for t in tactics)


def risk_bar_fraction(risk: float, top_risk: float) -> float:
    """Risk relative to the shift's top incident, in [0, 1]."""
    return 0.0 if top_risk <= 0 else max(0.0, min(1.0, risk / top_risk))


def local_time(ts: datetime, tz: str, fmt: str = "%H:%M") -> str:
    """``ts`` formatted in time zone ``tz``."""
    return ts.astimezone(ZoneInfo(tz)).strftime(fmt)


def zone_name(ts: datetime, tz: str) -> str:
    """Abbreviation of ``tz`` at ``ts`` (for example IST), or ``tz`` itself."""
    return ts.astimezone(ZoneInfo(tz)).tzname() or tz


def brief_as_text(brief: Brief) -> str:
    """The brief as editable plain text (also what the handover prints)."""
    lines = [brief.summary.strip(), ""]
    lines.append(f"Affected assets: {', '.join(brief.affected_assets)}")
    lines.append(f"Techniques: {', '.join(brief.techniques)}")
    lines.append("Timeline:")
    lines += [f"- {entry}" for entry in brief.timeline]
    lines.append(f"Next action: {brief.next_action}")
    return "\n".join(lines)


BRIEF_LABELS = ("Verdict", "Assets", "Techniques", "Timeline", "Next action")


def brief_as_markdown(brief: Brief) -> str:
    """The brief for the handover: each field in its own paragraph with a bold label, the
    timeline as a list. Markdown joins single newlines, so fields are separated by blank lines."""
    summary = "  \n".join(line.strip() for line in brief.summary.strip().splitlines())
    parts = [
        f"**Verdict:** {summary}",
        f"**Assets:** {', '.join(brief.affected_assets)}",
        f"**Techniques:** {', '.join(brief.techniques)}",
        "**Timeline:**\n\n" + "\n".join(f"- {entry}" for entry in brief.timeline),
        f"**Next action:** {brief.next_action}",
    ]
    return "\n\n".join(parts)


def evidence_rows(alerts: list, evidence_ids: set[str], tz: str) -> list[dict]:
    """Evidence alerts in time order; consecutive alerts with the same rule, host and user are
    one row with a count."""
    rows: list[dict] = []
    for a in alerts:
        if a.alert_id not in evidence_ids:
            continue
        last = rows[-1] if rows else None
        if last and (last["rule"], last["host"], last["user"]) == (a.rule_name, a.host, a.user):
            last["count"] += 1
            last["end"] = local_time(a.timestamp, tz)
            continue
        rows.append(
            {
                "start": local_time(a.timestamp, tz),
                "end": local_time(a.timestamp, tz),
                "count": 1,
                "rule": a.rule_name,
                "severity": a.severity.value,
                "host": a.host,
                "user": a.user,
            }
        )
    return rows


def routine_lines(alerts: list, evidence_ids: set[str], tz: str) -> list[str]:
    """Routine (non-evidence) alerts collapsed to one line per rule."""
    groups: dict[str, list] = {}
    for a in alerts:
        if a.alert_id not in evidence_ids:
            groups.setdefault(a.rule_name, []).append(a)
    zone = zone_name(alerts[0].timestamp, tz) if alerts else ""
    return [
        f"{len(g)} × {rule}, {local_time(g[0].timestamp, tz)}–{local_time(g[-1].timestamp, tz)} "
        f"{zone}, routine"
        for rule, g in groups.items()
    ]


def techniques_in_kill_chain_order(techniques: list) -> list:
    """Techniques in kill-chain order of their tactic (unknown tactics last; first appearance kept
    within a tactic)."""
    ref = load_reference()

    def position(t) -> int:
        try:
            return ref.tactic_index(t.tactic)
        except KeyError:
            return len(ref.tactics)

    return sorted(techniques, key=position)  # stable: first appearance within a tactic
