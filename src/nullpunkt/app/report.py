"""Shift handover report: Markdown, plus standalone HTML with print CSS (the browser's "Print →
Save as PDF" gives a PDF without adding a PDF library).

Lists only incidents whose latest decision is approve, edit or escalate, in rank order, with
their final brief text (the analyst's edit where there is one). Dismissed and undecided
incidents appear only in the counts.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

from nullpunkt.app.metrics import ShiftStats, format_duration, latest_decisions, shift_stats
from nullpunkt.app.views import brief_as_markdown
from nullpunkt.core.schema import Brief, DecisionAction
from nullpunkt.storage.repository import BatchInfo, DecisionRecord, Repository

REPORTED = (DecisionAction.APPROVE, DecisionAction.EDIT, DecisionAction.ESCALATE)
LABEL = {
    DecisionAction.APPROVE: "APPROVED",
    DecisionAction.EDIT: "EDITED & APPROVED",
    DecisionAction.ESCALATE: "ESCALATED",
}


@dataclass(frozen=True)
class ReportItem:
    """One incident in the handover, with the final text of its latest decision."""

    rank: int
    tier: str
    incident_id: str
    risk: float
    decision: DecisionRecord
    brief_text: str  # Markdown when ``brief`` is set, otherwise free text (an edit or the score)
    brief: Brief | None = None  # the unedited brief, for structured rendering


@dataclass(frozen=True)
class Handover:
    """Everything the handover report shows (built by ``build_handover``)."""

    batch: BatchInfo
    stats: ShiftStats
    items: list[ReportItem]
    generated_at: datetime
    brief_counts: dict[str, int]


def build_handover(repo: Repository, batch_id: str, scope: str | None = None) -> Handover:
    """The handover for one scope (a study session, or None for work outside sessions): the shift
    stats and the approved, edited and escalated incidents in rank order."""
    batch = repo.batch(batch_id)
    latest = latest_decisions(repo.scoped_decisions(batch_id, scope))
    items = []
    for row in repo.queue(batch_id):
        decision = latest.get(row.incident_id)
        if decision is None or decision.action not in REPORTED:
            continue
        view = repo.incident(batch_id, row.incident_id, scope)
        brief = None
        if decision.action is DecisionAction.EDIT and decision.edited_brief:
            text = decision.edited_brief
        elif view.brief is not None:
            brief = view.brief.brief
            text = brief_as_markdown(brief)
        else:
            text = view.incident.score.explanation if view.incident.score else ""
        items.append(
            ReportItem(row.rank, row.tier, row.incident_id, row.risk, decision, text, brief)
        )
    brief_counts = repo.brief_sources(batch_id)
    repo.log("report", "report_exported", batch_id, payload={"items": len(items)})
    return Handover(batch, shift_stats(repo, batch_id, scope), items, repo.now(), brief_counts)


def _local(ts: datetime, tz: str) -> str:
    return ts.astimezone(ZoneInfo(tz)).strftime("%H:%M")


def _stats_rows(h: Handover) -> tuple[list[str], list[str]]:
    s, by = h.stats, h.stats.by_action
    headers = ["Alerts", "Incidents", "Reduction", "Decided", "Approved", "Edited", "Escalated",
               "Dismissed", "Still open", "MTTT (first decisions)"]  # fmt: skip
    values = [
        f"{s.alerts:,}", str(s.incidents), f"{s.reduction_ratio:.0f}×", str(s.decided),
        str(by.get("approve", 0)), str(by.get("edit", 0)), str(by.get("escalate", 0)),
        str(by.get("dismiss", 0)), str(s.still_open), format_duration(s.mttt_seconds),
    ]  # fmt: skip
    return headers, values


def _heading(h: Handover, item: ReportItem) -> str:
    d, tz = item.decision, h.batch.timezone
    zone = d.decided_at.astimezone(ZoneInfo(tz)).tzname()
    return (
        f"{item.rank}. [{item.tier}] {item.incident_id} · risk {item.risk:.1f} · "
        f"{LABEL[d.action]} by {d.analyst} at {_local(d.decided_at, tz)} {zone}"
    )


def _window(h: Handover) -> str:
    tz = h.batch.timezone
    zone = h.batch.first_alert_at.astimezone(ZoneInfo(tz)).tzname()
    day = h.batch.first_alert_at.astimezone(ZoneInfo(tz)).strftime("%Y-%m-%d")
    return f"{day} {_local(h.batch.first_alert_at, tz)}–{_local(h.batch.last_alert_at, tz)} {zone}"


def to_markdown(h: Handover) -> str:
    """The handover as Markdown."""
    s = h.stats
    headers, values = _stats_rows(h)
    analysts = ", ".join(s.analysts) or "none yet"
    lines = [
        f"# Shift handover: {h.batch.batch_id}",
        "",
        f"{_window(h)} · report generated {_local(h.generated_at, h.batch.timezone)} "
        f"{h.generated_at.astimezone(ZoneInfo(h.batch.timezone)).tzname()} · "
        f"analysts: {analysts}",
        "",
        "## Shift at a glance",
        "",
        "| " + " | ".join(headers) + " |",
        "|" + "---|" * len(headers),
        "| " + " | ".join(values) + " |",
        "",
        "Tiers: "
        + " · ".join(f"{t} {c}" for t, c in s.tiers.items())
        + f". Re-decisions: {s.redecisions}."
        + (
            f" Briefs: {h.batch.model} (prompt {h.batch.prompt_version}), "
            f"{h.brief_counts.get('llm', 0)} LLM / {h.brief_counts.get('template', 0)} template."
            if h.batch.model
            else ""
        ),
        "",
        "## Incidents for the next shift (rank order)",
        "",
    ]
    if not h.items:
        lines.append("_No approved, edited or escalated incidents yet._")
    for item in h.items:
        lines += [f"### {_heading(h, item)}", ""]
        if item.decision.action is DecisionAction.ESCALATE and item.decision.notes:
            lines += [f"**Escalation note:** {item.decision.notes}", ""]
        lines += [item.brief_text if item.brief else _keep_line_breaks(item.brief_text), ""]
    return "\n".join(lines).rstrip() + "\n"


def _keep_line_breaks(text: str) -> str:
    """Free text (an analyst's edit) as Markdown that keeps its line breaks: Markdown would
    otherwise join consecutive lines into one paragraph."""
    lines = text.strip().splitlines()
    return "\n".join(
        line.rstrip() + ("  " if line.strip() and nxt.strip() else "")
        for line, nxt in zip(lines, [*lines[1:], ""], strict=True)
    )


CSS = """
body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; color: #111827;
       max-width: 900px; margin: 2rem auto; line-height: 1.45; }
h1 { font-size: 1.6rem; margin-bottom: .2rem; } h2 { margin-top: 2rem; }
h3 { font-size: 1.05rem; margin: 1.6rem 0 .4rem; }
table { border-collapse: collapse; margin: .6rem 0; }
th, td { border: 1px solid #d1d5db; padding: .3rem .6rem; text-align: right; }
th { background: #f3f4f6; } .meta { color: #4b5563; }
.tier { display: inline-block; padding: 0 .45rem; border-radius: 4px; color: #fff;
        font-weight: 600; }
.P1 { background: #dc2626; } .P2 { background: #d97706; } .P3 { background: #2563eb; }
.P4 { background: #6b7280; }
.note { background: #fef3c7; padding: .4rem .6rem; border-left: 4px solid #d97706; }
pre { white-space: pre-wrap; font-family: inherit; margin: .3rem 0 0; }
.item p { margin: .35rem 0; } .item ul { margin: .2rem 0 .4rem; }
.item { break-inside: avoid; }
@media print { body { margin: 0; max-width: none; } h2 { break-after: avoid; } }
"""


def _brief_html(brief: Brief) -> str:
    e = html.escape
    summary = "<br>".join(e(line.strip()) for line in brief.summary.strip().splitlines())
    timeline = "".join(f"<li>{e(entry)}</li>" for entry in brief.timeline)
    return (
        f"<p><strong>Verdict:</strong> {summary}</p>"
        f"<p><strong>Assets:</strong> {e(', '.join(brief.affected_assets))}</p>"
        f"<p><strong>Techniques:</strong> {e(', '.join(brief.techniques))}</p>"
        f"<p><strong>Timeline:</strong></p><ul>{timeline}</ul>"
        f"<p><strong>Next action:</strong> {e(brief.next_action)}</p>"
    )


def to_html(h: Handover) -> str:
    """The handover as a standalone HTML page with print CSS."""
    e = html.escape
    headers, values = _stats_rows(h)
    s = h.stats
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>Shift handover {e(h.batch.batch_id)}</title><style>{CSS}</style></head><body>",
        f"<h1>Shift handover: {e(h.batch.batch_id)}</h1>",
        f"<p class='meta'>{e(_window(h))} · analysts: {e(', '.join(s.analysts) or 'none yet')}</p>",
        "<h2>Shift at a glance</h2><table><tr>",
        "".join(f"<th>{e(x)}</th>" for x in headers),
        "</tr><tr>",
        "".join(f"<td>{e(x)}</td>" for x in values),
        "</tr></table>",
        "<p class='meta'>Tiers: "
        + " · ".join(f"{t} {c}" for t, c in s.tiers.items())
        + f". Re-decisions: {s.redecisions}.</p>",
        "<h2>Incidents for the next shift (rank order)</h2>",
    ]
    if not h.items:
        parts.append("<p><em>No approved, edited or escalated incidents yet.</em></p>")
    for item in h.items:
        d = item.decision
        heading = _heading(h, item).split("] ", 1)[1]
        parts.append(
            f"<div class='item'><h3>{item.rank}. <span class='tier {e(item.tier)}'>"
            f"{e(item.tier)}</span> {e(heading)}</h3>"
        )
        if d.action is DecisionAction.ESCALATE and d.notes:
            parts.append(f"<p class='note'><strong>Escalation note:</strong> {e(d.notes)}</p>")
        parts.append(_brief_html(item.brief) if item.brief else f"<pre>{e(item.brief_text)}</pre>")
        parts.append("</div>")
    parts.append("</body></html>")
    return "".join(parts)
