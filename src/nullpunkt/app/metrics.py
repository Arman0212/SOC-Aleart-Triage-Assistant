"""Shift and study-session measures, computed from stored decisions.

MTTT (mean time to triage) is the mean ``triage_seconds`` of each incident's *first* decision:
time from opening the incident to deciding it. Re-decisions are corrections; they are counted
separately and never averaged in. Queue browsing is not part of it, which is why study sessions
also report whole-session measures (Phase 7 compares against a spreadsheet baseline that
includes scanning time).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from statistics import mean

from nullpunkt.storage.repository import DecisionRecord, Repository


def first_decisions(decisions: list[DecisionRecord]) -> dict[str, DecisionRecord]:
    """incident_id -> its first decision (decisions are ordered oldest first)."""
    first: dict[str, DecisionRecord] = {}
    for d in decisions:
        first.setdefault(d.incident_id, d)
    return first


def latest_decisions(decisions: list[DecisionRecord]) -> dict[str, DecisionRecord]:
    return {d.incident_id: d for d in decisions}


def mttt_seconds(decisions: list[DecisionRecord]) -> float | None:
    firsts = first_decisions(decisions)
    return mean(d.triage_seconds for d in firsts.values()) if firsts else None


@dataclass(frozen=True)
class ShiftStats:
    alerts: int
    incidents: int
    reduction_ratio: float
    decided: int
    by_action: dict[str, int]  # latest decision per incident
    redecisions: int
    mttt_seconds: float | None
    tiers: dict[str, int]
    analysts: tuple[str, ...]

    @property
    def still_open(self) -> int:
        return self.incidents - self.decided


def shift_stats(repo: Repository, batch_id: str, scope: str | None = None) -> ShiftStats:
    """Stats for one scope: a study session, or (None) normal shift work outside sessions."""
    batch = repo.batch(batch_id)
    decisions = repo.scoped_decisions(batch_id, scope)
    latest = latest_decisions(decisions)
    tiers = Counter(row.tier for row in repo.queue(batch_id))
    return ShiftStats(
        alerts=batch.alert_count,
        incidents=batch.incident_count,
        reduction_ratio=batch.reduction_ratio,
        decided=len(latest),
        by_action=dict(Counter(d.action.value for d in latest.values())),
        redecisions=len(decisions) - len(latest),
        mttt_seconds=mttt_seconds(decisions),
        tiers={t: tiers.get(t, 0) for t in ("P1", "P2", "P3", "P4")},
        analysts=tuple(sorted({d.analyst for d in decisions})),
    )


@dataclass(frozen=True)
class SessionMetrics:
    session_id: str
    analyst: str
    batch_id: str
    running: bool
    duration_seconds: float  # start to end, or to now while running
    decisions: int  # every decision in the session, re-decisions included
    redecisions: int
    first_decision_mttt_seconds: float | None
    time_to_first_decision: dict[str, float]  # incident_id -> seconds from session start


def session_metrics(repo: Repository, session_id: str) -> SessionMetrics:
    """Whole-session measures for one study session. Decisions made outside any session
    (study_session NULL) are never included."""
    session = repo.session(session_id)
    decisions = repo.decisions(session.batch_id, session_id=session_id)
    end = session.ended_at or repo.now()
    firsts = first_decisions(decisions)
    return SessionMetrics(
        session_id=session.session_id,
        analyst=session.analyst,
        batch_id=session.batch_id,
        running=session.running,
        duration_seconds=(end - session.started_at).total_seconds(),
        decisions=len(decisions),
        redecisions=len(decisions) - len(firsts),
        first_decision_mttt_seconds=mttt_seconds(decisions),
        time_to_first_decision={
            iid: (d.decided_at - session.started_at).total_seconds() for iid, d in firsts.items()
        },
    )


def all_session_metrics(repo: Repository, batch_id: str | None = None) -> list[SessionMetrics]:
    return [session_metrics(repo, s.session_id) for s in repo.sessions(batch_id)]


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "–"
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"
