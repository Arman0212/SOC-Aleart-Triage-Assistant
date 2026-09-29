"""The shift database: prepared shifts, analyst decisions, study sessions and the audit log.

The app and the prepare-shift CLI use the ``Repository`` protocol; ``SQLiteRepository`` is the
implementation. Every write that matters is also appended to ``audit_log``.

Triage timing is kept in the database, not in the UI, so it survives Streamlit reruns, page
refreshes and second browser tabs:

- ``open_incident`` starts triage once: it inserts an opening only if the incident is undecided and
  this analyst has no open opening for it in the current study session (check and insert in one
  transaction). Viewing a decided incident never starts a timer.
- ``reopen_for_redecision`` starts a new opening on an already-decided incident; the UI calls it
  from its "Change decision" button.
- ``record_decision`` closes the opening: decided_at is now, triage_seconds = decided_at -
  opened_at.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from pydantic_settings import BaseSettings, SettingsConfigDict

from nullpunkt.core.config import PipelineConfig, StorageConfig
from nullpunkt.core.schema import Alert, Brief, Decision, DecisionAction, Incident
from nullpunkt.storage.db import connect, migrate

Clock = Callable[[], datetime]

STATUS_OF_ACTION = {
    DecisionAction.APPROVE: "approved",
    DecisionAction.EDIT: "approved",
    DecisionAction.DISMISS: "dismissed",
    DecisionAction.ESCALATE: "escalated",
}
MIN_NOTE_CHARS = 3


class DecisionError(ValueError):
    """A decision was refused (missing note, nothing opened, unknown incident, ...)."""


class StorageSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    db_path: str | None = None  # environment variable DB_PATH


def resolve_db_path(config: StorageConfig | None = None, explicit: str | Path | None = None) -> str:
    """--db beats DB_PATH (environment or .env), which beats pipeline.yaml."""
    if explicit:
        return str(explicit)
    env = StorageSettings().db_path
    return env or (config or StorageConfig()).db_path


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


@dataclass(frozen=True)
class BatchInfo:
    batch_id: str
    prepared_at: datetime
    source_dir: str
    alert_count: int
    incident_count: int
    first_alert_at: datetime
    last_alert_at: datetime
    timezone: str
    attack_version: str
    prompt_version: str | None
    model: str | None
    pipeline_seconds: float
    briefing_seconds: float | None

    @property
    def reduction_ratio(self) -> float:
        return self.alert_count / max(self.incident_count, 1)


@dataclass(frozen=True)
class QueueRow:
    incident_id: str
    rank: int
    tier: str
    risk: float
    status: str
    asset: str | None
    criticality: int
    tactics: tuple[str, ...]
    alert_count: int


@dataclass(frozen=True)
class DecisionRecord:
    id: int
    batch_id: str
    incident_id: str
    action: DecisionAction
    analyst: str
    opened_at: datetime
    decided_at: datetime
    triage_seconds: float
    edited_brief: str | None
    notes: str | None
    study_session: str | None


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    analyst: str
    batch_id: str
    started_at: datetime
    ended_at: datetime | None

    @property
    def running(self) -> bool:
        return self.ended_at is None


@dataclass(frozen=True)
class BriefRecord:
    brief: Brief
    context: dict
    meta: dict  # generated_by, path, attempts, latency_seconds, prompt_version, model, ...


@dataclass(frozen=True)
class IncidentView:
    """Everything the incident page shows."""

    rank: int
    tier: str
    status: str
    incident: Incident
    detail: dict  # scoring detail: asset, peak_alert, evidence, tactics, routine_only
    alerts: list[Alert]
    links: list[dict]
    brief: BriefRecord | None
    decisions: list[DecisionRecord]  # oldest first

    @property
    def latest_decision(self) -> DecisionRecord | None:
        return self.decisions[-1] if self.decisions else None


class Repository(Protocol):
    def save_shift(
        self,
        result: object,
        config: PipelineConfig,
        batch_id: str,
        source_dir: str,
        replace: bool = False,
    ) -> BatchInfo: ...

    def batches(self) -> list[BatchInfo]: ...
    def batch(self, batch_id: str) -> BatchInfo: ...
    def queue(
        self,
        batch_id: str,
        tiers: Iterable[str] | None = None,
        statuses: Iterable[str] | None = None,
    ) -> list[QueueRow]: ...
    def incident(self, batch_id: str, incident_id: str) -> IncidentView: ...
    def open_incident(
        self, batch_id: str, incident_id: str, analyst: str, session_id: str | None = None
    ) -> datetime | None: ...
    def reopen_for_redecision(
        self, batch_id: str, incident_id: str, analyst: str, session_id: str | None = None
    ) -> datetime: ...
    def current_opening(
        self, batch_id: str, incident_id: str, analyst: str, session_id: str | None = None
    ) -> datetime | None: ...
    def record_decision(
        self,
        batch_id: str,
        incident_id: str,
        analyst: str,
        action: DecisionAction | str,
        *,
        edited_brief: str | None = None,
        notes: str | None = None,
        session_id: str | None = None,
    ) -> DecisionRecord: ...
    def decisions(
        self, batch_id: str | None = None, session_id: str | None = None
    ) -> list[DecisionRecord]: ...
    def start_session(self, analyst: str, batch_id: str) -> SessionRecord: ...
    def end_session(self, session_id: str) -> SessionRecord: ...
    def running_session(self, analyst: str) -> SessionRecord | None: ...
    def session(self, session_id: str) -> SessionRecord: ...
    def sessions(self, batch_id: str | None = None) -> list[SessionRecord]: ...
    def audit(self, batch_id: str | None = None) -> list[dict]: ...
    def brief_sources(self, batch_id: str) -> dict[str, int]: ...
    def log(
        self, actor: str, event: str, batch_id: str | None = None,
        incident_id: str | None = None, payload: dict | None = None,
    ) -> None: ...  # fmt: skip
    def now(self) -> datetime: ...


class SQLiteRepository:
    def __init__(self, path: str | Path, clock: Clock | None = None) -> None:
        self.path = str(path)
        self.conn = connect(self.path)
        migrate(self.conn)
        self._clock = clock or (lambda: datetime.now(UTC))

    # -- basics --------------------------------------------------------------------------------

    def now(self) -> datetime:
        return self._clock().astimezone(UTC)

    def close(self) -> None:
        self.conn.close()

    def _tx(self):
        return _Transaction(self.conn)

    def log(
        self,
        actor: str,
        event: str,
        batch_id: str | None = None,
        incident_id: str | None = None,
        payload: dict | None = None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO audit_log (at, actor, event, batch_id, incident_id, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (_iso(self.now()), actor, event, batch_id, incident_id, json.dumps(payload or {})),
        )

    def audit(self, batch_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM audit_log"
        args: tuple = ()
        if batch_id:
            sql, args = sql + " WHERE batch_id = ?", (batch_id,)
        rows = self.conn.execute(sql + " ORDER BY id", args).fetchall()
        return [{**dict(r), "payload": json.loads(r["payload_json"])} for r in rows]

    # -- prepared shifts -----------------------------------------------------------------------

    def save_shift(
        self,
        result,
        config: PipelineConfig,
        batch_id: str,
        source_dir: str,
        replace: bool = False,
    ) -> BatchInfo:
        """Store a ``PipelineResult``. Re-preparing a batch needs ``replace``; its decisions,
        sessions and audit log are kept, and incident statuses are re-derived from them."""
        exists = self.conn.execute(
            "SELECT 1 FROM batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        if exists and not replace:
            raise ValueError(f"batch {batch_id!r} is already prepared; use replace to redo it")
        alerts = sorted(result.alerts, key=lambda a: (a.timestamp, a.alert_id))
        briefing = result.briefing
        with self._tx():
            if exists:
                for table in ("briefs", "hubs", "links", "incidents", "alerts"):
                    self.conn.execute(f"DELETE FROM {table} WHERE batch_id = ?", (batch_id,))
                self.conn.execute("DELETE FROM batches WHERE batch_id = ?", (batch_id,))
            self.conn.execute(
                "INSERT INTO batches VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    batch_id,
                    _iso(self.now()),
                    source_dir,
                    len(alerts),
                    len(result.ranked),
                    _iso(alerts[0].timestamp),
                    _iso(alerts[-1].timestamp),
                    config.site.timezone,
                    result.mapping.attack_version,
                    briefing.prompt_version if briefing else None,
                    briefing.model if briefing else None,
                    sum(result.timings.values()),
                    briefing.seconds if briefing else None,
                    config.model_dump_json(),
                ),
            )
            incident_of = result.correlation.incident_of
            self.conn.executemany(
                "INSERT INTO alerts VALUES (?,?,?,?,?)",
                [
                    (batch_id, a.alert_id, incident_of[a.alert_id], _iso(a.timestamp),
                     a.model_dump_json())
                    for a in alerts
                ],
            )  # fmt: skip
            self.conn.executemany(
                "INSERT INTO incidents (batch_id, incident_id, rank, tier, risk, asset, "
                "criticality, tactics_json, alert_count, first_seen, last_seen, incident_json, "
                "detail_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [self._incident_row(batch_id, r) for r in result.ranked],
            )
            self.conn.executemany(
                "INSERT INTO links (batch_id, incident_id, alert_id, linked_to, reason, entity, "
                "gap_seconds, rule_name) VALUES (?,?,?,?,?,?,?,?)",
                [
                    (batch_id, iid, link.alert_id, link.linked_to, link.reason, link.entity,
                     link.gap_seconds, link.rule_name)
                    for iid, links in result.correlation.links.items()
                    for link in links
                ],
            )  # fmt: skip
            self.conn.executemany(
                "INSERT INTO hubs VALUES (?,?,?,?,?,?,?)",
                [
                    (batch_id, h.entity, h.alerts, h.share, h.distinct_users, h.fanout,
                     json.dumps(list(h.reasons)))
                    for h in result.correlation.hubs
                ],
            )  # fmt: skip
            if briefing is not None:
                self.conn.executemany(
                    "INSERT INTO briefs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [
                        self._brief_row(batch_id, o, result.brief_contexts[iid])
                        for iid, o in briefing.outcomes.items()
                    ],
                )
            for row in self.conn.execute(
                "SELECT DISTINCT incident_id FROM decisions WHERE batch_id = ?", (batch_id,)
            ).fetchall():
                self._refresh_status(batch_id, row["incident_id"])
            self.log(
                "prepare-shift",
                "shift_replaced" if exists else "shift_prepared",
                batch_id,
                payload={
                    "alerts": len(alerts),
                    "incidents": len(result.ranked),
                    "briefs": briefing.paths() if briefing else None,
                    "source_dir": source_dir,
                },
            )
        return self.batch(batch_id)

    @staticmethod
    def _incident_row(batch_id: str, r) -> tuple:
        inc: Incident = r.incident
        detail = r.detail
        detail_json = json.dumps(
            {
                "asset": detail.asset,
                "peak_alert": detail.peak_alert,
                "evidence": list(detail.evidence),
                "tactics": list(detail.tactics),
                "routine_only": detail.routine_only,
            }
        )
        return (
            batch_id,
            inc.incident_id,
            r.rank,
            r.tier,
            inc.score.risk_score,
            detail.asset,
            inc.score.asset_criticality,
            json.dumps(list(detail.tactics)),
            len(inc.alert_ids),
            _iso(inc.first_seen),
            _iso(inc.last_seen),
            inc.model_dump_json(),
            detail_json,
        )

    @staticmethod
    def _brief_row(batch_id: str, o, ctx) -> tuple:
        return (
            batch_id,
            o.incident_id,
            o.brief.model_dump_json(),
            json.dumps(ctx.data, ensure_ascii=False),
            o.generated_by.value,
            int(o.brief.validated),
            o.brief.confidence.value,
            o.path,
            o.attempts,
            o.latency_seconds,
            o.prompt_version,
            o.model,
            int(o.cache_hit),
            o.fallback_reason,
            o.model_confidence,
            json.dumps(o.validation_errors),
        )

    def batches(self) -> list[BatchInfo]:
        rows = self.conn.execute("SELECT * FROM batches ORDER BY prepared_at DESC").fetchall()
        return [self._batch(r) for r in rows]

    def batch(self, batch_id: str) -> BatchInfo:
        row = self.conn.execute("SELECT * FROM batches WHERE batch_id = ?", (batch_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown batch {batch_id!r}")
        return self._batch(row)

    @staticmethod
    def _batch(r: sqlite3.Row) -> BatchInfo:
        return BatchInfo(
            batch_id=r["batch_id"],
            prepared_at=_utc(r["prepared_at"]),
            source_dir=r["source_dir"],
            alert_count=r["alert_count"],
            incident_count=r["incident_count"],
            first_alert_at=_utc(r["first_alert_at"]),
            last_alert_at=_utc(r["last_alert_at"]),
            timezone=r["timezone"],
            attack_version=r["attack_version"],
            prompt_version=r["prompt_version"],
            model=r["model"],
            pipeline_seconds=r["pipeline_seconds"],
            briefing_seconds=r["briefing_seconds"],
        )

    def brief_sources(self, batch_id: str) -> dict[str, int]:
        """generated_by -> number of briefs (llm / template) in the batch."""
        rows = self.conn.execute(
            "SELECT generated_by, COUNT(*) AS n FROM briefs WHERE batch_id = ? GROUP BY 1",
            (batch_id,),
        ).fetchall()
        return {r["generated_by"]: r["n"] for r in rows}

    # -- reading incidents ---------------------------------------------------------------------

    def queue(
        self,
        batch_id: str,
        tiers: Iterable[str] | None = None,
        statuses: Iterable[str] | None = None,
    ) -> list[QueueRow]:
        sql = (
            "SELECT incident_id, rank, tier, risk, status, asset, criticality, tactics_json, "
            "alert_count FROM incidents WHERE batch_id = ?"
        )
        args: list = [batch_id]
        for column, values in (("tier", tiers), ("status", statuses)):
            if values is not None:
                values = list(values)
                sql += f" AND {column} IN ({','.join('?' * len(values)) or 'NULL'})"
                args += values
        rows = self.conn.execute(sql + " ORDER BY rank", args).fetchall()
        return [
            QueueRow(
                r["incident_id"], r["rank"], r["tier"], r["risk"], r["status"], r["asset"],
                r["criticality"], tuple(json.loads(r["tactics_json"])), r["alert_count"],
            )
            for r in rows
        ]  # fmt: skip

    def incident(self, batch_id: str, incident_id: str) -> IncidentView:
        row = self.conn.execute(
            "SELECT * FROM incidents WHERE batch_id = ? AND incident_id = ?",
            (batch_id, incident_id),
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown incident {incident_id!r} in batch {batch_id!r}")
        alerts = [
            Alert.model_validate_json(r["alert_json"])
            for r in self.conn.execute(
                "SELECT alert_json FROM alerts WHERE batch_id = ? AND incident_id = ? "
                "ORDER BY timestamp, alert_id",
                (batch_id, incident_id),
            )
        ]
        links = [
            dict(r)
            for r in self.conn.execute(
                "SELECT alert_id, linked_to, reason, entity, gap_seconds, rule_name FROM links "
                "WHERE batch_id = ? AND incident_id = ? ORDER BY alert_id, linked_to",
                (batch_id, incident_id),
            )
        ]
        b = self.conn.execute(
            "SELECT * FROM briefs WHERE batch_id = ? AND incident_id = ?", (batch_id, incident_id)
        ).fetchone()
        brief = None
        if b is not None:
            meta = {
                k: b[k]
                for k in (
                    "generated_by", "validated", "confidence", "path", "attempts",
                    "latency_seconds", "prompt_version", "model", "cache_hit",
                    "fallback_reason", "model_confidence",
                )
            }  # fmt: skip
            meta["validation_errors"] = json.loads(b["validation_errors_json"])
            brief = BriefRecord(
                Brief.model_validate_json(b["brief_json"]), json.loads(b["context_json"]), meta
            )
        return IncidentView(
            rank=row["rank"],
            tier=row["tier"],
            status=row["status"],
            incident=Incident.model_validate_json(row["incident_json"]),
            detail=json.loads(row["detail_json"]),
            alerts=alerts,
            links=links,
            brief=brief,
            decisions=self._decisions(
                "WHERE batch_id = ? AND incident_id = ?", (batch_id, incident_id)
            ),
        )

    # -- triage timing and decisions -----------------------------------------------------------

    def current_opening(
        self, batch_id: str, incident_id: str, analyst: str, session_id: str | None = None
    ) -> datetime | None:
        row = self.conn.execute(
            "SELECT opened_at FROM openings WHERE batch_id = ? AND incident_id = ? AND analyst = ? "
            "AND study_session IS ? AND decision_id IS NULL ORDER BY id DESC LIMIT 1",
            (batch_id, incident_id, analyst, session_id),
        ).fetchone()
        return _utc(row["opened_at"]) if row else None

    def _insert_opening(
        self, batch_id: str, incident_id: str, analyst: str, session_id: str | None, event: str
    ) -> datetime:
        opened = self.now()
        self.conn.execute(
            "INSERT INTO openings (batch_id, incident_id, analyst, study_session, opened_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (batch_id, incident_id, analyst, session_id, _iso(opened)),
        )
        self.log(analyst, event, batch_id, incident_id, {"study_session": session_id})
        return opened

    def open_incident(
        self, batch_id: str, incident_id: str, analyst: str, session_id: str | None = None
    ) -> datetime | None:
        """Start triage the first time an undecided incident is opened; later calls (reruns,
        refreshes, other tabs) return the same opened_at. Returns None for decided incidents."""
        self._require_incident(batch_id, incident_id)
        with self._tx():
            existing = self.current_opening(batch_id, incident_id, analyst, session_id)
            if existing is not None:
                return existing
            decided = self.conn.execute(
                "SELECT 1 FROM decisions WHERE batch_id = ? AND incident_id = ? LIMIT 1",
                (batch_id, incident_id),
            ).fetchone()
            if decided:
                return None
            return self._insert_opening(
                batch_id, incident_id, analyst, session_id, "incident_opened"
            )

    def reopen_for_redecision(
        self, batch_id: str, incident_id: str, analyst: str, session_id: str | None = None
    ) -> datetime:
        self._require_incident(batch_id, incident_id)
        with self._tx():
            existing = self.current_opening(batch_id, incident_id, analyst, session_id)
            if existing is not None:
                return existing
            return self._insert_opening(
                batch_id, incident_id, analyst, session_id, "incident_reopened"
            )

    def record_decision(
        self,
        batch_id: str,
        incident_id: str,
        analyst: str,
        action: DecisionAction | str,
        *,
        edited_brief: str | None = None,
        notes: str | None = None,
        session_id: str | None = None,
    ) -> DecisionRecord:
        action = DecisionAction(action)
        analyst = analyst.strip()
        if not analyst:
            raise DecisionError("enter your analyst name first")
        edited_brief = (edited_brief or "").strip() or None
        notes = (notes or "").strip() or None
        if action is DecisionAction.EDIT and not edited_brief:
            raise DecisionError("an edit needs the edited brief text")
        if action is DecisionAction.DISMISS and len(notes or "") < MIN_NOTE_CHARS:
            raise DecisionError("dismissing as a false positive needs a reason")
        if action is DecisionAction.ESCALATE and len(notes or "") < MIN_NOTE_CHARS:
            raise DecisionError("escalating needs a note")
        if session_id is not None:
            session = self.session(session_id)
            if not session.running:
                raise DecisionError(f"study session {session_id} has ended")
        with self._tx():
            row = self.conn.execute(
                "SELECT id, opened_at FROM openings WHERE batch_id = ? AND incident_id = ? "
                "AND analyst = ? AND study_session IS ? AND decision_id IS NULL "
                "ORDER BY id DESC LIMIT 1",
                (batch_id, incident_id, analyst, session_id),
            ).fetchone()
            if row is None:
                raise DecisionError("open the incident before deciding")
            opened_at, decided_at = _utc(row["opened_at"]), self.now()
            decision = Decision(
                incident_id=incident_id,
                action=action,
                analyst=analyst,
                opened_at=opened_at,
                decided_at=decided_at,
                edited_brief=edited_brief,
                notes=notes,
            )
            previous = self.conn.execute(
                "SELECT COUNT(*) FROM decisions WHERE batch_id = ? AND incident_id = ?",
                (batch_id, incident_id),
            ).fetchone()[0]
            cur = self.conn.execute(
                "INSERT INTO decisions (batch_id, incident_id, action, analyst, opened_at, "
                "decided_at, triage_seconds, edited_brief, notes, study_session, decision_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (batch_id, incident_id, action.value, analyst, _iso(opened_at), _iso(decided_at),
                 decision.triage_seconds, edited_brief, notes, session_id,
                 decision.model_dump_json()),
            )  # fmt: skip
            decision_id = cur.lastrowid
            self.conn.execute(
                "UPDATE openings SET decision_id = ? WHERE id = ?", (decision_id, row["id"])
            )
            self._refresh_status(batch_id, incident_id)
            self.log(
                analyst,
                "decision_changed" if previous else "decision_recorded",
                batch_id,
                incident_id,
                {
                    "decision_id": decision_id,
                    "action": action.value,
                    "triage_seconds": decision.triage_seconds,
                    "study_session": session_id,
                },
            )
        return self._decisions("WHERE id = ?", (decision_id,))[0]

    def _refresh_status(self, batch_id: str, incident_id: str) -> None:
        """Latest decision wins (by decided_at, then id)."""
        row = self.conn.execute(
            "SELECT action FROM decisions WHERE batch_id = ? AND incident_id = ? "
            "ORDER BY decided_at DESC, id DESC LIMIT 1",
            (batch_id, incident_id),
        ).fetchone()
        status = STATUS_OF_ACTION[DecisionAction(row["action"])] if row else "open"
        self.conn.execute(
            "UPDATE incidents SET status = ? WHERE batch_id = ? AND incident_id = ?",
            (status, batch_id, incident_id),
        )

    def _require_incident(self, batch_id: str, incident_id: str) -> None:
        found = self.conn.execute(
            "SELECT 1 FROM incidents WHERE batch_id = ? AND incident_id = ?",
            (batch_id, incident_id),
        ).fetchone()
        if not found:
            raise DecisionError(f"unknown incident {incident_id!r} in batch {batch_id!r}")

    def decisions(
        self, batch_id: str | None = None, session_id: str | None = None
    ) -> list[DecisionRecord]:
        clauses, args = [], []
        if batch_id is not None:
            clauses.append("batch_id = ?")
            args.append(batch_id)
        if session_id is not None:
            clauses.append("study_session = ?")
            args.append(session_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self._decisions(where, tuple(args))

    def _decisions(self, where: str, args: tuple) -> list[DecisionRecord]:
        rows = self.conn.execute(
            f"SELECT * FROM decisions {where} ORDER BY decided_at, id", args
        ).fetchall()
        return [
            DecisionRecord(
                id=r["id"], batch_id=r["batch_id"], incident_id=r["incident_id"],
                action=DecisionAction(r["action"]), analyst=r["analyst"],
                opened_at=_utc(r["opened_at"]), decided_at=_utc(r["decided_at"]),
                triage_seconds=r["triage_seconds"], edited_brief=r["edited_brief"],
                notes=r["notes"], study_session=r["study_session"],
            )
            for r in rows
        ]  # fmt: skip

    # -- study sessions ------------------------------------------------------------------------

    def start_session(self, analyst: str, batch_id: str) -> SessionRecord:
        analyst = analyst.strip()
        if not analyst:
            raise DecisionError("enter your analyst name first")
        self.batch(batch_id)
        with self._tx():
            if self.running_session(analyst) is not None:
                raise DecisionError(f"{analyst} already has a running study session")
            n = self.conn.execute("SELECT COUNT(*) FROM study_sessions").fetchone()[0] + 1
            session_id = f"S{n:03d}"
            started = self.now()
            self.conn.execute(
                "INSERT INTO study_sessions (session_id, analyst, batch_id, started_at) "
                "VALUES (?, ?, ?, ?)",
                (session_id, analyst, batch_id, _iso(started)),
            )
            self.log(analyst, "session_started", batch_id, payload={"session_id": session_id})
        return self.session(session_id)

    def end_session(self, session_id: str) -> SessionRecord:
        session = self.session(session_id)
        if not session.running:
            return session
        with self._tx():
            self.conn.execute(
                "UPDATE study_sessions SET ended_at = ? WHERE session_id = ?",
                (_iso(self.now()), session_id),
            )
            self.log(
                session.analyst,
                "session_ended",
                session.batch_id,
                payload={"session_id": session_id},
            )
        return self.session(session_id)

    def running_session(self, analyst: str) -> SessionRecord | None:
        row = self.conn.execute(
            "SELECT * FROM study_sessions WHERE analyst = ? AND ended_at IS NULL", (analyst,)
        ).fetchone()
        return self._session(row) if row else None

    def session(self, session_id: str) -> SessionRecord:
        row = self.conn.execute(
            "SELECT * FROM study_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown study session {session_id!r}")
        return self._session(row)

    def sessions(self, batch_id: str | None = None) -> list[SessionRecord]:
        sql, args = "SELECT * FROM study_sessions", ()
        if batch_id:
            sql, args = sql + " WHERE batch_id = ?", (batch_id,)
        return [self._session(r) for r in self.conn.execute(sql + " ORDER BY started_at", args)]

    @staticmethod
    def _session(r: sqlite3.Row) -> SessionRecord:
        return SessionRecord(
            r["session_id"], r["analyst"], r["batch_id"], _utc(r["started_at"]),
            _utc(r["ended_at"]) if r["ended_at"] else None,
        )  # fmt: skip


class _Transaction:
    """BEGIN IMMEDIATE ... COMMIT/ROLLBACK; nested uses join the outer transaction."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.outer = False

    def __enter__(self):
        if not self.conn.in_transaction:
            self.conn.execute("BEGIN IMMEDIATE")
            self.outer = True
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.outer:
            self.conn.execute("ROLLBACK" if exc_type else "COMMIT")
        return False
