import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from nullpunkt.app.metrics import session_metrics, shift_stats
from nullpunkt.app.report import build_handover, to_html, to_markdown
from nullpunkt.briefing.llm import FakeClient, LLMError
from nullpunkt.core.config import PipelineConfig, StorageConfig
from nullpunkt.core.schema import DecisionAction
from nullpunkt.evaluation.sweep_correlation import make_batch
from nullpunkt.pipeline import process
from nullpunkt.storage.db import Migration, _statements, connect, current_version, migrate
from nullpunkt.storage.repository import DecisionError, SQLiteRepository, resolve_db_path

T0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self, start: datetime = T0) -> None:
        self.t = start

    def __call__(self) -> datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)


@pytest.fixture(scope="module")
def result():
    batch = make_batch(42)
    down = FakeClient([LLMError("unreachable", "no model in tests")])
    return process(batch.alerts, batch.assets, PipelineConfig(), briefs=True, client=down)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def repo(tmp_path, clock, result):
    r = SQLiteRepository(tmp_path / "shift.db", clock=clock)
    r.save_shift(result, PipelineConfig(), "batch-042", "data/generated/batch-042")
    yield r
    r.close()


B = "batch-042"
TOP = "INC-0055"  # rank 1 (SCN-01)


# --- migrations --------------------------------------------------------------------------------


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "m.db")
    yield c
    c.close()


def test_migrations_apply_once(conn):
    assert migrate(conn) == [1, 2]
    assert migrate(conn) == []
    assert current_version(conn) == 2
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"batches", "incidents", "decisions", "audit_log", "study_sessions"} <= tables


def test_upgrade_applies_only_new_migrations(conn):
    migrate(conn)
    extra = Migration(3, "003_add_note.sql", "ALTER TABLE batches ADD COLUMN note TEXT;")
    from nullpunkt.storage.db import bundled_migrations

    assert migrate(conn, [*bundled_migrations(), extra]) == [3]
    assert current_version(conn) == 3
    columns = [r[1] for r in conn.execute("PRAGMA table_info(batches)")]
    assert "note" in columns


def test_failed_migration_rolls_back(conn):
    migrate(conn)
    bad = Migration(3, "003_bad.sql", "CREATE TABLE t (x INT);\nNOT SQL AT ALL;")
    from nullpunkt.storage.db import bundled_migrations

    with pytest.raises(sqlite3.OperationalError):
        migrate(conn, [*bundled_migrations(), bad])
    assert current_version(conn) == 2
    assert "t" not in {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}


def test_phase6_database_upgrades_in_place(tmp_path):
    from nullpunkt.storage.db import bundled_migrations

    conn = connect(tmp_path / "old.db")
    migrate(conn, bundled_migrations()[:1])  # a Phase 6 database
    conn.execute(
        "INSERT INTO batches VALUES "
        "('b', 't', 's', 1, 1, 't', 't', 'UTC', '19.2', NULL, NULL, 0, NULL, '{}')"
    )
    conn.execute(
        "INSERT INTO study_sessions (session_id, analyst, batch_id, started_at) "
        "VALUES ('S001', 'jane', 'b', '2026-10-01T09:00:00+00:00')"
    )
    conn.close()
    repo = SQLiteRepository(tmp_path / "old.db")  # opening applies migration 002
    s = repo.session("S001")
    assert (s.purpose, s.arm, s.time_box_seconds) == ("study", None, None)
    assert current_version(repo.conn) == 2
    repo.close()


def test_statement_splitter_keeps_trigger_bodies_whole():
    sql = (
        "-- c\nCREATE TABLE a (x);\nCREATE TRIGGER t BEFORE DELETE ON a\nBEGIN\n  SELECT 1;\nEND;\n"
    )
    parts = _statements(sql)
    assert len(parts) == 2 and parts[1].startswith("CREATE TRIGGER") and parts[1].endswith("END;")


def test_db_path_resolution(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no .env
    monkeypatch.delenv("DB_PATH", raising=False)
    assert resolve_db_path(StorageConfig(db_path="from/yaml.db")) == "from/yaml.db"
    monkeypatch.setenv("DB_PATH", "from/env.db")
    assert resolve_db_path(StorageConfig(db_path="from/yaml.db")) == "from/env.db"
    assert resolve_db_path(StorageConfig(), "explicit.db") == "explicit.db"


# --- saving and reading a shift ----------------------------------------------------------------


def test_shift_round_trip(repo, result):
    batch = repo.batch(B)
    assert (batch.alert_count, batch.incident_count) == (3000, 65)
    assert batch.timezone == "Asia/Kolkata" and batch.attack_version == "19.2"
    queue = repo.queue(B)
    assert [q.incident_id for q in queue] == [r.incident.incident_id for r in result.ranked]
    assert [q.tier for q in queue] == [r.tier for r in result.ranked]
    assert queue[0].tactics[0] == "initial-access" and queue[0].asset == "FINDB01"
    view = repo.incident(B, TOP)
    ranked = result.ranked[0]
    assert view.incident == ranked.incident
    assert view.rank == 1 and view.tier == "P1" and view.status == "open"
    assert [a.alert_id for a in view.alerts] == ranked.incident.alert_ids
    assert len(view.links) == len(ranked.incident.alert_ids) - 1
    assert view.brief is not None and view.brief.brief == ranked.incident.brief
    assert (
        view.brief.meta["generated_by"] == "template" and view.brief.context["incident_id"] == TOP
    )
    assert view.detail["asset"] == "FINDB01"
    assert repo.brief_sources(B) == {"template": 10}
    assert repo.incident(B, result.ranked[20].incident.incident_id).brief is None


def test_queue_filters(repo):
    assert {q.tier for q in repo.queue(B, tiers=["P1"])} == {"P1"}
    assert len(repo.queue(B, tiers=["P1"])) == 4
    assert repo.queue(B, statuses=["approved"]) == []
    assert repo.queue(B, tiers=[]) == []


def test_preparing_twice_needs_replace(repo, result):
    with pytest.raises(ValueError, match="already prepared"):
        repo.save_shift(result, PipelineConfig(), B, "x")


def test_replace_keeps_decisions_and_statuses(repo, result):
    repo.open_incident(B, TOP, "jane")
    repo.record_decision(B, TOP, "jane", "escalate", notes="to IR lead")
    repo.save_shift(result, PipelineConfig(), B, "again", replace=True)
    assert repo.incident(B, TOP).status == "escalated"
    assert len(repo.decisions(B)) == 1
    assert [e["event"] for e in repo.audit(B)][-1] == "shift_replaced"


def test_unknown_batch_and_incident(repo):
    with pytest.raises(KeyError):
        repo.batch("nope")
    with pytest.raises(KeyError):
        repo.incident(B, "INC-9999")
    with pytest.raises(DecisionError):
        repo.open_incident(B, "INC-9999", "jane")


# --- audit log ---------------------------------------------------------------------------------


def test_audit_log_is_append_only(repo):
    assert repo.audit(B)[0]["event"] == "shift_prepared"
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        repo.conn.execute("UPDATE audit_log SET event = 'x'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        repo.conn.execute("DELETE FROM audit_log")


# --- triage timing and decisions ---------------------------------------------------------------


def test_opening_is_idempotent_across_reruns(repo, clock):
    first = repo.open_incident(B, TOP, "jane")
    clock.advance(30)
    assert repo.open_incident(B, TOP, "jane") == first  # rerun
    clock.advance(30)
    assert repo.open_incident(B, TOP, "jane") == first  # refresh / second tab
    assert first == T0
    opened = [e for e in repo.audit(B) if e["event"] == "incident_opened"]
    assert len(opened) == 1


def test_each_analyst_has_their_own_timer(repo, clock):
    jane = repo.open_incident(B, TOP, "jane")
    clock.advance(10)
    bob = repo.open_incident(B, TOP, "bob")
    assert (bob - jane).total_seconds() == 10


def test_decision_timing(repo, clock):
    repo.open_incident(B, TOP, "jane")
    clock.advance(95.5)
    d = repo.record_decision(B, TOP, "jane", DecisionAction.APPROVE)
    assert d.opened_at == T0 and d.decided_at == T0 + timedelta(seconds=95.5)
    assert d.triage_seconds == 95.5
    assert repo.incident(B, TOP).status == "approved"
    assert repo.current_opening(B, TOP, "jane") is None  # the opening was closed


def test_viewing_a_decided_incident_starts_no_timer(repo, clock):
    repo.open_incident(B, TOP, "jane")
    repo.record_decision(B, TOP, "jane", "approve")
    clock.advance(60)
    assert repo.open_incident(B, TOP, "jane") is None
    assert repo.open_incident(B, TOP, "bob") is None
    with pytest.raises(DecisionError, match="open the incident"):
        repo.record_decision(B, TOP, "bob", "dismiss", notes="looks benign")


@pytest.mark.parametrize(
    ("action", "kwargs", "status"),
    [
        ("approve", {}, "approved"),
        ("edit", {"edited_brief": "My own words."}, "approved"),
        ("dismiss", {"notes": "known pentest"}, "dismissed"),
        ("escalate", {"notes": "call the IR lead"}, "escalated"),
    ],
)
def test_each_decision_type(repo, action, kwargs, status):
    repo.open_incident(B, TOP, "jane")
    d = repo.record_decision(B, TOP, "jane", action, **kwargs)
    assert d.action.value == action
    assert repo.incident(B, TOP).status == status
    if action == "edit":
        assert d.edited_brief == "My own words."


@pytest.mark.parametrize(
    ("action", "kwargs", "message"),
    [
        ("edit", {"edited_brief": "   "}, "edited brief"),
        ("dismiss", {}, "needs a reason"),
        ("dismiss", {"notes": "no"}, "needs a reason"),
        ("escalate", {"notes": ""}, "needs a note"),
    ],
)
def test_incomplete_decisions_are_refused_and_nothing_is_saved(repo, action, kwargs, message):
    repo.open_incident(B, TOP, "jane")
    with pytest.raises(DecisionError, match=message):
        repo.record_decision(B, TOP, "jane", action, **kwargs)
    assert repo.decisions(B) == []
    assert repo.current_opening(B, TOP, "jane") is not None  # still open


def test_analyst_name_required(repo):
    with pytest.raises(DecisionError, match="analyst name"):
        repo.record_decision(B, TOP, "  ", "approve")


def test_redecision_latest_wins_and_is_audited(repo, clock):
    repo.open_incident(B, TOP, "jane")
    clock.advance(40)
    repo.record_decision(B, TOP, "jane", "approve")
    clock.advance(300)
    reopened = repo.reopen_for_redecision(B, TOP, "bob")
    clock.advance(20)
    second = repo.record_decision(B, TOP, "bob", "escalate", notes="needs IR after all")
    assert second.opened_at == reopened and second.triage_seconds == 20
    assert repo.incident(B, TOP).status == "escalated"
    view = repo.incident(B, TOP)
    assert [d.action.value for d in view.decisions] == ["approve", "escalate"]
    assert view.latest_decision.analyst == "bob"
    events = [e["event"] for e in repo.audit(B)]
    assert events[-3:] == ["decision_recorded", "incident_reopened", "decision_changed"]
    assert events.count("decision_changed") == 1


# --- study sessions ----------------------------------------------------------------------------


def test_session_lifecycle(repo, clock):
    s = repo.start_session("jane", B)
    assert s.running and s.session_id == "S001" and s.started_at == T0
    with pytest.raises(DecisionError, match="already has a running"):
        repo.start_session("jane", B)
    clock.advance(600)
    ended = repo.end_session(s.session_id)
    assert not ended.running and ended.ended_at == T0 + timedelta(seconds=600)
    assert repo.start_session("jane", B).session_id == "S002"
    events = [e["event"] for e in repo.audit(B)]
    assert events.count("session_started") == 2 and events.count("session_ended") == 1


def test_decisions_in_an_ended_session_are_refused(repo):
    s = repo.start_session("jane", B)
    repo.open_incident(B, TOP, "jane", s.session_id)
    repo.end_session(s.session_id)
    with pytest.raises(DecisionError, match="has ended"):
        repo.record_decision(B, TOP, "jane", "approve", session_id=s.session_id)


def test_session_metrics(repo, clock):
    ids = [q.incident_id for q in repo.queue(B)[:3]]
    # Outside any session: never counted.
    repo.open_incident(B, ids[2], "jane")
    repo.record_decision(B, ids[2], "jane", "approve")

    s = repo.start_session("jane", B)
    clock.advance(120)  # scanning the queue
    repo.open_incident(B, ids[0], "jane", s.session_id)
    clock.advance(60)
    repo.record_decision(B, ids[0], "jane", "approve", session_id=s.session_id)  # t=180
    repo.open_incident(B, ids[1], "jane", s.session_id)
    clock.advance(90)
    repo.record_decision(B, ids[1], "jane", "dismiss", notes="benign", session_id=s.session_id)
    clock.advance(10)
    repo.reopen_for_redecision(B, ids[0], "jane", s.session_id)
    clock.advance(30)
    repo.record_decision(
        B, ids[0], "jane", "escalate", notes="changed my mind", session_id=s.session_id
    )  # noqa: E501
    clock.advance(50)

    m = session_metrics(repo, s.session_id)
    assert m.running and m.duration_seconds == 360  # still running: up to now
    assert m.decisions == 3 and m.redecisions == 1
    assert m.first_decision_mttt_seconds == (60 + 90) / 2  # re-decision not averaged in
    assert m.time_to_first_decision == {ids[0]: 180, ids[1]: 270}
    repo.end_session(s.session_id)
    clock.advance(999)
    assert session_metrics(repo, s.session_id).duration_seconds == 360  # ended: fixed


def test_shift_stats(repo, clock):
    ids = [q.incident_id for q in repo.queue(B)[:2]]
    repo.open_incident(B, ids[0], "jane")
    clock.advance(30)
    repo.record_decision(B, ids[0], "jane", "approve")
    repo.open_incident(B, ids[1], "bob")
    clock.advance(90)
    repo.record_decision(B, ids[1], "bob", "dismiss", notes="scanner")
    s = shift_stats(repo, B)
    assert (s.alerts, s.incidents, s.decided, s.still_open) == (3000, 65, 2, 63)
    assert s.by_action == {"approve": 1, "dismiss": 1}
    assert s.mttt_seconds == 60 and s.analysts == ("bob", "jane")
    assert s.tiers == {"P1": 4, "P2": 7, "P3": 9, "P4": 45}


# --- handover report ---------------------------------------------------------------------------


def test_handover_lists_only_approved_edited_escalated_in_rank_order(repo, clock):
    q = [row.incident_id for row in repo.queue(B)]
    plan = [
        (q[3], "approve", {}),
        (q[0], "escalate", {"notes": "IR <lead> & legal"}),
        (q[1], "dismiss", {"notes": "benign"}),
        (q[2], "edit", {"edited_brief": "Analyst rewrite of the brief."}),
    ]
    for iid, action, kw in plan:
        repo.open_incident(B, iid, "jane")
        clock.advance(45)
        repo.record_decision(B, iid, "jane", action, **kw)
    h = build_handover(repo, B)
    assert [i.incident_id for i in h.items] == [q[0], q[2], q[3]]
    md = to_markdown(h)
    assert md.startswith("# Shift handover: batch-042\n")
    assert "| 3,000 | 65 | 46× | 4 | 1 | 1 | 1 | 1 | 61 | 45s |" in md
    assert f"### 1. [P1] {q[0]} · risk" in md and "ESCALATED by jane at 14:31 IST" in md
    assert "**Escalation note:** IR <lead> & legal" in md
    assert "Analyst rewrite of the brief." in md
    assert q[1] not in md  # dismissed: counted, not listed
    assert "**Assets:** FINDB01" in md  # final brief text for approved/escalated
    html = to_html(h)
    assert html.startswith("<!doctype html>") and "@media print" in html
    assert "IR &lt;lead&gt; &amp; legal" in html and "<lead>" not in html
    assert [e["event"] for e in repo.audit(B)][-1] == "report_exported"


def test_handover_puts_each_brief_field_on_its_own_line(repo, clock):
    top = repo.queue(B)[0].incident_id
    repo.open_incident(B, top, "jane")
    clock.advance(30)
    repo.record_decision(B, top, "jane", "approve")
    item = build_handover(repo, B).items[0]
    brief = item.brief
    assert brief is not None
    md = to_markdown(build_handover(repo, B))
    lines = md.splitlines()
    for label in ("Verdict", "Assets", "Techniques", "Timeline", "Next action"):
        starts = [n for n, line in enumerate(lines) if line.startswith(f"**{label}:**")]
        assert len(starts) == 1, label  # the label starts its own line, once
        assert lines[starts[0] - 1] == "", label  # a paragraph of its own, not run together
    timeline = lines.index("**Timeline:**")
    entries = lines[timeline + 2 : timeline + 2 + len(brief.timeline)]
    assert entries == [f"- {entry}" for entry in brief.timeline]  # a Markdown list
    html = to_html(build_handover(repo, B))
    assert "<p><strong>Assets:</strong> FINDB01" in html and "<ul><li>" in html


def test_handover_keeps_line_breaks_of_an_edited_brief(repo, clock):
    top = repo.queue(B)[0].incident_id
    repo.open_incident(B, top, "jane")
    clock.advance(30)
    repo.record_decision(B, top, "jane", "edit", edited_brief="Line one.\nLine two.\n\nLine four.")
    md = to_markdown(build_handover(repo, B))
    assert "Line one.  \nLine two.\n\nLine four." in md  # hard break, then a new paragraph


def test_handover_with_no_decisions(repo):
    md = to_markdown(build_handover(repo, B))
    assert "_No approved, edited or escalated incidents yet._" in md
