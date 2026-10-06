import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from nullpunkt.app.baseline import alert_table, filter_alerts
from nullpunkt.briefing.llm import FakeClient, LLMError
from nullpunkt.core.config import PipelineConfig
from nullpunkt.evaluation.mttt_study import (
    ArmResult,
    StudyResult,
    km_median,
    schedule_check,
    to_markdown,
    wilcoxon_exact_p,
)
from nullpunkt.evaluation.sweep_correlation import make_batch
from nullpunkt.pipeline import process
from nullpunkt.storage.repository import DecisionError, SessionRecord, SQLiteRepository

T0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
B = "batch-042"
BOX = 900


class FakeClock:
    def __init__(self) -> None:
        self.t = T0

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
    r = SQLiteRepository(tmp_path / "study.db", clock=clock)
    r.save_shift(result, PipelineConfig(), B, "x")
    yield r
    r.close()


def baseline(repo, code="P1"):
    return repo.start_session(code, B, arm="baseline", time_box_seconds=BOX)


def tool(repo, code="P1"):
    return repo.start_session(code, B, arm="tool", time_box_seconds=BOX)


# --- sessions ----------------------------------------------------------------------------------


def test_study_session_fields(repo):
    s = repo.start_session("P3", B, arm="baseline", purpose="practice", time_box_seconds=BOX)
    assert (s.analyst, s.arm, s.purpose, s.time_box_seconds) == ("P3", "baseline", "practice", BOX)
    assert s.deadline == T0 + timedelta(seconds=BOX)
    started = [e for e in repo.audit(B) if e["event"] == "session_started"][-1]
    assert started["payload"] == {
        "session_id": s.session_id, "arm": "baseline", "purpose": "practice",
        "time_box_seconds": BOX,
    }  # fmt: skip


@pytest.mark.parametrize(
    ("code", "kwargs", "message"),
    [
        ("Jane Doe", {"arm": "tool", "time_box_seconds": BOX}, "participant code"),
        ("jane", {"arm": "tool", "time_box_seconds": BOX}, "participant code"),
        ("P1", {"arm": "spreadsheet", "time_box_seconds": BOX}, "arm must be"),
        ("P1", {"arm": "tool"}, "needs a time box"),
        ("P1", {"arm": "tool", "time_box_seconds": BOX, "purpose": "fun"}, "purpose must be"),
    ],
)
def test_study_session_validation(repo, code, kwargs, message):
    with pytest.raises(DecisionError, match=message):
        repo.start_session(code, B, **kwargs)


def test_time_box_ends_the_session_at_its_deadline(repo, clock):
    s = baseline(repo)
    clock.advance(BOX - 1)
    assert repo.session(s.session_id).running
    assert repo.session(s.session_id).remaining_seconds(clock()) == 1
    clock.advance(500)  # the tab was closed; nobody pressed End
    ended = repo.session(s.session_id)
    assert not ended.running and ended.end_reason == "timed_out"
    assert ended.ended_at == s.deadline  # exactly the deadline, not "now"
    assert ended.remaining_seconds(clock()) == 0
    assert repo.running_session("P1") is None
    events = [e["event"] for e in repo.audit(B)]
    assert events.count("session_timed_out") == 1
    repo.session(s.session_id)
    assert [e["event"] for e in repo.audit(B)].count("session_timed_out") == 1  # only once


def test_ending_early_is_recorded_as_ended(repo, clock):
    s = tool(repo)
    clock.advance(300)
    ended = repo.end_session(s.session_id)
    assert ended.end_reason == "ended" and ended.ended_at == T0 + timedelta(seconds=300)


# --- flags -------------------------------------------------------------------------------------


def test_flag_timing(repo, clock):
    s = baseline(repo)
    clock.advance(125)
    flag = repo.flag_alert(s.session_id, "ALR-000001", "  odd  ")
    assert flag.flagged_at == T0 + timedelta(seconds=125) and flag.note == "odd"
    clock.advance(5)
    repo.flag_alert(s.session_id, "ALR-000002")
    assert [f.alert_id for f in repo.flags(s.session_id)] == ["ALR-000001", "ALR-000002"]
    assert repo.flags(s.session_id)[1].note is None
    assert "alert_flagged" in [e["event"] for e in repo.audit(B)]


def test_no_flags_after_the_time_box(repo, clock):
    s = baseline(repo)
    clock.advance(BOX)
    with pytest.raises(DecisionError, match="has ended"):
        repo.flag_alert(s.session_id, "ALR-000001")
    assert repo.flags(s.session_id) == []


def test_flags_only_in_baseline_sessions_and_for_known_alerts(repo):
    t = tool(repo, "P2")
    with pytest.raises(DecisionError, match="baseline sessions"):
        repo.flag_alert(t.session_id, "ALR-000001")
    b = baseline(repo, "P3")
    with pytest.raises(DecisionError, match="not an alert"):
        repo.flag_alert(b.session_id, "ALR-999999")


def test_flags_are_append_only(repo):
    s = baseline(repo)
    repo.flag_alert(s.session_id, "ALR-000001")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        repo.conn.execute("DELETE FROM flags")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        repo.conn.execute("UPDATE flags SET note = 'x'")


# --- decisions in study sessions ---------------------------------------------------------------


def test_baseline_sessions_make_no_decisions(repo):
    s = baseline(repo)
    repo.open_incident(B, "INC-0055", "P1", s.session_id)
    with pytest.raises(DecisionError, match="no decisions"):
        repo.record_decision(B, "INC-0055", "P1", "approve", session_id=s.session_id)


def test_no_decisions_after_the_time_box(repo, clock):
    s = tool(repo)
    repo.open_incident(B, "INC-0055", "P1", s.session_id)
    clock.advance(BOX + 1)
    with pytest.raises(DecisionError, match="has ended"):
        repo.record_decision(B, "INC-0055", "P1", "approve", session_id=s.session_id)
    assert repo.decisions(B) == []


# --- baseline list -----------------------------------------------------------------------------


def test_raw_alerts_carry_nothing_derived(repo):
    alerts = repo.raw_alerts(B)
    assert len(alerts) == 3000
    rows = alert_table(alerts, "Asia/Kolkata")
    assert list(rows[0]) == ["Time", "Severity", "Source", "Rule", "Host", "User", "Source IP",
                             "Destination IP", "Message", "Alert"]  # fmt: skip
    order = [r["Severity"] for r in rows]
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    assert order == sorted(order, key=lambda s: -weights[s])  # severity first
    crit = [r["Time"] for r in rows if r["Severity"] == "critical"]
    assert crit == sorted(crit)  # then time


def test_baseline_filters(repo):
    rows = alert_table(repo.raw_alerts(B), "Asia/Kolkata")
    assert all(r["Severity"] == "low" for r in filter_alerts(rows, severities=["low"]))
    assert all(r["Host"] == "FINDB01" for r in filter_alerts(rows, host="findb01"))
    hits = filter_alerts(rows, query="powershell")
    assert hits and all("powershell" in (r["Rule"] + r["Message"]).lower() for r in hits)
    assert len(filter_alerts(rows)) == 3000
    assert filter_alerts(rows, query="ALR-000010") == [
        r for r in rows if r["Alert"] == "ALR-000010"
    ]


# --- statistics --------------------------------------------------------------------------------


def arm(detections: dict[str, float | None], tau: float = 900) -> ArmResult:
    return ArmResult("P1", "tool", B, "S001", tau, detections, 0, 0)


def test_rmst_censors_misses_at_the_time_box():
    r = arm({"SCN-01": 60.0, "SCN-02": None, "SCN-03": 300.0})
    assert r.detected == 2 and r.attacks == 3
    assert r.rmst_seconds == (60 + 900 + 300) / 3
    assert arm({"SCN-01": None}).rmst_seconds == 900  # nothing found: the whole box


def test_km_median():
    assert km_median([60, 120, 300, None], 900) == 120  # S: 0.75, 0.5 -> median 120
    assert km_median([60, None, None, None], 900) is None  # never reaches 0.5
    assert km_median([100, 100, 200], 900) == 100  # tied events


def test_wilcoxon_exact_p():
    assert wilcoxon_exact_p([5, 4, 3, 2, 1]) == pytest.approx(0.0625)  # smallest possible, n=5
    assert wilcoxon_exact_p([5, -4, 3, -2, 1]) == pytest.approx(0.8125)
    assert wilcoxon_exact_p([0, 0]) is None
    assert wilcoxon_exact_p([2, 2, -2]) == pytest.approx(1.0)


# --- results document ------------------------------------------------------------------------


class SessionsOnly:
    """Just enough repository for the schedule check."""

    def __init__(self, sessions: list[SessionRecord] | None = None) -> None:
        self._sessions = sessions or []

    def sessions(self) -> list[SessionRecord]:
        return self._sessions


A = {"SCN-01": None, "SCN-03": None, "SCN-05": None, "SCN-07": None}


def scored(person, arm_name, batch, detections, sid, fp=0) -> ArmResult:
    return ArmResult(person, arm_name, batch, sid, 900, detections, fp, 0)


def pilot() -> StudyResult:
    """The real pilot's shape: P1 ran both arms on study-A, baseline first."""
    found = {"SCN-01": 82.0, "SCN-03": 220.0, "SCN-05": 270.0, "SCN-07": 292.0}
    return StudyResult([
        scored("P1", "baseline", "study-A", dict(A), "S004", fp=53),
        scored("P1", "tool", "study-A", found, "S005", fp=8),
    ])  # fmt: skip


def test_pilot_document_states_the_real_participant_count():
    text = to_markdown(pilot(), SessionsOnly())
    assert "**Pilot with one participant.**" in text
    assert "- **Small n.** One participant;" in text and "This is a pilot" in text
    assert "on one paired participant: 1.000" in text
    assert "with n = 1 the smallest possible p is 1, so no significance claim" in text
    assert "five" not in text.lower() and "n = 5" not in text
    assert "- **One batch.** Only study-A was analysed" in text and "study-B" in text


def test_same_batch_in_both_arms_is_reported_with_the_learning_risk():
    study = pilot()
    first, second = study.same_batch()[0]
    assert (first.arm, second.arm, first.batch_id) == ("baseline", "tool", "study-A")
    text = to_markdown(study, SessionsOnly())
    assert "**Deviation: P1 ran both arms on study-A** (baseline first, then tool)" in text
    assert "- **Same batch in both arms.** P1 ran the baseline arm and then the tool arm" in text
    assert "This favours the tool arm, so the improvement may be overstated." in text
    assert "P1 detected no attacks in the first arm" in text
    assert "The participant ran the baseline arm first, so practice favours the tool arm" in text


def test_no_pilot_or_same_batch_notes_for_a_full_crossover():
    rows = []
    for i, (person, arms) in enumerate(
        {"P1": ("baseline", "tool"), "P2": ("tool", "baseline"), "P3": ("baseline", "tool")}.items()
    ):
        batches = ("study-A", "study-B") if i % 2 == 0 else ("study-B", "study-A")
        for j, (arm_name, batch) in enumerate(zip(arms, batches, strict=True)):
            rows.append(scored(person, arm_name, batch, {"SCN-01": None}, f"S{i}{j}"))
    study = StudyResult(rows)
    assert study.same_batch() == []
    text = to_markdown(study, SessionsOnly())
    assert "Pilot" not in text and "Same batch" not in text and "Deviation: P" not in text
    assert "- **Small n.** Three participants;" in text
    assert "on three paired participants" in text and "smallest possible p is 0.25" in text
    assert "whichever arm it is; counterbalancing spreads this over both arms" in text


def test_p_value_note_drops_the_no_significance_clause_once_it_is_possible():
    rows = [scored(f"P{i}", arm_name, "study-A", {"SCN-01": None}, f"S{i}{arm_name}")
            for i in range(6) for arm_name in ("baseline", "tool")]  # fmt: skip
    text = to_markdown(StudyResult(rows), SessionsOnly())
    assert "with n = 6 the smallest possible p is 0.03125)." in text
    assert "so no significance claim is possible)" not in text


def test_schedule_check_ignores_sessions_outside_the_study_batches():
    def session(sid, batch, arm_name, minute):
        start = T0 + timedelta(minutes=minute)
        return SessionRecord(sid, "P1", batch, start, start + timedelta(minutes=15), arm_name,
                             "study", BOX, "timed_out")  # fmt: skip

    repo = SessionsOnly([
        session("S001", "practice", "baseline", 0),
        session("S002", "study-A", "baseline", 20),
        session("S003", "study-A", "tool", 40),
    ])  # fmt: skip
    notes = schedule_check(pilot(), repo)
    p1 = next(n for n in notes if n.startswith("P1:"))
    assert "practice" not in p1 and "ran [('baseline', 'study-A'), ('tool', 'study-A')]" in p1
