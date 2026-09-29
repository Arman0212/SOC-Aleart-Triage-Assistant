"""The before/after study end to end: the two study batches, simulated participants on the
pre-registered schedule (fake clock), the analysis and results document, and the study UI."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from nullpunkt.core.config import PipelineConfig
from nullpunkt.evaluation.ground_truth import load_ground_truth
from nullpunkt.evaluation.mttt_study import SCHEDULE, analyse, main, to_markdown
from nullpunkt.generator.batch import generate, write_batch
from nullpunkt.generator.config import load_config
from nullpunkt.storage.prepare import prepare_shift
from nullpunkt.storage.repository import SQLiteRepository

REPO = Path(__file__).parents[2]
APP = str(REPO / "app" / "streamlit_app.py")
BOX = 900
T0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)


@pytest.fixture(scope="module")
def batches(tmp_path_factory):
    root = tmp_path_factory.mktemp("study")
    dirs = {}
    for batch_id, config in (("study-A", "study_a"), ("study-B", "study_b")):
        out = root / batch_id
        write_batch(generate(load_config(REPO / "configs" / f"{config}.yaml")), out)
        dirs[batch_id] = out
    return dirs


@pytest.fixture(scope="module")
def prepared(batches, tmp_path_factory):
    db = tmp_path_factory.mktemp("studydb") / "study.db"
    repo = SQLiteRepository(db)
    for out in batches.values():
        prepare_shift(out, repo, PipelineConfig(), briefs=False)
    repo.close()
    return db


@pytest.fixture
def labels(batches):
    return {b: load_ground_truth(d / "labels.csv") for b, d in batches.items()}


def test_study_batches_hold_disjoint_attacks(labels):
    a = {g.scenario_id for g in labels["study-A"].values() if g.scenario_id}
    b = {g.scenario_id for g in labels["study-B"].values() if g.scenario_id}
    assert a == {"SCN-01", "SCN-03", "SCN-05", "SCN-07"}
    assert b == {"SCN-02", "SCN-04", "SCN-06"}


def _copy(prepared, tmp_path) -> Path:
    copy = tmp_path / "study.db"
    src = SQLiteRepository(prepared)
    src.conn.execute(f"VACUUM INTO '{copy}'")
    src.close()
    return copy


def _scenario_alerts(labels, batch_id, scenario) -> list[str]:
    return sorted(a for a, g in labels[batch_id].items() if g.scenario_id == scenario)


def _incident_of(repo, batch_id, alert_id) -> str:
    return repo.conn.execute(
        "SELECT incident_id FROM alerts WHERE batch_id = ? AND alert_id = ?", (batch_id, alert_id)
    ).fetchone()[0]


def _noise_alert(labels, batch_id) -> str:
    return next(a for a, g in sorted(labels[batch_id].items()) if not g.scenario_id)


def run_simulated_study(repo, clock, labels):
    """Five fake participants on the pre-registered schedule. In the tool arm they find every
    attack quickly; in the baseline arm they find one or two and flag noise."""
    for person, arms in SCHEDULE.items():
        for arm_name, batch_id in arms:
            session = repo.start_session(person, batch_id, arm=arm_name, time_box_seconds=BOX)
            attacks = sorted({g.scenario_id for g in labels[batch_id].values() if g.scenario_id})
            if arm_name == "tool":
                for scenario in attacks:
                    incident = _incident_of(
                        repo, batch_id, _scenario_alerts(labels, batch_id, scenario)[0]
                    )
                    clock.advance(40)  # scanning the queue
                    repo.open_incident(batch_id, incident, person, session.session_id)
                    clock.advance(50)
                    repo.record_decision(
                        batch_id, incident, person, "approve", session_id=session.session_id
                    )  # noqa: E501
                clock.advance(BOX)  # sits out the rest; the box ends the session
            else:
                clock.advance(400)
                repo.flag_alert(session.session_id, _noise_alert(labels, batch_id), "looked odd")
                clock.advance(200)
                first = _scenario_alerts(labels, batch_id, attacks[0])[0]
                repo.flag_alert(session.session_id, first, "suspicious")
                clock.advance(BOX)
            assert not repo.session(session.session_id).running
            clock.advance(180)  # break


def test_detection_matching_in_both_arms(prepared, tmp_path, labels):
    clock = FakeClock()
    repo = SQLiteRepository(_copy(prepared, tmp_path), clock=clock)
    # Tool arm on study-A: approve SCN-01's incident, dismiss SCN-03's, approve a noise incident.
    s = repo.start_session("P1", "study-A", arm="tool", time_box_seconds=BOX)
    scn01 = _incident_of(repo, "study-A", _scenario_alerts(labels, "study-A", "SCN-01")[0])
    scn03 = _incident_of(repo, "study-A", _scenario_alerts(labels, "study-A", "SCN-03")[0])
    noise = next(q.incident_id for q in reversed(repo.queue("study-A")))
    for incident, action, kw in ((scn01, "approve", {}), (scn03, "dismiss", {"notes": "benign"}),
                                 (noise, "escalate", {"notes": "odd"})):  # fmt: skip
        repo.open_incident("study-A", incident, "P1", s.session_id)
        clock.advance(60)
        repo.record_decision("study-A", incident, "P1", action, session_id=s.session_id, **kw)
    repo.end_session(s.session_id)
    # Baseline arm on study-B: flag a noise alert, then an SCN-04 alert at +300 s.
    clock.advance(60)
    b = repo.start_session("P1", "study-B", arm="baseline", time_box_seconds=BOX)
    clock.advance(100)
    repo.flag_alert(b.session_id, _noise_alert(labels, "study-B"))
    clock.advance(200)
    repo.flag_alert(b.session_id, _scenario_alerts(labels, "study-B", "SCN-04")[-1])
    clock.advance(BOX)
    study = analyse(repo, labels)
    by_arm = {r.arm: r for r in study.results}
    t, base = by_arm["tool"], by_arm["baseline"]
    assert t.detections == {"SCN-01": 60.0, "SCN-03": None, "SCN-05": None, "SCN-07": None}
    assert t.false_positives == 1 and t.actions == 3 and t.mttt_seconds == 60
    assert base.detections == {"SCN-02": None, "SCN-04": 300.0, "SCN-06": None}
    assert base.false_positives == 1 and base.end_reason == "timed_out"
    assert base.rmst_seconds == (900 + 300 + 900) / 3
    repo.close()


def test_simulated_study_and_results_document(prepared, tmp_path, labels, batches):
    clock = FakeClock()
    db = _copy(prepared, tmp_path)
    repo = SQLiteRepository(db, clock=clock)
    # A dry run and a practice session first: both must be excluded.
    dry = repo.start_session("DRY", "study-A", arm="tool", purpose="dry-run", time_box_seconds=BOX)
    clock.advance(BOX + 1)
    repo.session(dry.session_id)
    run_simulated_study(repo, clock, labels)
    study = analyse(repo, labels)
    assert len(study.arm("tool")) == len(study.arm("baseline")) == 5
    assert study.detection_rate("tool") == 1.0
    # Baseline ran study-A three times (P1, P4, P5) and study-B twice: 4x3 + 3x2 attacks.
    assert study.detection_rate("baseline") == pytest.approx(5 / (4 * 3 + 3 * 2))
    assert study.rmst("tool") < study.rmst("baseline")
    assert study.improvement() > 0.5
    assert any(why == "purpose dry-run" for _, why in study.excluded)
    text = to_markdown(study, repo)
    assert text.startswith("# Before/after study: time to detect")
    assert "**Target met**" in text and "Restricted mean time to detect (τ = 15:00)" in text
    assert "| P1 | baseline | study-A |" in text and "| P5 | tool | study-B |" in text
    assert "All five participants followed the pre-registered schedule." in text
    assert "Excluded S001 (DRY, tool, study-A): purpose dry-run" in text
    assert "Round 1 deck" in text and "smallest possible p is 0.0625" in text
    repo.close()
    out = tmp_path / "mttt_study.md"
    args = ["--db", str(db), "--out", str(out)]
    for batch_id, directory in batches.items():
        args += ["--batch", f"{batch_id}={directory}"]
    assert main(args) == 0
    written = out.read_text()
    assert written.startswith("# Before/after study") and "## Per participant" in written
    assert "| P3 | tool | study-A | 4/4 |" in written


def test_target_not_met_is_reported_honestly(prepared, tmp_path, labels):
    clock = FakeClock()
    repo = SQLiteRepository(_copy(prepared, tmp_path), clock=clock)
    for person in ("P1", "P2"):
        for arm_name, batch_id in (("baseline", "study-A"), ("tool", "study-B")):
            s = repo.start_session(person, batch_id, arm=arm_name, time_box_seconds=BOX)
            clock.advance(BOX)  # nobody finds anything in either arm
            repo.session(s.session_id)
    study = analyse(repo, labels)
    assert study.improvement() == 0
    text = to_markdown(study, repo)
    assert "**Target not met**" in text and "P3: planned" in text
    repo.close()


# --- the study UI ------------------------------------------------------------------------------


@pytest.fixture
def ui_db(prepared, tmp_path, monkeypatch):
    db = _copy(prepared, tmp_path)
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.chdir(REPO)
    return db


def start(at: AppTest, code: str, arm: str, batch: str) -> AppTest:
    at.run()
    at.sidebar.text_input(key="s_participant").input(code).run()
    at.sidebar.radio(key="s_arm").set_value(arm).run()
    at.sidebar.selectbox(key="s_batch").select(batch).run()
    return at.sidebar.button(key="session_start").click().run()


FORBIDDEN = ("INC-", "risk", "Risk", "tier", "Tier", "P1", "P2", "brief", "Brief", "ATT&CK",
             "T1566", "tactic", "Incident", "incident", "score", "Score")  # fmt: skip


def test_baseline_page_shows_raw_alerts_only(ui_db):
    at = start(AppTest.from_file(APP, default_timeout=60), "P1", "baseline", "study-A")
    assert not at.exception
    table = at.dataframe[0].value
    assert len(table) == 3000
    assert list(table.columns) == ["Time", "Severity", "Source", "Rule", "Host", "User",
                                   "Source IP", "Destination IP", "Message", "Alert"]  # fmt: skip
    main = at.main
    rendered = " ".join(
        [m.value for m in main.markdown if not m.value.lstrip().startswith("<style>")]
        + [c.value for c in main.caption]
        + [i.value for i in main.info]
        + [b.label for b in main.button]
        + [t.label for t in main.text_input]
        + [str(x.label) for x in main.multiselect]
    )
    for word in FORBIDDEN:
        assert word not in rendered, word
    sidebar = " ".join(m.value for m in at.sidebar.markdown)
    assert "⏱ 15:00" in sidebar or "⏱ 14:5" in sidebar
    assert "baseline arm" in sidebar


def test_baseline_flag_via_the_page(ui_db):
    at = start(AppTest.from_file(APP, default_timeout=60), "P2", "baseline", "study-B")
    at.text_input(key="flag_alert_id").input("ALR-000010").run()
    at.text_input(key="flag_note").input("strange").run()
    at.button(key="flag_submit").click().run()
    assert not at.exception
    repo = SQLiteRepository(ui_db)
    session = repo.running_session("P2")
    flags = repo.flags(session.session_id)
    assert [(f.alert_id, f.note) for f in flags] == [("ALR-000010", "strange")]
    assert session.arm == "baseline" and session.time_box_seconds == 900
    repo.close()


def test_tool_session_restricts_navigation_and_tags_decisions(ui_db):
    at = start(AppTest.from_file(APP, default_timeout=60), "P3", "tool", "study-A")
    assert not at.exception
    assert len(at.dataframe[0].value) > 50  # the queue, not the alert list
    at.selectbox(key="open_choice").select(at.selectbox(key="open_choice").options[0]).run()
    at.button(key="open_incident").click().run()
    at.switch_page("pages/incident.py").run()
    at.button(key="approve").click().run()
    repo = SQLiteRepository(ui_db)
    session = repo.running_session("P3")
    assert [d.study_session for d in repo.decisions("study-A")] == [session.session_id]
    repo.close()


def test_expired_session_ends_itself_in_the_ui(ui_db):
    # A session whose 15 minutes ran out an hour ago (e.g. the laptop slept).
    past = SQLiteRepository(ui_db, clock=lambda: datetime.now(UTC) - timedelta(hours=1))
    s = past.start_session("P4", "study-B", arm="baseline", time_box_seconds=BOX)
    past.close()
    at = AppTest.from_file(APP, default_timeout=60)
    at.session_state["active_session_id"] = s.session_id
    at.run()
    assert not at.exception
    assert any("time box reached" in w.value for w in at.sidebar.warning)
    repo = SQLiteRepository(ui_db)
    ended = repo.session(s.session_id)
    assert ended.end_reason == "timed_out" and ended.ended_at == s.deadline
    repo.close()


def test_invalid_participant_code_is_refused_in_the_ui(ui_db):
    at = start(AppTest.from_file(APP, default_timeout=60), "Jane Doe", "tool", "study-A")
    assert any("participant code" in e.value for e in at.sidebar.error)
