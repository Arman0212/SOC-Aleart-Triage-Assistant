"""Prepare a shift into SQLite (fake LLM client), then drive the Streamlit app headlessly."""

import time
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from nullpunkt.briefing.llm import FakeClient, LLMError
from nullpunkt.core.config import BriefingConfig, PipelineConfig
from nullpunkt.generator.batch import generate, write_batch
from nullpunkt.generator.config import GeneratorConfig
from nullpunkt.storage.prepare import main, prepare_shift
from nullpunkt.storage.repository import SQLiteRepository

REPO = Path(__file__).parents[2]
APP = str(REPO / "app" / "streamlit_app.py")
B = "batch-042"


@pytest.fixture(scope="module")
def batch_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("prep") / B
    write_batch(generate(GeneratorConfig(seed=42)), out)
    return out


def _config(tmp_path) -> PipelineConfig:
    return PipelineConfig(briefing=BriefingConfig(cache_dir=str(tmp_path / "cache")))


@pytest.fixture(scope="module")
def prepared_db(batch_dir, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("db")
    db = tmp / "shift.db"
    repo = SQLiteRepository(db)
    down = FakeClient([LLMError("unreachable", "no model in tests")])
    prepare_shift(batch_dir, repo, _config(tmp), client=down)
    repo.close()
    return db


# --- prepare-shift -----------------------------------------------------------------------------


def test_prepare_shift_stores_everything(prepared_db):
    repo = SQLiteRepository(prepared_db)
    batch = repo.batch(B)
    assert (batch.alert_count, batch.incident_count) == (3000, 65)
    assert batch.model == "fake" and batch.prompt_version == "v1"
    assert repo.brief_sources(B) == {"template": 10}
    count = repo.conn.execute("SELECT COUNT(*) FROM alerts WHERE batch_id = ?", (B,)).fetchone()[0]
    assert count == 3000
    links = repo.conn.execute("SELECT COUNT(*) FROM links WHERE batch_id = ?", (B,)).fetchone()[0]
    assert links == 3000 - 65  # one link per union: a spanning tree per incident
    assert repo.conn.execute("SELECT COUNT(*) FROM hubs").fetchone()[0] > 10
    assert repo.audit(B)[0]["event"] == "shift_prepared"
    repo.close()


def test_prepare_shift_cli(batch_dir, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no .env, no configs/: defaults
    monkeypatch.delenv("DB_PATH", raising=False)
    db = tmp_path / "cli.db"
    args = ["--batch", str(batch_dir), "--db", str(db), "--no-briefs"]
    assert main(args) == 0
    assert f"prepared {B} into {db}: 3000 alerts -> 65 incidents" in capsys.readouterr().out
    assert main(args) == 2  # already prepared
    assert "already prepared" in capsys.readouterr().err
    assert main([*args, "--replace"]) == 0


def test_db_path_from_environment(batch_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "env.db"
    monkeypatch.setenv("DB_PATH", str(db))
    assert main(["--batch", str(batch_dir), "--no-briefs"]) == 0
    assert db.is_file()


# --- the app -----------------------------------------------------------------------------------


@pytest.fixture
def db(prepared_db, tmp_path, monkeypatch):
    """A fresh copy of the prepared database per test, so decisions don't leak between tests."""
    copy = tmp_path / "shift.db"
    source = SQLiteRepository(prepared_db)
    source.conn.execute(f"VACUUM INTO '{copy}'")
    source.close()
    monkeypatch.setenv("DB_PATH", str(copy))
    monkeypatch.chdir(REPO)
    return copy


def app() -> AppTest:
    return AppTest.from_file(APP, default_timeout=60)


def open_incident(at: AppTest, incident_id: str, analyst: str = "jane") -> AppTest:
    at.run()
    at.sidebar.text_input(key="analyst").input(analyst).run()
    at.selectbox(key="open_choice").select(incident_id).run()
    at.button(key="open_incident").click().run()
    # AppTest does not keep a page switched to from inside the script for later reruns (a
    # browser keeps it in the URL), so pin it before interacting.
    return at.switch_page("pages/incident.py").run()


def test_queue_loads_fast_with_all_incidents(db):
    at = app()
    at.run()  # cold: imports, cache warm-up
    assert not at.exception
    started = time.perf_counter()
    at.run()
    assert time.perf_counter() - started < 1.0
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Alerts in shift"] == "3,000" and metrics["Incidents"] == "65"
    assert metrics["Reduction"] == "46×" and metrics["Decided"] == "0 / 65"
    table = at.dataframe[0].value
    assert len(table) == 65
    assert list(table["Tier"][:4]) == ["P1"] * 4 and table["Incident"].iloc[0] == "INC-0055"


def test_queue_filters(db):
    at = app()
    at.run()
    at.multiselect(key="f_tier").set_value(["P1"]).run()
    assert list(at.dataframe[0].value["Tier"]) == ["P1"] * 4


def test_opening_an_incident_starts_triage_once(db):
    at = open_incident(app(), "INC-0055")
    assert not at.exception
    text = " ".join(m.value for m in at.markdown)
    assert "INC-0055" in text and "np-verdict" in text
    assert "Why these alerts are grouped" in text and "Evidence timeline (IST)" in text
    sc = at.metric[0]
    assert sc.label == "S × C" and "Severity × criticality" in sc.proto.help  # short label
    at.run()  # rerun must not start a second timer
    repo = SQLiteRepository(db)
    opened = [e for e in repo.audit(B) if e["event"] == "incident_opened"]
    assert len(opened) == 1 and opened[0]["actor"] == "jane"
    assert repo.current_opening(B, "INC-0055", "jane") is not None
    repo.close()


def test_no_timer_without_an_analyst_name(db):
    at = app()
    at.run()
    at.session_state["incident_id"] = "INC-0055"
    at.switch_page("pages/incident.py").run()
    assert any("Enter your analyst name" in w.value for w in at.warning)
    repo = SQLiteRepository(db)
    assert [e["event"] for e in repo.audit(B)] == ["shift_prepared"]
    repo.close()


@pytest.mark.parametrize(
    ("action", "fill", "status"),
    [
        ("approve", None, "approved"),
        ("edit_submit", ("edit_text", "My own brief."), "approved"),
        ("dismiss_submit", ("dismiss_reason", "known pentest"), "dismissed"),
        ("escalate_submit", ("escalate_note", "IR lead paged"), "escalated"),
    ],
)
def test_each_decision_type(db, action, fill, status):
    at = open_incident(app(), "INC-0055")
    if fill:
        key, value = fill
        widget = at.text_area(key=key) if key != "dismiss_reason" else at.text_input(key=key)
        widget.input(value).run()
    at.button(key=action).click().run()
    assert not at.exception
    repo = SQLiteRepository(db)
    view = repo.incident(B, "INC-0055")
    assert view.status == status
    d = view.latest_decision
    assert d.analyst == "jane" and d.triage_seconds >= 0 and d.study_session is None
    if action == "edit_submit":
        assert d.edited_brief == "My own brief."
    if fill and action != "edit_submit":
        assert d.notes == fill[1]
    repo.close()
    assert any("by jane" in s.value for s in at.success)


def test_dismiss_without_reason_is_refused(db):
    at = open_incident(app(), "INC-0055")
    at.button(key="dismiss_submit").click().run()
    assert any("needs a reason" in e.value for e in at.error)
    repo = SQLiteRepository(db)
    assert repo.decisions(B) == [] and repo.incident(B, "INC-0055").status == "open"
    repo.close()


def test_redecision_via_change_decision(db):
    at = open_incident(app(), "INC-0055")
    at.button(key="approve").click().run()
    at.button(key="redecide").click().run()
    at.text_area(key="escalate_note").input("second look: escalate").run()
    at.button(key="escalate_submit").click().run()
    repo = SQLiteRepository(db)
    assert [d.action.value for d in repo.decisions(B)] == ["approve", "escalate"]
    assert repo.incident(B, "INC-0055").status == "escalated"
    assert "decision_changed" in [e["event"] for e in repo.audit(B)]
    repo.close()


def _start_tool_session(code: str) -> AppTest:
    at = app()
    at.run()
    at.sidebar.text_input(key="s_participant").input(code).run()
    at.sidebar.radio(key="s_arm").set_value("tool").run()
    return at.sidebar.button(key="session_start").click().run()


def _approve_top(at: AppTest) -> AppTest:
    at.selectbox(key="open_choice").select("INC-0055").run()
    at.button(key="open_incident").click().run()
    at.switch_page("pages/incident.py").run()
    return at.button(key="approve").click().run()


def test_study_session_controls_tag_decisions(db):
    at = _start_tool_session("P9")
    repo = SQLiteRepository(db)
    session = repo.running_session("P9")
    assert session is not None and session.batch_id == B and session.arm == "tool"
    _approve_top(at)
    assert repo.decisions(B)[0].study_session == session.session_id
    assert repo.incident(B, "INC-0055").status == "open"  # study work never touches the shift
    at.sidebar.button(key="session_end").click().run()
    assert repo.running_session("P9") is None
    events = [e["event"] for e in repo.audit(B)]
    assert "session_started" in events and "session_ended" in events
    repo.close()


def test_each_participant_starts_from_a_fresh_queue(db):
    _approve_top(_start_tool_session("P1"))
    at = _start_tool_session("P2")
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Decided"] == "0 / 65"
    assert at.dataframe[0].value["Status"].iloc[0] == "open"
    _approve_top(at)  # P2 can triage INC-0055 although P1 already approved it
    repo = SQLiteRepository(db)
    assert [d.analyst for d in repo.decisions(B)] == ["P1", "P2"]
    repo.close()


def test_handover_page(db):
    at = open_incident(app(), "INC-0055")
    at.text_area(key="escalate_note").input("Paged the IR lead").run()
    at.button(key="escalate_submit").click().run()
    at.switch_page("pages/handover.py").run()
    assert not at.exception
    text = " ".join(m.value for m in at.markdown)
    assert "# Shift handover: batch-042" in text
    assert "ESCALATED by jane" in text and "Paged the IR lead" in text


def test_empty_database_explains_what_to_do(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "empty.db"))
    monkeypatch.chdir(REPO)
    at = app()
    at.run()
    assert not at.exception
    assert any("nullpunkt-prepare-shift" in i.value for i in at.info)
