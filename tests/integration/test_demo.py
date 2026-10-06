"""The committed demo database, nullpunkt-demo-reset and the optional passcode gate."""

import sqlite3
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from nullpunkt.storage.demo import main, pristine_problems, reset_demo
from nullpunkt.storage.repository import SQLiteRepository

REPO = Path(__file__).parents[2]
DEMO_DB = REPO / "data" / "demo" / "nullpunkt-demo.db"
APP = str(REPO / "app" / "streamlit_app.py")


def _count(db: Path, sql: str) -> int:
    conn = sqlite3.connect(f"{db.as_uri()}?mode=ro&immutable=1", uri=True)
    try:
        return conn.execute(sql).fetchone()[0]
    finally:
        conn.close()


# --- the committed demo database ---------------------------------------------------------------


@pytest.mark.parametrize("table", ["decisions", "openings", "flags", "study_sessions"])
def test_demo_db_has_no_analyst_activity(table):
    assert _count(DEMO_DB, f"SELECT COUNT(*) FROM {table}") == 0


def test_demo_db_is_the_prepared_seed_42_shift():
    assert pristine_problems(DEMO_DB) == []
    conn = sqlite3.connect(f"{DEMO_DB.as_uri()}?mode=ro&immutable=1", uri=True)
    try:
        batch = conn.execute("SELECT batch_id, alert_count, incident_count FROM batches").fetchall()
        briefs = conn.execute("SELECT generated_by, validated, COUNT(*) FROM briefs GROUP BY 1, 2")
        events = conn.execute("SELECT event FROM audit_log").fetchall()
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        briefs = briefs.fetchall()
    finally:
        conn.close()
    assert batch == [("batch-042", 3000, 65)]
    assert briefs == [("llm", 1, 10)]  # all ten from Phi, none from the template
    assert events == [("shift_prepared",)]
    assert mode == "delete"  # one self-contained file


# --- nullpunkt-demo-reset ----------------------------------------------------------------------


def test_reset_restores_the_pristine_shift(tmp_path):
    target = tmp_path / "live" / "nullpunkt.db"
    reset_demo(DEMO_DB, target)
    repo = SQLiteRepository(target)
    repo.open_incident("batch-042", "INC-0055", "jane")
    repo.record_decision("batch-042", "INC-0055", "jane", "approve")
    repo.close()
    assert pristine_problems(target) != []  # the demo was used

    reset_demo(DEMO_DB, target)
    assert pristine_problems(target) == []
    assert not Path(f"{target}-wal").exists()
    assert not target.with_name(target.name + ".tmp").exists()


def test_reset_refuses_a_used_database(tmp_path):
    used = tmp_path / "used.db"
    reset_demo(DEMO_DB, used)
    repo = SQLiteRepository(used)
    repo.start_session("P1", "batch-042")
    repo.close()
    with pytest.raises(ValueError, match="1 rows in study_sessions"):
        reset_demo(used, tmp_path / "target.db")
    with pytest.raises(ValueError, match="does not exist"):
        reset_demo(tmp_path / "missing.db", tmp_path / "target.db")
    with pytest.raises(ValueError, match="pristine copy itself"):
        reset_demo(DEMO_DB, DEMO_DB)


def test_reset_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)  # no configs/: DB_PATH or --db decide the target
    monkeypatch.setenv("DEMO_PRISTINE_DB", str(DEMO_DB))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "env.db"))
    assert main(["--check"]) == 0
    assert main([]) == 0
    assert pristine_problems(tmp_path / "env.db") == []
    assert main(["--db", str(tmp_path / "explicit.db")]) == 0
    assert (tmp_path / "explicit.db").is_file()
    assert main(["--check", "--pristine", str(tmp_path / "missing.db")]) == 1
    assert "does not exist" in capsys.readouterr().err


# --- the app on the demo database, with and without the passcode -------------------------------


@pytest.fixture
def demo_app(tmp_path, monkeypatch):
    reset_demo(DEMO_DB, tmp_path / "demo.db")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.chdir(REPO)
    return lambda: AppTest.from_file(APP, default_timeout=60)


def test_demo_db_serves_the_queue(demo_app):
    at = demo_app()
    at.run()
    assert not at.exception
    table = at.dataframe[0].value
    assert len(table) == 65 and table["Incident"].iloc[0] == "INC-0055"


def test_passcode_gate_hides_everything_until_unlocked(demo_app, monkeypatch):
    monkeypatch.setenv("DEMO_PASSCODE", "orbit-42")
    at = demo_app()
    at.run()
    assert not at.exception
    assert len(at.dataframe) == 0 and len(at.metric) == 0 and len(at.sidebar.text_input) == 0
    at.text_input(key="passcode").input("wrong")
    at.button[0].click().run()
    assert any("Wrong passcode" in e.value for e in at.error)
    assert len(at.dataframe) == 0

    at.text_input(key="passcode").input("orbit-42")
    at.button[0].click().run()
    assert not at.exception
    assert at.dataframe[0].value["Incident"].iloc[0] == "INC-0055"
    at.run()  # stays unlocked on later reruns
    assert len(at.dataframe) == 1


def test_sign_in_hands_name_and_shift_to_the_sidebar(demo_app, monkeypatch):
    monkeypatch.setenv("DEMO_PASSCODE", "orbit-42")
    at = demo_app()
    at.run()
    at.text_input(key="gate_analyst").input("Dev")
    at.text_input(key="passcode").input("orbit-42")
    at.button[0].click().run()
    assert not at.exception
    assert at.sidebar.text_input(key="analyst").value == "Dev"
    assert at.sidebar.selectbox(key="batch_id").value == at.session_state["batch_name"]


def test_sign_out_locks_the_app_again(demo_app, monkeypatch):
    monkeypatch.setenv("DEMO_PASSCODE", "orbit-42")
    at = demo_app()
    at.run()
    at.text_input(key="gate_analyst").input("Dev")
    at.text_input(key="passcode").input("orbit-42")
    at.button[0].click().run()
    assert len(at.dataframe) == 1
    at.sidebar.button(key="sign_out").click().run()
    assert not at.exception
    assert len(at.dataframe) == 0 and len(at.sidebar.text_input) == 0
    assert at.text_input(key="passcode").value == ""
    assert at.text_input(key="gate_analyst").value == ""


def test_no_passcode_prompt_when_unset(demo_app):
    at = demo_app()
    at.run()
    assert "passcode" not in at.session_state
    assert len(at.sidebar.text_input) > 0  # the normal sidebar, straight away
    assert not [b for b in at.sidebar.button if b.key == "sign_out"]  # nothing to sign out of
