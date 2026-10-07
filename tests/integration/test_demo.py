"""The committed demo database, nullpunkt-demo-reset and the sign-in page (accounts, emailed
codes and the team password)."""

import re
import sqlite3
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from nullpunkt.app import mail
from nullpunkt.storage.accounts import AccountStore
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


# --- the app on the demo database: accounts and the sign-in page --------------------------------

PASSWORD = "correct horse"


@pytest.fixture
def demo_app(tmp_path, monkeypatch):
    reset_demo(DEMO_DB, tmp_path / "demo.db")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.chdir(REPO)
    return lambda: AppTest.from_file(APP, default_timeout=60)


def add_account(username: str = "dev", email: str = "dev@example.com") -> None:
    """A confirmed account in this test's accounts database (tests/conftest.py)."""
    with AccountStore() as store:
        store.add_confirmed(username, email, PASSWORD)


def log_in(at: AppTest, identifier: str = "dev", password: str = PASSWORD) -> AppTest:
    at.text_input(key="login_id").input(identifier)
    at.text_input(key="login_password").input(password)
    return at.button(key="login_submit").click().run()


def fill_registration(at: AppTest, username: str, email: str, team: str | None = None) -> AppTest:
    at.text_input(key="reg_username").input(username)
    at.text_input(key="reg_email").input(email)
    at.text_input(key="reg_password").input(PASSWORD)
    at.text_input(key="reg_repeat").input(PASSWORD)
    if team is not None:
        at.text_input(key="reg_team").input(team)
    return at.button(key="register_submit").click().run()


def last_code() -> str:
    """The code in the newest email of the in-memory outbox."""
    return re.search(r"\d{6}", mail.OUTBOX[-1]["Subject"]).group()


def test_demo_db_serves_the_queue(demo_app):
    add_account()
    at = demo_app()
    at.run()
    log_in(at)
    assert not at.exception
    table = at.dataframe[0].value
    assert len(table) == 65 and table["Incident"].iloc[0] == "INC-0055"


def test_the_app_opens_on_sign_in(demo_app):
    at = demo_app()
    at.run()
    assert not at.exception
    assert len(at.dataframe) == 0 and len(at.metric) == 0 and len(at.sidebar.text_input) == 0
    assert [t.key for t in at.text_input] == ["login_id", "login_password"]
    assert at.text_input(key="login_password").label == "Password"
    assert len(at.selectbox) == 0  # the shift is chosen in the sidebar after sign-in


def test_register_confirm_and_sign_in(demo_app):
    at = demo_app()
    at.run()
    at.button(key="to_register").click().run()
    fill_registration(at, "dev", "dev@example.com")
    assert not at.exception
    assert [m["To"] for m in mail.OUTBOX] == ["dev@example.com"]
    assert any("d***@example.com" in s.value for s in at.success)

    at.text_input(key="confirm_code").input("000000" if last_code() != "000000" else "111111")
    at.button(key="confirm_submit").click().run()
    assert any("Wrong code" in e.value for e in at.error)
    at.text_input(key="confirm_code").input(last_code())
    at.button(key="confirm_submit").click().run()
    assert not at.exception and len(at.dataframe) == 1  # confirming signs in
    assert any(m.value == "Signed in as **dev**" for m in at.sidebar.markdown)
    assert at.sidebar.selectbox(key="batch_id").value == "batch-042"  # the first shift
    assert "reg_password" not in at.session_state  # typed passwords are not kept


def test_wrong_password_reads_the_same_as_an_unknown_account(demo_app):
    add_account()
    at = demo_app()
    at.run()
    for identifier in ("dev", "nobody"):
        log_in(at, identifier, "wrong password")
        assert [e.value for e in at.error] == ["Wrong username or password."]
        assert len(at.dataframe) == 0


def test_an_unconfirmed_account_gets_a_code_at_sign_in(demo_app):
    with AccountStore() as store:
        store.register("dev", "dev@example.com", PASSWORD)
    at = demo_app()
    at.run()
    log_in(at, "dev@example.com")
    assert not at.exception and len(mail.OUTBOX) == 1
    assert any("Confirm your email first" in i.value for i in at.info)
    at.text_input(key="confirm_code").input(last_code())
    at.button(key="confirm_submit").click().run()
    assert len(at.dataframe) == 1


def test_forgot_password_resets_with_an_emailed_code(demo_app):
    add_account()
    at = demo_app()
    at.run()
    at.button(key="to_forgot").click().run()
    at.text_input(key="forgot_id").input("nobody@example.com")
    at.button(key="forgot_submit").click().run()
    assert mail.OUTBOX == []  # no email, but the same message as for a real account
    assert any("If an account matches" in i.value for i in at.info)

    at.button(key="reset_back").click().run()
    at.button(key="to_forgot").click().run()
    at.text_input(key="forgot_id").input("DEV@example.com")
    at.button(key="forgot_submit").click().run()
    assert [m["To"] for m in mail.OUTBOX] == ["dev@example.com"]
    at.text_input(key="reset_code").input(last_code())
    at.text_input(key="reset_password").input("new battery staple")
    at.text_input(key="reset_repeat").input("new battery staple")
    at.button(key="reset_submit").click().run()
    assert any("Password changed" in s.value for s in at.success)
    log_in(at, "dev", PASSWORD)
    assert any("Wrong username or password" in e.value for e in at.error)
    log_in(at, "dev", "new battery staple")
    assert len(at.dataframe) == 1


def test_team_password_guards_registration_only(demo_app, monkeypatch):
    monkeypatch.setenv("DEMO_PASSCODE", "orbit-42")
    add_account()
    at = demo_app()
    at.run()
    log_in(at)  # signing in needs only the account's own password
    assert len(at.dataframe) == 1

    at = demo_app()
    at.run()
    at.button(key="to_register").click().run()
    fill_registration(at, "eve", "eve@example.com", team="wrong")
    assert any("Wrong team password" in e.value for e in at.error)
    assert mail.OUTBOX == []
    fill_registration(at, "eve", "eve@example.com", team="orbit-42")
    assert [m["To"] for m in mail.OUTBOX] == ["eve@example.com"]


def test_registration_needs_email_to_be_set_up(demo_app, monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "")
    monkeypatch.setenv("SMTP_USER", "")
    at = demo_app()
    at.run()
    at.button(key="to_register").click().run()
    fill_registration(at, "dev", "dev@example.com")
    assert any("Email isn't set up" in e.value for e in at.error)
    with AccountStore() as store:
        assert store.account("dev") is None  # nothing half-created


def test_sign_out_returns_to_the_sign_in_page(demo_app):
    add_account()
    at = demo_app()
    at.run()
    log_in(at)
    assert len(at.dataframe) == 1
    at.sidebar.button(key="sign_out").click().run()
    assert not at.exception
    assert len(at.dataframe) == 0 and len(at.sidebar.button) == 0
    assert at.text_input(key="login_id").value == ""
    assert at.text_input(key="login_password").value == ""
