"""Where the sign-in page's shared password comes from: the environment, else .env."""

from nullpunkt.app.gate import required_passcode


def test_password_from_dotenv(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("DB_PATH=x.db\nDEMO_PASSCODE=from-file\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DEMO_PASSCODE")
    assert required_passcode() == "from-file"


def test_environment_wins_over_dotenv(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("DEMO_PASSCODE=from-file\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEMO_PASSCODE", "from-env")
    assert required_passcode() == "from-env"


def test_no_password_when_unset_or_empty(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no .env here
    monkeypatch.delenv("DEMO_PASSCODE")
    assert required_passcode() is None
    (tmp_path / ".env").write_text("DEMO_PASSCODE=\n", encoding="utf-8")
    assert required_passcode() is None
