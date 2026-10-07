from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = REPO_ROOT / "data" / "sample"


@pytest.fixture
def sample_dir() -> Path:
    return SAMPLE_DIR


@pytest.fixture(autouse=True)
def _no_demo_passcode(monkeypatch):
    """Registration needs no team password unless a test sets one (docs/deployment.md). An empty
    value, unlike an unset one, also overrides a DEMO_PASSCODE in a developer's .env."""
    monkeypatch.setenv("DEMO_PASSCODE", "")


@pytest.fixture(autouse=True)
def _private_accounts_and_mail(tmp_path, monkeypatch):
    """Each test gets an empty accounts database and an in-memory outbox (nullpunkt.app.mail):
    no test reads a developer's accounts or sends real email, whatever .env says."""
    from nullpunkt.app import mail

    monkeypatch.setenv("ACCOUNTS_DB_PATH", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    mail.OUTBOX.clear()
