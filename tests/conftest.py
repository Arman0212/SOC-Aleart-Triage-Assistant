from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = REPO_ROOT / "data" / "sample"


@pytest.fixture
def sample_dir() -> Path:
    return SAMPLE_DIR


@pytest.fixture(autouse=True)
def _no_demo_passcode(monkeypatch):
    """The sign-in page asks for no password unless a test sets one (docs/deployment.md). An empty
    value, unlike an unset one, also overrides a DEMO_PASSCODE in a developer's .env."""
    monkeypatch.setenv("DEMO_PASSCODE", "")
