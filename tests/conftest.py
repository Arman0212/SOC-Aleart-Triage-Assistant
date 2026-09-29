from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = REPO_ROOT / "data" / "sample"


@pytest.fixture
def sample_dir() -> Path:
    return SAMPLE_DIR


@pytest.fixture(autouse=True)
def _no_demo_passcode(monkeypatch):
    """The passcode gate is off unless a test turns it on (docs/deployment.md)."""
    monkeypatch.delenv("DEMO_PASSCODE", raising=False)
