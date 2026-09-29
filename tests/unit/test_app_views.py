from datetime import UTC, datetime, timedelta

import pytest

from nullpunkt.app.metrics import format_duration
from nullpunkt.app.views import (
    TIER_COLOURS,
    brief_as_text,
    evidence_rows,
    risk_bar_fraction,
    routine_lines,
    tactic_chain,
    tactic_name,
    techniques_in_kill_chain_order,
)
from nullpunkt.core.config import PipelineConfig, StorageConfig
from nullpunkt.core.schema import Alert, Brief, Technique

T0 = datetime(2026, 10, 1, 3, 30, tzinfo=UTC)  # 09:00 IST
TZ = "Asia/Kolkata"


def alert(n: int, minutes: float, rule: str, host: str = "H", user: str | None = "u") -> Alert:
    return Alert(
        alert_id=f"ALR-{n:06d}",
        timestamp=T0 + timedelta(minutes=minutes),
        source="auth",
        rule_name=rule,
        severity="low",
        host=host,
        user=user,
        message="m",
    )


def test_evidence_rows_group_bursts_and_routine_is_collapsed():
    alerts = [
        alert(1, 0, "Failed login"),
        alert(2, 1, "Failed login"),
        alert(3, 2, "Failed login", host="OTHER"),
        alert(4, 60, "Typo", user="v"),
        alert(5, 120, "Typo", user="v"),
    ]
    evidence = {"ALR-000001", "ALR-000002", "ALR-000003"}
    rows = evidence_rows(alerts, evidence, TZ)
    assert [(r["start"], r["end"], r["count"], r["host"]) for r in rows] == [
        ("09:00", "09:01", 2, "H"),
        ("09:02", "09:02", 1, "OTHER"),
    ]
    assert routine_lines(alerts, evidence, TZ) == ["2 × Typo, 10:00–11:00 IST, routine"]


def test_techniques_in_kill_chain_order():
    techniques = [
        Technique(technique_id="T1005", name="Data from Local System", tactic="collection"),
        Technique(technique_id="T1566.001", name="Spearphishing", tactic="initial-access"),
        Technique(technique_id="T1078", name="Valid Accounts", tactic="stealth"),
    ]
    ordered = techniques_in_kill_chain_order(techniques)
    assert [t.tactic for t in ordered] == ["initial-access", "stealth", "collection"]
    assert tactic_name("initial-access") == "Initial Access"
    assert tactic_chain(["initial-access", "lateral-movement", "exfiltration"]) == "IA › LM › EF"


@pytest.mark.parametrize(
    ("risk", "top", "fraction"), [(33.1, 33.1, 1.0), (0, 33.1, 0.0), (5, 0, 0.0)]
)
def test_risk_bar_is_relative_to_the_top_incident(risk, top, fraction):
    assert risk_bar_fraction(risk, top) == fraction


def test_brief_as_text():
    brief = Brief(
        summary="Line one.\nLine two.",
        affected_assets=["FINDB01"],
        techniques=["T1005"],
        timeline=["09:00 IST - x"],
        next_action="Do y.",
        confidence="high",
        generated_by="llm",
        validated=True,
    )
    assert brief_as_text(brief) == (
        "Line one.\nLine two.\n\nAffected assets: FINDB01\nTechniques: T1005\nTimeline:\n"
        "- 09:00 IST - x\nNext action: Do y."
    )


@pytest.mark.parametrize(
    ("seconds", "text"), [(None, "–"), (7.4, "7s"), (95, "1m 35s"), (3725, "1h 02m")]
)
def test_format_duration(seconds, text):
    assert format_duration(seconds) == text


def test_tier_colours_cover_every_tier():
    assert set(TIER_COLOURS) == {"P1", "P2", "P3", "P4"}


def test_storage_config_default():
    assert PipelineConfig().storage == StorageConfig(db_path="data/generated/nullpunkt.db")
