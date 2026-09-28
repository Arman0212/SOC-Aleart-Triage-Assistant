"""Mapping, scoring and ranking on the seed-42 demo batch, held out of tuning.

Targets (docs/scoring_evaluation.md): SCN-01 in the top 5 while severity-only buries it; at least
6 of 7 scenarios in the top 10 and all 7 in the top 15; our mean scenario rank beats both
baselines; scenario incidents are P1/P2 and routine-only noise P3/P4; pipeline under 3 seconds.
"""

import shutil
import time

import pytest

from nullpunkt.core.config import PipelineConfig, ScoringConfig
from nullpunkt.evaluation.baselines import by_alert_count, by_severity
from nullpunkt.evaluation.ground_truth import load_ground_truth
from nullpunkt.evaluation.metrics import ranking_metrics
from nullpunkt.evaluation.sweep_scoring import (
    choose_thresholds,
    comparison_table,
    evaluate,
    prepare,
    sweep,
)
from nullpunkt.generator.batch import generate, write_batch
from nullpunkt.generator.config import SCENARIO_IDS, GeneratorConfig
from nullpunkt.pipeline import main, process, run


@pytest.fixture(scope="module")
def batch_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("score") / "batch-042"
    write_batch(generate(GeneratorConfig(seed=42)), out)
    return out


@pytest.fixture(scope="module")
def result(batch_dir):
    return run(batch_dir, PipelineConfig())


@pytest.fixture(scope="module")
def labels(batch_dir):
    return load_ground_truth(batch_dir / "labels.csv")


@pytest.fixture(scope="module")
def ordered(result):
    return [r.incident for r in result.ranked]


@pytest.fixture(scope="module")
def ours(ordered, labels):
    return ranking_metrics(ordered, labels)


@pytest.fixture(scope="module")
def baselines(result, ordered, labels):
    alerts_by_id = {a.alert_id: a for a in result.alerts}
    return {
        "severity-only": ranking_metrics(by_severity(ordered, alerts_by_id), labels),
        "alert count": ranking_metrics(by_alert_count(ordered), labels),
    }


def test_scn01_top5_while_severity_only_buries_it(ours, baselines):
    assert ours.scenario_ranks["SCN-01"] <= 5
    assert baselines["severity-only"].scenario_ranks["SCN-01"] > 15


def test_scenarios_in_top_10_and_top_15(ours):
    assert sorted(ours.scenario_ranks) == list(SCENARIO_IDS)
    assert ours.found_in_top(10) >= 6
    assert ours.found_in_top(15) == 7


def test_beats_both_baselines_on_mean_scenario_rank(ours, baselines):
    for name, baseline in baselines.items():
        assert ours.mean_rank < baseline.mean_rank, name
    assert ours.precision_at_10 > max(b.precision_at_10 for b in baselines.values())


def test_scenarios_are_p1_p2_and_routine_noise_p3_p4(result, labels):
    scenario_alerts = {g.alert_id for g in labels.values() if g.scenario_id}
    for r in result.ranked:
        is_scenario = any(a in scenario_alerts for a in r.incident.alert_ids)
        if is_scenario:
            assert r.tier in ("P1", "P2"), (r.incident.incident_id, r.tier)
        elif r.detail.routine_only:
            assert r.tier in ("P3", "P4"), (r.incident.incident_id, r.tier)
    counts = result.tier_counts()
    assert sum(counts.values()) == len(result.ranked)
    assert counts["P1"] >= 1


def test_every_incident_is_mapped_and_scored(result):
    assert result.mapping.attack_version == "19.2"
    assert result.mapping.unmapped == {}
    for r in result.ranked:
        assert r.incident.techniques, r.incident.incident_id
        assert r.incident.score is not None
        assert 0 < r.incident.score.risk_score <= 100
    assert [r.rank for r in result.ranked] == list(range(1, len(result.ranked) + 1))
    risks = [r.incident.score.risk_score for r in result.ranked]
    assert risks == sorted(risks, reverse=True)


def test_scn05_is_driven_by_the_exfiltration_not_the_typos(result, labels):
    scn05 = {g.alert_id for g in labels.values() if g.scenario_id == "SCN-05"}
    r = next(r for r in result.ranked if scn05 & set(r.incident.alert_ids))
    assert r.detail.peak_alert in scn05
    assert r.detail.asset == "FS02"
    assert len(r.incident.alert_ids) > 50  # the typos are in the incident...
    assert len(r.detail.evidence) < 15  # ...but not in its evidence


def test_quiet_shift_has_no_p1(result):
    """Tiers are fixed thresholds, not ranks: routine noise alone never becomes P1."""
    routine = [r for r in result.ranked if r.detail.routine_only]
    assert routine and all(r.tier != "P1" for r in routine)


def test_pipeline_is_fast(batch_dir):
    started = time.perf_counter()
    run(batch_dir, PipelineConfig())
    assert time.perf_counter() - started < 3


def test_deterministic(result):
    again = process(list(reversed(result.alerts)), result.assets, PipelineConfig())
    assert [r.incident for r in again.ranked] == [r.incident for r in result.ranked]
    assert [r.tier for r in again.ranked] == [r.tier for r in result.ranked]


def test_cli_needs_only_alerts_and_assets(batch_dir, tmp_path, capsys):
    blind = tmp_path / "blind"
    blind.mkdir()
    for name in ("alerts.jsonl", "assets.csv"):
        shutil.copy(batch_dir / name, blind / name)
    assert main(["--batch", str(blind)]) == 0
    out = capsys.readouterr().out
    assert "3000 alerts -> 65 incidents" in out and "ATT&CK 19.2" in out
    assert "  1. [P1]" in out and "critical asset FINDB01" in out


def test_sweep_smoke_and_held_out_table():
    prepared = [prepare(101)]
    grid = {
        "stage_step": [0.5, 1.0],
        "tactic_cap": [4],
        "routine_min_hours": [3],
        "routine_penalty": [0.1],
    }
    ranked = sweep(prepared, grid)
    assert len(ranked) == 2 and all(c.neighbours == 1 for c in ranked)
    p1, p2, p3 = choose_thresholds(ranked[0])
    assert 0 < p3 < p2 < p1 <= 100
    held = prepare(42)
    table = comparison_table(held, evaluate(held, ScoringConfig()).metrics)
    assert "| SCN-01 | 1 |" in table and "severity-only" in table
