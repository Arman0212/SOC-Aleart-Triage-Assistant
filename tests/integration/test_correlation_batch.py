"""Correlation on the seed-42 demo batch, which was held out of tuning.

Thresholds (see docs/correlation_tuning.md):
- every scenario complete (1.0);
- purity >= 0.9, except SCN-05 >= 0.05 (its user also has password-typo noise, by design);
- 50-75 incidents (the tuned result, 65, is inside the requested range);
- largest incident <= 10 %, and every incident above 5 % is one recurring activity;
- 3,000 alerts correlated in under 2 seconds.
"""

import shutil
import time

import pytest

from nullpunkt.core.config import CorrelationConfig
from nullpunkt.correlation.cli import main
from nullpunkt.correlation.engine import correlate, run_correlation
from nullpunkt.evaluation.ground_truth import load_ground_truth
from nullpunkt.evaluation.metrics import correlation_metrics, is_single_activity
from nullpunkt.evaluation.sweep_correlation import (
    GRID,
    evaluate,
    grid_neighbours,
    make_batch,
    margin_lines,
    markdown,
    sweep,
)
from nullpunkt.generator.batch import generate, write_batch
from nullpunkt.generator.config import SCENARIO_IDS, GeneratorConfig
from nullpunkt.ingestion.loader import load_alerts, load_assets

PURITY_FLOOR = {"SCN-05": 0.05}
DEFAULT_PURITY_FLOOR = 0.9


@pytest.fixture(scope="module")
def batch_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("corr") / "batch-042"
    write_batch(generate(GeneratorConfig(seed=42)), out)
    return out


@pytest.fixture(scope="module")
def data(batch_dir):
    # The pipeline side reads only alerts and assets, exactly as the CLI does.
    alerts = load_alerts(batch_dir / "alerts.jsonl")
    assets = load_assets(batch_dir / "assets.csv")
    return alerts, assets


@pytest.fixture(scope="module")
def result(data):
    alerts, assets = data
    return run_correlation(alerts, assets, CorrelationConfig())


@pytest.fixture(scope="module")
def metrics(result, batch_dir):
    return correlation_metrics(result.incidents, load_ground_truth(batch_dir / "labels.csv"))


def test_every_scenario_is_complete(metrics):
    assert sorted(metrics.scenarios) == list(SCENARIO_IDS)
    for score in metrics.scenarios.values():
        assert score.completeness == 1.0, score


def test_purity(metrics):
    for scenario_id, score in metrics.scenarios.items():
        assert score.purity >= PURITY_FLOOR.get(scenario_id, DEFAULT_PURITY_FLOOR), score


def test_incident_count_and_reduction(metrics):
    assert 50 <= metrics.incidents <= 75
    assert metrics.reduction_ratio >= 40


def test_no_catch_all_incidents(result, data, metrics):
    alerts, assets = data
    by_id = {a.alert_id: a for a in alerts}
    assert metrics.largest_share <= 0.10
    for incident in result.incidents:
        if len(incident.alert_ids) > 0.05 * len(alerts):
            assert is_single_activity(incident, by_id, assets), incident.incident_id


def test_every_alert_in_exactly_one_incident(result, data):
    alerts, _ = data
    ids = [a for inc in result.incidents for a in inc.alert_ids]
    assert sorted(ids) == sorted(a.alert_id for a in alerts)
    assert [i.incident_id for i in result.incidents] == [
        f"INC-{n:04d}" for n in range(1, len(result.incidents) + 1)
    ]
    firsts = [(i.first_seen, i.alert_ids[0]) for i in result.incidents]
    assert firsts == sorted(firsts)


def test_links_form_a_spanning_tree_per_incident(result):
    for incident in result.incidents:
        links = result.links[incident.incident_id]
        assert len(links) == len(incident.alert_ids) - 1
        members = set(incident.alert_ids)
        assert all(link.alert_id in members and link.linked_to in members for link in links)


def test_hubs_include_infrastructure_but_not_scenario_hosts(result):
    hubs = {h.entity for h in result.hubs}
    assert {"host:DC01", "host:PROXY01", "host:VULNSCAN01", "user:adm-it"} <= hubs
    assert "host:WEB02" not in hubs  # SCN-03 depends on it


def test_deterministic(data, result):
    alerts, assets = data
    again = run_correlation(list(reversed(alerts)), assets, CorrelationConfig())
    assert again.incidents == result.incidents
    assert again.links == result.links


def test_fast(data):
    alerts, assets = data
    started = time.perf_counter()
    correlate(alerts, assets, CorrelationConfig())
    assert time.perf_counter() - started < 2


def test_cli_needs_only_alerts_and_assets(batch_dir, tmp_path, capsys):
    blind = tmp_path / "blind"
    blind.mkdir()
    for name in ("alerts.jsonl", "assets.csv"):
        shutil.copy(batch_dir / name, blind / name)
    assert main(["--batch", str(blind), "--top", "3"]) == 0
    out = capsys.readouterr().out
    assert "3000 alerts -> 65 incidents" in out
    assert "Detected hubs" in out and "host:DC01" in out


TUNED = {key: getattr(CorrelationConfig(), key) for key in GRID}


def test_tuned_defaults_are_on_the_grid():
    for key, value in TUNED.items():
        assert value in GRID[key], key


@pytest.mark.parametrize(
    "perturbed",
    grid_neighbours(TUNED),
    ids=lambda p: ",".join(f"{k}={v}" for k, v in p.items() if TUNED[k] != v),
)
def test_every_scenario_survives_one_step_perturbation(batch_dir, perturbed):
    """Move each tuned parameter one grid step in each direction and check that all seven
    scenarios stay complete on seed 42, so the demo never sits on a knife edge.

    Two parameters are perturbed in one direction only, because the tuned value is the end of
    its range by nature: "no recurrence gap" (recurrence_max_gap_minutes=None) can only move to
    a finite gap, and "routine on" (hub_actor_routine=True) can only be switched off. The numeric
    thresholds (window, hub share, hub users, hub fan-out) are interior grid points and are
    perturbed both ways.

    Only completeness is asserted. Purity is not: one step up in hub users or hub fan-out keeps
    every scenario whole but merges SCN-06 or SCN-01 into noise (docs/correlation_tuning.md).
    """
    alerts = load_alerts(batch_dir / "alerts.jsonl")
    assets = load_assets(batch_dir / "assets.csv")
    labels = load_ground_truth(batch_dir / "labels.csv")
    incidents = correlate(alerts, assets, CorrelationConfig(**perturbed))
    metrics = correlation_metrics(incidents, labels)
    assert sorted(metrics.scenarios) == list(SCENARIO_IDS)
    broken = {s: v.completeness for s, v in metrics.scenarios.items() if v.completeness < 1.0}
    assert not broken, broken


def test_perturbations_cover_every_parameter_both_ways_where_possible():
    moved = {}
    for p in grid_neighbours(TUNED):
        (key,) = [k for k in p if p[k] != TUNED[k]]
        moved.setdefault(key, []).append(p[key])
    assert set(moved) == set(GRID)
    one_way = {"recurrence_max_gap_minutes", "hub_actor_routine"}
    for key, values in moved.items():
        assert len(values) == (1 if key in one_way else 2), (key, values)


def test_sweep_smoke():
    batch = make_batch(42)
    grid = {
        "window_minutes": [60, 120],
        "hub_min_share": [0.06],
        "hub_min_users": [4],
        "hub_min_fanout": [4],
        "recurrence_max_gap_minutes": [None],
        "hub_actor_routine": [True],
    }
    ranked = sweep([batch], grid)
    assert [c.params["window_minutes"] for c in ranked] == [120, 60]
    text = markdown(ranked, evaluate(batch, CorrelationConfig()))
    assert text.count("\n| ") >= 2 + 7
    assert "Held-out seed 42" in text

    margins = margin_lines([batch], CorrelationConfig())
    assert margins[2] == "| host:WEB02 | 42 | 170 | 5.7% (8%) | 3 (6) | 1 (6) | no |"
    assert "Hub-threshold margins" in markdown(
        ranked, evaluate(batch, CorrelationConfig()), 2, margins
    )
