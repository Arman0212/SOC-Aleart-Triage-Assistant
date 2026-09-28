"""The sample batch in data/sample is a valid, self-consistent fixture.

SCN-01 is built so that ranking by raw severity buries the real attack under
high-severity noise, while ranking by severity x asset criticality surfaces it.
"""

import json

import pytest

from nullpunkt.core.schema import SEVERITY_WEIGHT, Alert, GroundTruth, Severity
from nullpunkt.evaluation.ground_truth import load_ground_truth
from nullpunkt.ingestion.loader import load_alerts, load_assets


@pytest.fixture
def alerts(sample_dir):
    return load_alerts(sample_dir / "alerts.jsonl")


@pytest.fixture
def assets(sample_dir):
    return load_assets(sample_dir / "assets.csv")


@pytest.fixture
def labels(sample_dir):
    return load_ground_truth(sample_dir / "labels.csv")


@pytest.fixture
def scn01(alerts, labels):
    return [a for a in alerts if labels[a.alert_id].scenario_id == "SCN-01"]


def test_fixture_loads(alerts, assets, labels):
    assert len(alerts) == 14
    assert len(assets) == 9
    assert len(labels) == len(alerts)


def test_assets_include_crown_jewels_and_laptops(assets):
    assert assets["DC01"].criticality == 5
    assert assets["FINDB01"].criticality == 5
    laptops = [a for a in assets.values() if a.asset_type == "laptop"]
    assert laptops and all(a.criticality == 1 for a in laptops)


def test_every_alert_has_exactly_one_label(alerts, labels):
    assert {a.alert_id for a in alerts} == set(labels)


def test_every_alert_host_exists_in_assets(alerts, assets):
    assert {a.host for a in alerts} <= set(assets)


def test_true_positives_have_scenario_and_technique(labels):
    true_positives = [g for g in labels.values() if g.is_true_positive]
    assert true_positives
    for label in true_positives:
        assert label.scenario_id is not None
        assert label.true_technique is not None


def test_false_positives_have_no_scenario_or_technique(labels):
    for label in labels.values():
        if not label.is_true_positive:
            assert label.scenario_id is None
            assert label.true_technique is None


def test_scn01_follows_the_kill_chain(scn01, labels):
    techniques = [labels[a.alert_id].true_technique for a in scn01]
    assert techniques == ["T1566.001", "T1059.001", "T1078", "T1021.002", "T1005"]


def test_scn01_is_low_or_medium_and_touches_a_criticality_5_host(scn01, assets):
    assert {a.severity for a in scn01} <= {Severity.LOW, Severity.MEDIUM}
    assert any(assets[a.host].criticality == 5 for a in scn01)


def test_noise_includes_high_severity_false_positives_on_low_criticality_hosts(
    alerts, assets, labels
):
    loud_noise = [
        a
        for a in alerts
        if not labels[a.alert_id].is_true_positive
        and SEVERITY_WEIGHT[a.severity] >= SEVERITY_WEIGHT[Severity.HIGH]
    ]
    assert loud_noise
    assert all(assets[a.host].criticality == 1 for a in loud_noise)


def test_asset_aware_ranking_beats_severity_ranking(alerts, assets, labels):
    """The core claim of the project, on the smallest possible batch."""

    def is_attack(alert: Alert) -> bool:
        return labels[alert.alert_id].is_true_positive

    by_severity = sorted(alerts, key=lambda a: -SEVERITY_WEIGHT[a.severity])
    by_risk = sorted(
        alerts, key=lambda a: -SEVERITY_WEIGHT[a.severity] * assets[a.host].criticality
    )

    # Severity-only: the analyst works through all the loud noise before any attack alert.
    loud = [a for a in alerts if SEVERITY_WEIGHT[a.severity] >= SEVERITY_WEIGHT[Severity.HIGH]]
    assert not any(is_attack(a) for a in by_severity[: len(loud)])

    # Severity x criticality: the attack on the finance DB is at the very top.
    assert is_attack(by_risk[0]) and is_attack(by_risk[1])
    assert {by_risk[0].host, by_risk[1].host} == {"FINDB01"}

    def first_attack_rank(ranking: list[Alert]) -> int:
        return next(i for i, a in enumerate(ranking) if is_attack(a))

    assert first_attack_rank(by_risk) < first_attack_rank(by_severity)


def test_alert_has_no_label_fields():
    label_fields = set(GroundTruth.model_fields) - {"alert_id"}
    assert not label_fields & set(Alert.model_fields)


def test_raw_alert_lines_carry_no_label_keys(sample_dir):
    text = (sample_dir / "alerts.jsonl").read_text()
    for key in ("scenario_id", "is_true_positive", "true_technique", "SCN-"):
        assert key not in text


def test_alert_lines_have_identical_keys(sample_dir):
    lines = (sample_dir / "alerts.jsonl").read_text().splitlines()
    assert all(list(json.loads(line)) == list(Alert.model_fields) for line in lines)
