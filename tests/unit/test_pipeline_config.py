from ipaddress import IPv4Network
from pathlib import Path

import pytest
from pydantic import ValidationError

from nullpunkt.core.config import (
    CorrelationConfig,
    PipelineConfig,
    ScoringConfig,
    load_pipeline_config,
)
from nullpunkt.core.schema import AssetType

REPO_CONFIG = Path(__file__).parents[2] / "configs" / "pipeline.yaml"


def test_repo_config_matches_defaults():
    assert load_pipeline_config(REPO_CONFIG) == PipelineConfig()


def test_tuned_defaults():
    c = CorrelationConfig()
    assert (c.window_minutes, c.hub_min_share, c.hub_min_users, c.hub_min_fanout) == (
        150,
        0.08,
        6,
        6,
    )
    assert c.recurrence_max_gap_minutes is None
    assert c.hub_actor_routine is True
    assert AssetType.DOMAIN_CONTROLLER in c.hub_hint_types
    assert IPv4Network("10.0.0.0/8") in c.internal_networks


def test_empty_file_gives_defaults(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text("")
    assert load_pipeline_config(path) == PipelineConfig()


def test_partial_section_overrides(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text("correlation:\n  window_minutes: 45\n  internal_networks: [10.0.0.0/8]\n")
    c = load_pipeline_config(path).correlation
    assert c.window_minutes == 45
    assert c.internal_networks == (IPv4Network("10.0.0.0/8"),)
    assert c.hub_min_users == CorrelationConfig().hub_min_users


@pytest.mark.parametrize(
    "bad",
    [
        {"correlation": {"window_minutes": 0}},
        {"correlation": {"hub_min_share": 1.5}},
        {"correlation": {"hub_min_users": 1}},
        {"correlation": {"recurrence_min_alerts": 1}},
        {"correlation": {"hub_hint_types": ["printer"]}},
        {"correlation": {"internal_networks": ["not-a-network"]}},
        {"correlation": {"typo": 1}},
        {"unknown_section": {}},
    ],
)
def test_invalid(bad):
    with pytest.raises(ValidationError):
        PipelineConfig.model_validate(bad)


def test_sections_are_immutable():
    with pytest.raises(ValidationError):
        CorrelationConfig().window_minutes = 5  # type: ignore[misc]


def test_scoring_defaults():
    s = PipelineConfig().scoring
    assert (s.stage_step, s.tactic_cap, s.routine_min_hours, s.routine_penalty) == (1.0, 4, 3, 0.1)
    assert s.tier_thresholds == (23.0, 6.2, 3.8)
    assert AssetType.MAIL_SERVER in s.relay_asset_types


@pytest.mark.parametrize(
    "thresholds", [(5.0, 6.2, 3.8), (23.0, 6.2, 6.2), (23.0, 6.2, 0.0), (120.0, 6.2, 3.8)]
)
def test_tier_thresholds_must_descend_within_0_100(thresholds):
    with pytest.raises(ValidationError, match="tier_thresholds"):
        ScoringConfig(tier_thresholds=thresholds)
