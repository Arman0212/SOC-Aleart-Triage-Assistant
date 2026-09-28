import re

import pytest

from nullpunkt.core.detection_rules import RULES, RULES_BY_NAME, get_rule
from nullpunkt.core.schema import TECHNIQUE_PATTERN, Severity, Source
from nullpunkt.generator.config import SCENARIO_IDS
from nullpunkt.generator.messages import TEMPLATES, VOCAB, template_fields
from nullpunkt.generator.scenarios import SCENARIOS

BANNED = re.compile(r"attack|malicious|simulated|scenario|SCN-", re.IGNORECASE)


def test_rule_names_unique():
    assert len(RULES_BY_NAME) == len(RULES)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_name)
def test_rule_is_well_formed(rule):
    assert re.fullmatch(TECHNIQUE_PATTERN, rule.technique)
    assert isinstance(rule.source, Source)
    assert isinstance(rule.severity, Severity)
    assert not BANNED.search(rule.rule_name)


def test_every_source_has_rules():
    assert {r.source for r in RULES} == set(Source)


def test_port_scan_is_reconnaissance():
    assert get_rule("Port scan detected").technique == "T1595.001"


def test_unknown_rule_rejected():
    with pytest.raises(KeyError, match="unknown detection rule"):
        get_rule("Totally made up")


def test_every_rule_has_templates_and_nothing_else_does():
    assert set(TEMPLATES) == set(RULES_BY_NAME)


@pytest.mark.parametrize("rule_name", sorted(TEMPLATES))
def test_templates_only_use_known_fields_and_no_banned_words(rule_name):
    for template in TEMPLATES[rule_name]:
        for name in template_fields(template):
            assert name in VOCAB or name in {"host", "user", "src_ip", "dst_ip"}, name
        assert not BANNED.search(template)


def test_scenarios_match_config_ids_and_use_catalog_rules():
    assert tuple(s.scenario_id for s in SCENARIOS) == SCENARIO_IDS
    for scenario in SCENARIOS:
        for step in scenario.steps:
            assert step.rule in RULES_BY_NAME
            assert step.host in scenario.roles
            for role in (step.user, step.src, step.dst):
                assert role is None or role in scenario.roles


def test_scn01_rules_are_low_or_medium():
    scn01 = next(s for s in SCENARIOS if s.scenario_id == "SCN-01")
    assert {get_rule(step.rule).severity for step in scn01.steps} <= {
        Severity.LOW,
        Severity.MEDIUM,
    }


def test_scn05_and_scn07_end_with_the_same_exfiltration_rule():
    by_id = {s.scenario_id: s for s in SCENARIOS}
    assert by_id["SCN-05"].steps[-1].rule == by_id["SCN-07"].steps[-1].rule
    assert get_rule(by_id["SCN-07"].steps[-1].rule).technique == "T1567.002"


def test_only_scn05_overlaps_with_noise():
    assert [s.scenario_id for s in SCENARIOS if s.typo_overlap_role] == ["SCN-05"]
