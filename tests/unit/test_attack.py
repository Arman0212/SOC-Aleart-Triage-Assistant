import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nullpunkt.attack.mapping import map_incident, map_incidents
from nullpunkt.attack.reference import load_reference
from nullpunkt.core.detection_rules import RULES
from nullpunkt.core.schema import Alert, Incident

REPO = Path(__file__).parents[2]
T0 = datetime(2026, 10, 1, 9, tzinfo=UTC)


def _load_build_script():
    spec = importlib.util.spec_from_file_location(
        "build_attack_subset", REPO / "scripts" / "build_attack_subset.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- reference data ----------------------------------------------------------------------------


def test_reference_is_attack_19_2_with_15_tactics_in_kill_chain_order():
    ref = load_reference()
    assert ref.version == "19.2"
    assert "enterprise-attack-19.2.json" in ref.source
    names = [t.shortname for t in ref.tactics]
    assert len(names) == 15
    assert names[0] == "reconnaissance" and names[-1] == "impact"
    assert {"stealth", "defense-impairment"} <= set(names)
    assert "defense-evasion" not in names
    assert all(t.id.startswith("TA") for t in ref.tactics)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_name)
def test_rule_technique_and_tactic_are_official(rule):
    ref = load_reference()
    assert rule.technique in ref.techniques
    assert rule.tactic in ref.techniques[rule.technique].tactics


def test_sub_technique_parents_are_included():
    ref = load_reference()
    for tid in ref.techniques:
        assert tid.split(".")[0] in ref.techniques


def test_subset_contains_only_catalog_techniques_and_parents():
    wanted = {r.technique for r in RULES} | {r.technique.split(".")[0] for r in RULES}
    assert set(load_reference().techniques) == wanted


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_name)
def test_asset_at_risk_values(rule):
    assert rule.asset_at_risk in ("host", "source")


def test_mail_rules_resolve_past_the_gateway():
    by_name = {r.rule_name: r for r in RULES}
    for name in ("Suspicious attachment delivered", "Spam campaign blocked"):
        assert by_name[name].asset_at_risk == "source"


# --- build script (offline, synthetic bundle) --------------------------------------------------


def _bundle() -> dict:
    tactic = lambda i, short: {  # noqa: E731
        "type": "x-mitre-tactic",
        "id": f"x-mitre-tactic--{i}",
        "x_mitre_shortname": short,
        "name": short.title(),
        "external_references": [{"source_name": "mitre-attack", "external_id": f"TA{i:04d}"}],
    }
    shorts = ["reconnaissance", "initial-access", "execution", "stealth"]
    objects = [tactic(i, s) for i, s in enumerate(shorts, start=1)]
    objects.append(
        {
            "type": "x-mitre-matrix",
            "id": "x-mitre-matrix--1",
            "tactic_refs": [f"x-mitre-tactic--{i}" for i in range(1, 5)],
        }
    )
    objects.append({"type": "x-mitre-collection", "x_mitre_version": "19.2"})
    wanted = {r.technique for r in RULES} | {r.technique.split(".")[0] for r in RULES}
    for n, tid in enumerate(sorted(wanted)):
        objects.append(
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--{n}",
                "name": f"Name {tid}",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "stealth"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
                ],
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            }
        )
    objects.append(
        {
            "type": "attack-pattern",
            "id": "attack-pattern--revoked",
            "revoked": True,
            "name": "Old",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        }
    )
    return {"type": "bundle", "objects": objects}


def test_build_extracts_tactics_in_order_and_sorts_technique_tactics(tmp_path):
    build = _load_build_script().build
    subset = build(_bundle(), "19.2", "file://test")
    assert [t["shortname"] for t in subset["tactics"]] == [
        "reconnaissance",
        "initial-access",
        "execution",
        "stealth",
    ]
    assert subset["techniques"]["T1078"]["tactics"] == ["initial-access", "stealth"]
    assert "T9999" not in subset["techniques"]
    assert subset["attack_version"] == "19.2"


def test_build_rejects_version_mismatch_and_missing_techniques():
    module = _load_build_script()
    with pytest.raises(SystemExit, match="not 18.0"):
        module.build(_bundle(), "18.0", "x")
    bundle = _bundle()
    bundle["objects"] = [
        o
        for o in bundle["objects"]
        if not (o["type"] == "attack-pattern" and o["name"] == "Name T1078")
    ]
    with pytest.raises(SystemExit, match="T1078"):
        module.build(bundle, "19.2", "x")


def test_build_script_round_trips_through_json(tmp_path):
    module = _load_build_script()
    source = tmp_path / "bundle.json"
    source.write_text(json.dumps(_bundle()))
    out = tmp_path / "subset.json"
    assert module.main(["--from-file", str(source), "--out", str(out)]) == 0
    first = out.read_bytes()
    module.main(["--from-file", str(source), "--out", str(out)])
    assert out.read_bytes() == first  # deterministic


# --- mapping -----------------------------------------------------------------------------------


def alert(n: int, rule: str) -> Alert:
    return Alert(
        alert_id=f"ALR-{n:06d}",
        timestamp=T0 + timedelta(minutes=n),
        source="edr",
        rule_name=rule,
        severity="low",
        host="H",
        message="m",
    )


def incident(alerts: list[Alert]) -> Incident:
    return Incident(
        incident_id="INC-0001",
        alert_ids=[a.alert_id for a in alerts],
        first_seen=alerts[0].timestamp,
        last_seen=alerts[-1].timestamp,
        hosts=["H"],
    )


def test_techniques_ordered_by_first_appearance_and_deduplicated():
    alerts = [
        alert(1, "Suspicious attachment delivered"),
        alert(2, "Office application spawned PowerShell"),
        alert(3, "Suspicious attachment delivered"),
        alert(4, "SMB admin share access"),
    ]
    techniques = map_incident(incident(alerts), {a.alert_id: a for a in alerts})
    assert [(t.technique_id, t.tactic) for t in techniques] == [
        ("T1566.001", "initial-access"),
        ("T1059.001", "execution"),
        ("T1021.002", "lateral-movement"),
    ]
    assert all(t.confirmed for t in techniques)
    assert techniques[0].name == "Spearphishing Attachment"


def test_same_technique_in_two_tactics_is_kept_twice():
    alerts = [alert(1, "Successful login after failures"), alert(2, "Login from new source host")]
    techniques = map_incident(incident(alerts), {a.alert_id: a for a in alerts})
    assert [(t.technique_id, t.tactic) for t in techniques] == [
        ("T1078", "initial-access"),
        ("T1078", "stealth"),
    ]


def test_unknown_rules_are_reported_as_unmapped():
    alerts = [
        alert(1, "Totally new rule"),
        alert(2, "LSASS memory access"),
        alert(3, "Totally new rule"),
    ]
    inc = incident(alerts)
    result = map_incidents([inc], {a.alert_id: a for a in alerts})
    assert [t.technique_id for t in result.techniques["INC-0001"]] == ["T1003.001"]
    assert result.unmapped == {"INC-0001": {"Totally new rule": ["ALR-000001", "ALR-000003"]}}
    assert result.attack_version == "19.2"


def test_incident_with_only_unknown_rules_has_no_techniques():
    alerts = [alert(1, "Totally new rule")]
    assert map_incident(incident(alerts), {a.alert_id: a for a in alerts}) == []
