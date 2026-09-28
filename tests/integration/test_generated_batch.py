"""End-to-end checks on a generated shift (default config: 80 hosts, 3,000 alerts, seed 42)."""

import hashlib
import json
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

import faker
import networkx as nx
import pytest

from nullpunkt.core.detection_rules import get_rule
from nullpunkt.core.schema import SCHEMA_VERSION, Severity
from nullpunkt.evaluation.ground_truth import load_ground_truth
from nullpunkt.generator.batch import generate, write_batch
from nullpunkt.generator.cli import main
from nullpunkt.generator.config import SCENARIO_IDS, GeneratorConfig
from nullpunkt.generator.messages import TEMPLATES, template_fields
from nullpunkt.ingestion.loader import load_alerts, load_assets

FILES = ("alerts.jsonl", "assets.csv", "labels.csv", "manifest.json")
BANNED = re.compile(r"attack|malicious|simulated|scenario|SCN-", re.IGNORECASE)
ENTITY_FIELDS = ("host", "user", "src_ip", "dst_ip")


@pytest.fixture(scope="module")
def batch():
    return generate(GeneratorConfig())


@pytest.fixture(scope="module")
def batch_dir(batch, tmp_path_factory):
    out = tmp_path_factory.mktemp("gen") / "batch-001"
    write_batch(batch, out)
    return out


@pytest.fixture(scope="module")
def labels(batch):
    return {g.alert_id: g for g in batch.labels}


@pytest.fixture(scope="module")
def by_scenario(batch, labels):
    groups = defaultdict(list)
    for alert in batch.alerts:
        if labels[alert.alert_id].scenario_id:
            groups[labels[alert.alert_id].scenario_id].append(alert)
    return groups


def entities(alert) -> set[str]:
    return {v for f in ENTITY_FIELDS if (v := getattr(alert, f)) is not None}


# --- determinism -------------------------------------------------------------------------------


def test_same_seed_gives_identical_bytes(batch_dir, tmp_path):
    again = tmp_path / "batch-001"
    write_batch(generate(GeneratorConfig()), again)
    for name in FILES:
        assert (again / name).read_bytes() == (batch_dir / name).read_bytes(), name


# Seed-42 digests, recorded on Python 3.14 with Faker 40.39.0. CI runs 3.11 and 3.12, so this
# catches cross-version drift (e.g. Python 3.12 changed float sum()). Update the digests only
# when you deliberately change what the generator produces.
GOLDEN_FAKER = "40.39.0"
GOLDEN_SHA256 = {
    "alerts.jsonl": "e19e69f97858bb502f4a3862dcd08f9bfd54ddf2c2fa6883dfd0ccc95032eaeb",
    "labels.csv": "418924a43d0a8deb2df1275404fc87467dae1594a8287cdbf30b8a24e326ec9e",
    "assets.csv": "8fadc659268810f89674fa984fb1b4fe46f40d83d0ab0ea6fe29f40165ff4262",
}


@pytest.mark.skipif(
    faker.VERSION != GOLDEN_FAKER, reason="digests are tied to the Faker version they came from"
)
@pytest.mark.parametrize("name", sorted(GOLDEN_SHA256))
def test_output_matches_golden_digest_on_every_python(batch_dir, name):
    digest = hashlib.sha256((batch_dir / name).read_bytes()).hexdigest()
    assert digest == GOLDEN_SHA256[name]


def test_different_seed_gives_different_output(batch_dir, tmp_path):
    other = tmp_path / "batch-001"
    write_batch(generate(GeneratorConfig(seed=43)), other)
    for name in ("alerts.jsonl", "labels.csv", "assets.csv"):
        assert (other / name).read_bytes() != (batch_dir / name).read_bytes(), name


# --- shape and validity ------------------------------------------------------------------------


@pytest.mark.parametrize("n_alerts", [500, 1234, 3000])
def test_exact_alert_count(n_alerts):
    batch = generate(GeneratorConfig(n_alerts=n_alerts))
    assert len(batch.alerts) == len(batch.labels) == n_alerts


def test_files_validate_and_match(batch, batch_dir):
    alerts = load_alerts(batch_dir / "alerts.jsonl")
    assets = load_assets(batch_dir / "assets.csv")
    labels = load_ground_truth(batch_dir / "labels.csv")
    assert alerts == batch.alerts
    assert len(assets) == 80
    assert set(labels) == {a.alert_id for a in alerts}


def test_alert_ids_are_sequential_in_time_order(batch):
    assert [a.alert_id for a in batch.alerts] == [f"ALR-{i:06d}" for i in range(1, 3001)]
    times = [a.timestamp for a in batch.alerts]
    assert times == sorted(times)


def test_timestamps_inside_shift_and_utc(batch):
    cfg = batch.config
    for alert in batch.alerts:
        assert alert.timestamp.utcoffset() == timedelta(0)
        assert cfg.shift_start_utc <= alert.timestamp < cfg.shift_end_utc


def test_every_alert_host_is_in_inventory(batch):
    hosts = {a.host for a in batch.assets}
    assert {a.host for a in batch.alerts} <= hosts


def test_manifest(batch_dir, batch):
    manifest = json.loads((batch_dir / "manifest.json").read_text())
    assert manifest["batch_id"] == "batch-001"
    assert manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["seed"] == 42
    assert manifest["company_timezone"] == "Asia/Kolkata"
    assert manifest["shift"]["start_utc"] == "2026-10-01T03:30:00Z"
    counts = manifest["counts"]
    assert counts["alerts"] == sum(counts["by_source"].values()) == 3000
    assert sum(counts["by_severity"].values()) == 3000
    assert [s["scenario_id"] for s in manifest["scenarios"]] == list(SCENARIO_IDS)
    noise_alerts = sum(n["alerts"] for n in manifest["noise"])
    assert noise_alerts + counts["true_positives"] == 3000


# --- labels ------------------------------------------------------------------------------------


def test_true_positives_have_scenario_and_catalog_technique(batch, labels):
    for alert in batch.alerts:
        label = labels[alert.alert_id]
        if label.is_true_positive:
            assert label.scenario_id is not None
            assert label.true_technique == get_rule(alert.rule_name).technique
        else:
            assert label.scenario_id is None and label.true_technique is None


def test_all_enabled_scenarios_present(by_scenario):
    assert sorted(by_scenario) == list(SCENARIO_IDS)


def test_disabled_scenarios_are_absent():
    batch = generate(GeneratorConfig(scenarios=["SCN-01", "SCN-03"], n_alerts=800))
    assert {g.scenario_id for g in batch.labels if g.scenario_id} == {"SCN-01", "SCN-03"}
    assert len(batch.alerts) == 800


# --- scenario properties -----------------------------------------------------------------------


def test_scenario_alerts_are_entity_linked_within_their_window(batch, by_scenario):
    runs = {r.scenario.scenario_id: r for r in batch.scenario_runs}
    for scenario_id, alerts in by_scenario.items():
        # Bipartite alert-entity graph: connected means every alert is reachable through
        # shared hosts, users or IPs.
        graph = nx.Graph()
        for alert in alerts:
            graph.add_node(alert.alert_id)
            graph.add_edges_from((alert.alert_id, value) for value in entities(alert))
        assert nx.is_connected(graph), scenario_id

        span = (alerts[-1].timestamp - alerts[0].timestamp).total_seconds()
        assert span <= runs[scenario_id].scenario.max_window_s, scenario_id


def test_scn01_is_low_medium_and_reaches_criticality_5(batch, by_scenario):
    crit = {a.host: a.criticality for a in batch.assets}
    scn01 = by_scenario["SCN-01"]
    assert {a.severity for a in scn01} <= {Severity.LOW, Severity.MEDIUM}
    assert any(crit[a.host] == 5 for a in scn01)
    assert "FINDB01" in {a.host for a in scn01}


def test_scn07_is_on_a_criticality_1_laptop(batch, by_scenario):
    crit = {a.host: a.criticality for a in batch.assets}
    assert any(crit[a.host] == 1 and a.host.startswith("LT-") for a in by_scenario["SCN-07"])


def test_every_scenario_rule_also_fires_as_noise(batch, labels):
    attack_rules = {a.rule_name for a in batch.alerts if labels[a.alert_id].is_true_positive}
    noise_rules = {a.rule_name for a in batch.alerts if not labels[a.alert_id].is_true_positive}
    assert attack_rules <= noise_rules


# --- purity: scenario victims stay out of the noise --------------------------------------------


def test_only_scn05_user_is_shared_with_noise_keys(batch):
    victims = {run.scenario.scenario_id: run.victims for run in batch.scenario_runs}
    noise_key_entities = {e for keys in batch.noise_keys.values() for k in keys for e in k.entities}
    scn05_user = next(r for r in batch.scenario_runs if r.scenario.scenario_id == "SCN-05")
    scn05_user = scn05_user.bindings["victim"]

    shared = {e for v in victims.values() for e in v} & noise_key_entities
    assert shared == {scn05_user}
    typo_users = {k.entities[0] for k in batch.noise_keys["password-typos"]}
    assert scn05_user in typo_users


def test_noise_alerts_never_touch_other_victims(batch, labels):
    runs = batch.scenario_runs
    scn05_user = next(r for r in runs if r.scenario.scenario_id == "SCN-05").bindings["victim"]
    victims = {e for r in runs for e in r.victims} - {scn05_user}
    for alert in batch.alerts:
        if not labels[alert.alert_id].is_true_positive:
            assert not entities(alert) & victims, alert


# --- noise structure ---------------------------------------------------------------------------


def test_noise_forms_natural_clusters(batch, labels):
    noise = [a for a in batch.alerts if not labels[a.alert_id].is_true_positive]
    assert all(a.alert_id in batch.noise_origin for a in noise)
    clusters = {batch.noise_origin[a.alert_id] for a in noise}
    assert 50 <= len(clusters) <= 70
    assert len(batch.noise_origin) == len(noise)


def test_hub_entities_appear_across_many_clusters(batch):
    clusters_by_entity = defaultdict(set)
    by_id = {a.alert_id: a for a in batch.alerts}
    for alert_id, origin in batch.noise_origin.items():
        for value in entities(by_id[alert_id]):
            clusters_by_entity[value].add(origin)
    assert len(clusters_by_entity["DC01"]) >= 10
    assert len(clusters_by_entity["PROXY01"]) >= 5


def test_business_hours_noise_peaks_in_business_hours(batch):
    cfg = batch.config
    by_id = {a.alert_id: a for a in batch.alerts}
    typo = [by_id[i] for i, (c, _) in batch.noise_origin.items() if c == "password-typos"]
    inside = sum(cfg.is_business_hours(a.timestamp) for a in typo) / len(typo)
    assert inside > 0.8


# --- no leakage --------------------------------------------------------------------------------


def test_messages_and_rule_names_do_not_leak(batch):
    for alert in batch.alerts:
        assert not BANNED.search(alert.message), alert.message
        assert not BANNED.search(alert.rule_name)


def _template_regex(template: str) -> re.Pattern[str]:
    pattern = re.escape(template)
    for name in template_fields(template):
        pattern = pattern.replace(re.escape("{" + name + "}"), ".+?")
    return re.compile(pattern + "$")


def test_noise_and_attack_messages_come_from_the_same_templates(batch, labels):
    regexes = {rule: [_template_regex(t) for t in ts] for rule, ts in TEMPLATES.items()}
    for alert in batch.alerts:
        assert any(r.match(alert.message) for r in regexes[alert.rule_name]), alert.message


# --- CLI and performance -----------------------------------------------------------------------


def test_cli_writes_a_batch(tmp_path, capsys):
    config = Path(__file__).parents[2] / "configs" / "generator.yaml"
    out = tmp_path / "cli-batch"
    assert main(["--config", str(config), "--seed", "7", "--out", str(out)]) == 0
    assert all((out / name).exists() for name in FILES)
    assert json.loads((out / "manifest.json").read_text())["seed"] == 7
    assert "3000 alerts" in capsys.readouterr().out


def test_python_dash_m_entry_point(tmp_path):
    config = Path(__file__).parents[2] / "configs" / "generator.yaml"
    out = tmp_path / "m-batch"
    result = subprocess.run(
        [sys.executable, "-m", "nullpunkt.generator", "--config", str(config), "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (out / "alerts.jsonl").exists()


def test_generating_3000_alerts_is_fast(tmp_path):
    started = time.perf_counter()
    write_batch(generate(GeneratorConfig()), tmp_path / "perf")
    assert time.perf_counter() - started < 5
