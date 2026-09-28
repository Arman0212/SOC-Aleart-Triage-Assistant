"""Assemble a batch from inventory, scenarios and noise, and write it to disk.

Determinism: a single ``random.Random(seed)`` and a single seeded ``Faker`` drive everything,
in a fixed order, and no wall-clock time is read. Same seed + config + Faker version gives
byte-identical files.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import faker
from faker import Faker

from nullpunkt import __version__
from nullpunkt.core.schema import SCHEMA_VERSION, Alert, Asset, GroundTruth
from nullpunkt.evaluation.ground_truth import load_ground_truth, write_ground_truth
from nullpunkt.generator.common import Clock, Draft
from nullpunkt.generator.config import GeneratorConfig
from nullpunkt.generator.inventory import build_inventory
from nullpunkt.generator.messages import render_message
from nullpunkt.generator.noise import NoiseKey, generate_noise
from nullpunkt.generator.scenarios import SCENARIOS_BY_ID, ScenarioRun, run_scenario
from nullpunkt.ingestion.loader import load_alerts, load_assets, write_alerts, write_assets


@dataclass(frozen=True)
class Batch:
    config: GeneratorConfig
    alerts: list[Alert]
    assets: list[Asset]
    labels: list[GroundTruth]
    scenario_runs: list[ScenarioRun]
    noise_keys: dict[str, list[NoiseKey]]
    noise_origin: dict[str, tuple[str, str]]  # alert_id -> (category, cluster) for noise

    def manifest(self, batch_id: str) -> dict:
        cfg = self.config
        by_id = {a.alert_id: a for a in self.alerts}
        scenario_alerts: dict[str, list[Alert]] = {}
        for label in self.labels:
            if label.scenario_id:
                scenario_alerts.setdefault(label.scenario_id, []).append(by_id[label.alert_id])
        technique = {g.alert_id: g.true_technique for g in self.labels}
        noise_counts = Counter(category for category, _ in self.noise_origin.values())
        return {
            "batch_id": batch_id,
            "schema_version": SCHEMA_VERSION,
            "generator_version": __version__,
            "faker_version": faker.VERSION,
            "seed": cfg.seed,
            "company_timezone": cfg.company_timezone,
            "shift": {
                "start_local": cfg.shift_start.isoformat(),
                "start_utc": _z(cfg.shift_start_utc),
                "end_utc": _z(cfg.shift_end_utc),
            },
            "config": cfg.model_dump(mode="json"),
            "counts": {
                "alerts": len(self.alerts),
                "assets": len(self.assets),
                "true_positives": sum(g.is_true_positive for g in self.labels),
                "by_source": _count(a.source.value for a in self.alerts),
                "by_severity": _count(a.severity.value for a in self.alerts),
            },
            "scenarios": [
                {
                    "scenario_id": run.scenario.scenario_id,
                    "name": run.scenario.name,
                    "alerts": len(alerts),
                    "first_seen": _z(alerts[0].timestamp),
                    "last_seen": _z(alerts[-1].timestamp),
                    "hosts": sorted({a.host for a in alerts}),
                    "techniques": sorted({technique[a.alert_id] for a in alerts}),
                }
                for run in self.scenario_runs
                for alerts in [scenario_alerts[run.scenario.scenario_id]]
            ],
            "noise": [
                {"category": category, "clusters": len(keys), "alerts": noise_counts[category]}
                for category, keys in self.noise_keys.items()
            ],
        }


def _z(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _count(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def generate(config: GeneratorConfig) -> Batch:
    rng = random.Random(config.seed)
    fake = Faker("en_US")
    fake.seed_instance(config.seed)

    clock = Clock(config)
    inv = build_inventory(config.n_hosts, rng, fake)

    runs: list[ScenarioRun] = []
    for scenario_id in sorted(config.scenarios):
        scenario = SCENARIOS_BY_ID[scenario_id]
        latest = clock.seconds - 1 - scenario.max_window_s
        if latest < 0:
            raise ValueError(f"{scenario_id} needs a shift of at least {scenario.max_window_s} s")
        runs.append(run_scenario(scenario, inv, rng, clock.sample(rng, "flat", latest)))
    scenario_drafts = [d for run in runs for d in run.drafts]

    overlap_ids = {run.overlap_user for run in runs if run.overlap_user}
    overlap_users = [u for u in inv.users if u.user_id in overlap_ids]
    noise_total = config.n_alerts - len(scenario_drafts)
    noise = generate_noise(noise_total, inv, rng, clock, overlap_users)

    drafts: list[Draft] = scenario_drafts + noise.drafts
    order = sorted(range(len(drafts)), key=lambda i: (drafts[i].offset, i))

    alerts: list[Alert] = []
    labels: list[GroundTruth] = []
    noise_origin: dict[str, tuple[str, str]] = {}
    start = config.shift_start_utc
    for n, i in enumerate(order, start=1):
        d = drafts[i]
        alert_id = f"ALR-{n:06d}"
        alerts.append(
            Alert(
                alert_id=alert_id,
                timestamp=start + timedelta(seconds=d.offset),
                source=d.rule.source,
                rule_name=d.rule.rule_name,
                severity=d.rule.severity,
                host=d.host,
                user=d.user,
                src_ip=d.src_ip,
                dst_ip=d.dst_ip,
                message=render_message(d, rng, fake),
            )
        )
        is_tp = d.scenario_id is not None
        labels.append(
            GroundTruth(
                alert_id=alert_id,
                scenario_id=d.scenario_id,
                is_true_positive=is_tp,
                true_technique=d.rule.technique if is_tp else None,
            )
        )
        if d.category and d.cluster:
            noise_origin[alert_id] = (d.category, d.cluster)
    return Batch(config, alerts, inv.assets, labels, runs, noise.keys, noise_origin)


def write_batch(batch: Batch, out_dir: str | Path) -> dict:
    """Write the four batch files, reload them through the loaders, and return the manifest."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_alerts(batch.alerts, out / "alerts.jsonl")
    write_assets(batch.assets, out / "assets.csv")
    write_ground_truth(batch.labels, out / "labels.csv")
    manifest = batch.manifest(out.name)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    alerts = load_alerts(out / "alerts.jsonl")
    assets = load_assets(out / "assets.csv")
    labels = load_ground_truth(out / "labels.csv")
    if alerts != sorted(batch.alerts, key=lambda a: (a.timestamp, a.alert_id)):
        raise RuntimeError("alerts.jsonl does not round-trip")
    if list(assets.values()) != batch.assets or list(labels.values()) != batch.labels:
        raise RuntimeError("assets.csv or labels.csv does not round-trip")
    return manifest
