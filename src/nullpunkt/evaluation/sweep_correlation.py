"""Tune correlation settings: python -m nullpunkt.evaluation.sweep_correlation

Tunes on generated seeds 101-105 only and reports the chosen settings on seed 42 (the demo
batch) as a held-out check. Batches are generated in memory; nothing is written unless
``--markdown`` is given.

Selection order (lexicographic):
  1. every scenario complete (completeness 1.0) on every tuning seed;
  2. every incident above 5 % of the batch is a single recurring activity, and the largest is
     at most 10 %;
  3. highest worst-case purity, excluding SCN-05 (impure by design);
  4. incident count inside 50-75 on every seed, if any setting achieves it;
  5. mean incident count closest to 60;
  6. smallest largest incident; then the order of the grid (deterministic).
"""

from __future__ import annotations

import argparse
import itertools
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path

from nullpunkt.core.config import CorrelationConfig
from nullpunkt.core.schema import Alert, Asset, GroundTruth
from nullpunkt.correlation.engine import correlate
from nullpunkt.evaluation.metrics import (
    LARGE_INCIDENT_SHARE,
    CorrelationMetrics,
    correlation_metrics,
    is_single_activity,
)
from nullpunkt.generator.batch import generate
from nullpunkt.generator.config import GeneratorConfig

TUNING_SEEDS = (101, 102, 103, 104, 105)
HELD_OUT_SEED = 42
MAX_LARGEST_SHARE = 0.10
TARGET_RANGE = (50, 75)
TARGET_COUNT = 60
BY_DESIGN_IMPURE = {"SCN-05"}

GRID: dict[str, list] = {
    "window_minutes": [30, 45, 60, 90, 120],
    "hub_min_share": [0.04, 0.06, 0.08],
    "hub_min_users": [3, 4, 6],
    "hub_min_fanout": [4, 6, 8],
    "recurrence_max_gap_minutes": [None, 120, 240],
    "hub_actor_routine": [True, False],
}


@dataclass(frozen=True)
class Batch:
    seed: int
    alerts: list[Alert]
    assets: dict[str, Asset]
    labels: dict[str, GroundTruth]


@dataclass(frozen=True)
class Evaluation:
    metrics: CorrelationMetrics
    oversized_ok: bool  # every incident > 5 % is a single activity and none exceeds 10 %

    @property
    def min_completeness(self) -> float:
        return min(s.completeness for s in self.metrics.scenarios.values())

    @property
    def min_purity(self) -> float:
        return min(
            s.purity for sid, s in self.metrics.scenarios.items() if sid not in BY_DESIGN_IMPURE
        )


@dataclass(frozen=True)
class Candidate:
    params: dict
    runs: tuple[Evaluation, ...]

    @property
    def counts(self) -> list[int]:
        return [r.metrics.incidents for r in self.runs]

    @property
    def sort_key(self) -> tuple:
        counts = self.counts
        in_range = all(TARGET_RANGE[0] <= c <= TARGET_RANGE[1] for c in counts)
        return (
            -min(r.min_completeness for r in self.runs),
            not all(r.oversized_ok for r in self.runs),
            -min(r.min_purity for r in self.runs),
            not in_range,
            abs(statistics.mean(counts) - TARGET_COUNT),
            max(r.metrics.largest_share for r in self.runs),
        )


def make_batch(seed: int) -> Batch:
    b = generate(GeneratorConfig(seed=seed))
    return Batch(seed, b.alerts, {a.host: a for a in b.assets}, {g.alert_id: g for g in b.labels})


def evaluate(batch: Batch, config: CorrelationConfig) -> Evaluation:
    incidents = correlate(batch.alerts, batch.assets, config)
    metrics = correlation_metrics(incidents, batch.labels)
    by_id = {a.alert_id: a for a in batch.alerts}
    limit = LARGE_INCIDENT_SHARE * len(batch.alerts)
    oversized_ok = metrics.largest_share <= MAX_LARGEST_SHARE and all(
        is_single_activity(inc, by_id, batch.assets)
        for inc in incidents
        if len(inc.alert_ids) > limit
    )
    return Evaluation(metrics, oversized_ok)


def sweep(batches: list[Batch], grid: dict[str, list] = GRID) -> list[Candidate]:
    candidates = []
    for values in itertools.product(*grid.values()):
        params = dict(zip(grid, values, strict=True))
        config = CorrelationConfig(**params)
        candidates.append(Candidate(params, tuple(evaluate(b, config) for b in batches)))
    # sorted() is stable, so equal keys keep grid order.
    return sorted(candidates, key=lambda c: c.sort_key)


def _fmt_params(p: dict) -> str:
    gap = p["recurrence_max_gap_minutes"]
    return (
        f"{p['window_minutes']} | {p['hub_min_share']} | {p['hub_min_users']} | "
        f"{p['hub_min_fanout']} | {'none' if gap is None else gap} | "
        f"{'on' if p['hub_actor_routine'] else 'off'}"
    )


def markdown(ranked: list[Candidate], held_out: Evaluation, top: int = 15) -> str:
    lines = [
        "| # | window (min) | hub share | hub users | hub fan-out | recurrence gap | routine "
        "| min completeness | min purity* | incidents (101-105) | largest | oversized OK |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for rank, c in enumerate(ranked[:top], start=1):
        lines.append(
            f"| {rank} | {_fmt_params(c.params)} "
            f"| {min(r.min_completeness for r in c.runs):.2f} "
            f"| {min(r.min_purity for r in c.runs):.2f} "
            f"| {min(c.counts)}-{max(c.counts)} "
            f"| {max(r.metrics.largest_share for r in c.runs):.1%} "
            f"| {'yes' if all(r.oversized_ok for r in c.runs) else 'no'} |"
        )
    lines.append("")
    lines.append("\\* excluding SCN-05, which shares its user with password-typo noise by design.")
    lines.append("")
    m = held_out.metrics
    lines.append(f"Held-out seed {HELD_OUT_SEED} with the chosen settings:")
    lines.append("")
    lines.append("| scenario | alerts | incident | incident size | completeness | purity |")
    lines.append("|---|---|---|---|---|---|")
    for s in m.scenarios.values():
        lines.append(
            f"| {s.scenario_id} | {s.alerts} | {s.incident_id} | {s.incident_size} "
            f"| {s.completeness:.2f} | {s.purity:.2f} |"
        )
    lines.append("")
    lines.append(
        f"{m.alerts} alerts, {m.incidents} incidents ({m.reduction_ratio:.1f} alerts per "
        f"incident), largest {m.largest_incident} ({m.largest_share:.1%}), oversized incidents "
        f"single-activity: {'yes' if held_out.oversized_ok else 'no'}."
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--top", type=int, default=15, help="rows to show")
    parser.add_argument("--markdown", type=Path, help="also write the tables to this file")
    args = parser.parse_args(argv)

    batches = [make_batch(seed) for seed in TUNING_SEEDS]
    ranked = sweep(batches)
    best = ranked[0]
    held_out = evaluate(make_batch(HELD_OUT_SEED), CorrelationConfig(**best.params))
    text = markdown(ranked, held_out, args.top)
    print(f"{len(ranked)} settings evaluated on seeds {', '.join(map(str, TUNING_SEEDS))}.")
    print(f"Chosen: {best.params}\n")
    print(text)
    if args.markdown:
        args.markdown.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
