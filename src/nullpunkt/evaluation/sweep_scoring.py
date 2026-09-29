"""Tune risk scoring: python -m nullpunkt.evaluation.sweep_scoring

Tunes on generated seeds 101-105 only (correlated with the tuned correlation defaults) and
reports the chosen settings on seed 42, the demo batch, as a held-out check.

Targets, per seed:
  - SCN-01 in the top 5;
  - at least 6 of the 7 scenarios in the top 10, and all 7 in the top 15;
  - lower mean scenario rank than both baselines (severity-only, alert count).

Selection order (lexicographic):
  1. meets the targets on every tuning seed;
  2. robustness: every neighbouring grid point (one parameter moved one step) also meets them;
  3. tiers are separable: every scenario incident scores above every routine-only noise
     incident, on every tuning seed;
  4. the most neighbours that meet the targets;
  5. lowest worst-case mean scenario rank;
  6. widest tier gap (lowest scenario score / highest routine-only noise score); then grid order.

Tier thresholds are then fixed from the chosen setting's tuning scores (``tier_thresholds``).
"""

from __future__ import annotations

import argparse
import itertools
import math
import statistics
import sys
from dataclasses import dataclass, replace
from pathlib import Path

from nullpunkt.core.config import CorrelationConfig, ScoringConfig
from nullpunkt.core.schema import Alert, Asset, GroundTruth, Incident
from nullpunkt.correlation.engine import correlate
from nullpunkt.evaluation.baselines import by_alert_count, by_severity
from nullpunkt.evaluation.metrics import RankingMetrics, ranking_metrics
from nullpunkt.evaluation.sweep_correlation import (
    HELD_OUT_SEED,
    TUNING_SEEDS,
    grid_neighbours,
    make_batch,
)
from nullpunkt.scoring.engine import build_context, priority_tier, rank, score_incident

GRID: dict[str, list] = {
    "stage_step": [0.5, 0.75, 1.0, 1.5],
    "tactic_cap": [3, 4, 5, 6],
    "routine_min_hours": [2, 3, 4, 5],
    "routine_penalty": [0.05, 0.1, 0.25, 0.5],
}
SCN01_TOP = 5
TOP10_MIN = 6
ALL_WITHIN = 15


@dataclass(frozen=True)
class Prepared:
    seed: int
    alerts_by_id: dict[str, Alert]
    assets: dict[str, Asset]
    labels: dict[str, GroundTruth]
    incidents: list[Incident]
    baselines: dict[str, RankingMetrics]

    @property
    def alerts(self) -> list[Alert]:
        return list(self.alerts_by_id.values())

    def scenario_incidents(self) -> set[str]:
        scenario_alerts = {g.alert_id for g in self.labels.values() if g.scenario_id}
        return {
            inc.incident_id
            for inc in self.incidents
            if any(a in scenario_alerts for a in inc.alert_ids)
        }


def prepare(seed: int) -> Prepared:
    """Generate, correlate and baseline one seed once, so the sweep only re-scores."""
    batch = make_batch(seed)
    incidents = correlate(batch.alerts, batch.assets, CorrelationConfig())
    alerts_by_id = {a.alert_id: a for a in batch.alerts}
    baselines = {
        "severity-only": ranking_metrics(by_severity(incidents, alerts_by_id), batch.labels),
        "alert count": ranking_metrics(by_alert_count(incidents), batch.labels),
    }
    return Prepared(seed, alerts_by_id, batch.assets, batch.labels, incidents, baselines)


@dataclass(frozen=True)
class Run:
    metrics: RankingMetrics
    ranked: list[Incident]
    scenario_scores: tuple[float, ...]
    routine_noise_scores: tuple[float, ...]  # routine-only incidents without scenario alerts
    ok: bool


def evaluate(p: Prepared, config: ScoringConfig) -> Run:
    """Score and rank a prepared batch with ``config`` and measure the scenario ranks."""
    context = build_context(p.alerts, p.assets, config)
    scored, routine = [], {}
    for inc in p.incidents:
        detail = score_incident(inc, p.alerts_by_id, p.assets, context, config)
        scored.append(inc.model_copy(update={"score": detail.score}))
        routine[inc.incident_id] = detail.routine_only
    ranked = rank(scored)
    metrics = ranking_metrics(ranked, p.labels)
    scenario_ids = p.scenario_incidents()
    scenario_scores = tuple(i.score.risk_score for i in ranked if i.incident_id in scenario_ids)
    routine_noise = tuple(
        i.score.risk_score
        for i in ranked
        if routine[i.incident_id] and i.incident_id not in scenario_ids
    )
    ranks = metrics.scenario_ranks
    ok = (
        ranks["SCN-01"] <= SCN01_TOP
        and metrics.found_in_top(10) >= TOP10_MIN
        and metrics.worst_rank <= ALL_WITHIN
        and all(metrics.mean_rank < b.mean_rank for b in p.baselines.values())
    )
    return Run(metrics, ranked, scenario_scores, routine_noise, ok)


@dataclass(frozen=True)
class Candidate:
    params: dict
    runs: tuple[Run, ...]
    ok_neighbours: int = 0
    neighbours: int = 0

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.runs)

    @property
    def lowest_scenario(self) -> float:
        return min(min(r.scenario_scores) for r in self.runs)

    @property
    def highest_routine(self) -> float:
        return max((max(r.routine_noise_scores, default=0.0) for r in self.runs), default=0.0)

    @property
    def tier_gap(self) -> float:
        """Ratio of the lowest scenario score to the highest routine-only noise score."""
        return self.lowest_scenario / max(self.highest_routine, 1e-9)

    @property
    def worst_mean_rank(self) -> float:
        return max(r.metrics.mean_rank for r in self.runs)

    @property
    def sort_key(self) -> tuple:
        return (
            not self.ok,
            self.ok_neighbours < self.neighbours,
            self.tier_gap <= 1,
            -self.ok_neighbours,
            self.worst_mean_rank,
            -self.tier_gap,
        )


def _key(params: dict) -> tuple:
    return tuple(sorted(params.items()))


def sweep(prepared: list[Prepared], grid: dict[str, list] = GRID) -> list[Candidate]:
    """Evaluate every grid point on every tuning seed, with its neighbourhood check."""
    candidates = []
    for values in itertools.product(*grid.values()):
        params = dict(zip(grid, values, strict=True))
        config = ScoringConfig(**params)
        candidates.append(Candidate(params, tuple(evaluate(p, config) for p in prepared)))
    ok = {_key(c.params): c.ok for c in candidates}
    scored = []
    for c in candidates:
        near = [ok[_key(n)] for n in grid_neighbours(c.params, grid)]
        scored.append(replace(c, ok_neighbours=sum(near), neighbours=len(near)))
    return sorted(scored, key=lambda c: c.sort_key)


def _round_down(x: float, step: float = 0.1) -> float:
    return math.floor(x / step) * step


def choose_thresholds(best: Candidate) -> tuple[float, float, float]:
    """P1: the upper half of scenario scores on the tuning seeds (median, rounded down).
    P2: the geometric midpoint between the highest routine-only noise score and the lowest
        scenario score, so every tuning scenario is P1/P2 and every routine incident P3/P4.
    P3: just above the highest routine-only noise score, so routine incidents are P4."""
    scenario = [s for r in best.runs for s in r.scenario_scores]
    high_routine, low_scenario = best.highest_routine, best.lowest_scenario
    if low_scenario <= high_routine:
        raise ValueError("no score separates scenarios from routine noise")
    p2 = round(math.sqrt(high_routine * low_scenario), 1)
    p3 = round(_round_down(high_routine) + 0.1, 1)
    p1 = max(float(math.floor(statistics.median(scenario))), p2 + 0.1)
    return (p1, p2, p3)


def _fmt(p: dict) -> str:
    return (
        f"{p['stage_step']} | {p['tactic_cap']} | {p['routine_min_hours']} | {p['routine_penalty']}"
    )


def tier_table(runs: list[tuple[str, Prepared, list[Incident]]], config: ScoringConfig) -> str:
    """Tier counts per seed and each scenario's tier, as Markdown."""
    lines = [
        "| seed | P1 | P2 | P3 | P4 | scenario tiers |",
        "|---|---|---|---|---|---|",
    ]
    for name, p, ranked in runs:
        tiers = [priority_tier(i.score.risk_score, config) for i in ranked]  # type: ignore[union-attr]
        counts = {t: tiers.count(t) for t in ("P1", "P2", "P3", "P4")}
        scen = p.scenario_incidents()
        scenario_tiers = sorted(
            priority_tier(i.score.risk_score, config)  # type: ignore[union-attr]
            for i in ranked
            if i.incident_id in scen
        )
        lines.append(
            f"| {name} | {counts['P1']} | {counts['P2']} | {counts['P3']} | {counts['P4']} "
            f"| {' '.join(scenario_tiers)} |"
        )
    return "\n".join(lines)


def comparison_table(p: Prepared, ours: RankingMetrics) -> str:
    """Scenario ranks under our score and the baselines, as Markdown."""
    orderings = {"our score": ours, **p.baselines}
    lines = [
        "| scenario | " + " | ".join(orderings) + " |",
        "|---|" + "---|" * len(orderings),
    ]
    for sid in sorted(ours.scenario_ranks):
        lines.append(
            f"| {sid} | "
            + " | ".join(str(m.scenario_ranks[sid]) for m in orderings.values())
            + " |"
        )
    rows = [
        ("mean scenario rank", lambda m: f"{m.mean_rank:.1f}"),
        ("scenarios in top 5", lambda m: str(m.found_in_top(5))),
        ("scenarios in top 10", lambda m: str(m.found_in_top(10))),
        ("scenarios in top 15", lambda m: str(m.found_in_top(15))),
        ("precision@10", lambda m: f"{m.precision_at_10:.1f}"),
    ]
    for label, fmt in rows:
        lines.append(f"| **{label}** | " + " | ".join(fmt(m) for m in orderings.values()) + " |")
    return "\n".join(lines)


def markdown(ranked: list[Candidate], thresholds, held: Prepared, held_run: Run, top: int) -> str:
    """The sweep results and the held-out check as Markdown tables."""
    lines = [
        "| # | stage step | tactic cap | routine hours | routine penalty | targets | "
        "neighbours OK | worst mean rank | lowest scenario | highest routine |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for n, c in enumerate(ranked[:top], start=1):
        lines.append(
            f"| {n} | {_fmt(c.params)} | {'yes' if c.ok else 'no'} | "
            f"{c.ok_neighbours}/{c.neighbours} | {c.worst_mean_rank:.2f} | "
            f"{c.lowest_scenario:.1f} | {c.highest_routine:.1f} |"
        )
    p1, p2, p3 = thresholds
    lines += ["", f"Tier thresholds: P1 ≥ {p1}, P2 ≥ {p2}, P3 ≥ {p3}, else P4.", ""]
    lines += [f"Held-out seed {HELD_OUT_SEED}:", "", comparison_table(held, held_run.metrics)]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point: run the scoring sweep and print (or write) the tables."""
    parser = argparse.ArgumentParser(
        prog="python -m nullpunkt.evaluation.sweep_scoring",
        description="Tune risk scoring on seeds 101-105 and check the held-out seed 42.",
    )
    parser.add_argument("--top", type=int, default=12, help="rows to show (default: 12)")
    parser.add_argument("--markdown", type=Path, help="also write the tables to this file")
    args = parser.parse_args(argv)

    prepared = [prepare(seed) for seed in TUNING_SEEDS]
    ranked = sweep(prepared)
    best = ranked[0]
    thresholds = choose_thresholds(best)
    chosen = ScoringConfig(**best.params, tier_thresholds=thresholds)
    held = prepare(HELD_OUT_SEED)
    held_run = evaluate(held, chosen)
    text = markdown(ranked, thresholds, held, held_run, args.top)
    runs = [(str(p.seed), p, r.ranked) for p, r in zip(prepared, best.runs, strict=True)]
    runs.append((f"{HELD_OUT_SEED} (held out)", held, held_run.ranked))
    text += "\n" + tier_table(runs, chosen) + "\n"
    print(f"{len(ranked)} settings evaluated on seeds {', '.join(map(str, TUNING_SEEDS))}.")
    print(f"Chosen: {best.params}, tier thresholds {thresholds}\n")
    print(text)
    if args.markdown:
        args.markdown.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
