"""The Nullpunkt pipeline: ingest -> correlate -> map (ATT&CK) -> score -> rank.

    python -m nullpunkt.pipeline --batch data/generated/batch-001

Reads only alerts.jsonl and assets.csv. Briefing and analyst review come later.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from nullpunkt.attack.mapping import MappingResult, map_incidents
from nullpunkt.core.config import PipelineConfig, load_pipeline_config
from nullpunkt.core.schema import Alert, Asset, Incident
from nullpunkt.correlation.engine import run_correlation
from nullpunkt.correlation.result import CorrelationResult
from nullpunkt.ingestion.loader import load_alerts, load_assets
from nullpunkt.scoring.engine import (
    BatchContext,
    ScoreDetail,
    build_context,
    priority_tier,
    rank,
    score_incident,
)

TIERS = ("P1", "P2", "P3", "P4")


@dataclass(frozen=True)
class RankedIncident:
    rank: int
    tier: str
    incident: Incident  # techniques and score filled in
    detail: ScoreDetail


@dataclass
class PipelineResult:
    alerts: list[Alert]
    assets: dict[str, Asset]
    correlation: CorrelationResult
    mapping: MappingResult
    context: BatchContext
    ranked: list[RankedIncident]
    timings: dict[str, float]  # stage -> seconds

    def tier_counts(self) -> dict[str, int]:
        counts = Counter(r.tier for r in self.ranked)
        return {tier: counts.get(tier, 0) for tier in TIERS}


def process(
    alerts: list[Alert], assets: dict[str, Asset], config: PipelineConfig | None = None
) -> PipelineResult:
    cfg = config or PipelineConfig()
    timings: dict[str, float] = {}

    def timed(stage: str, started: float) -> None:
        timings[stage] = time.perf_counter() - started

    t = time.perf_counter()
    correlation = run_correlation(alerts, assets, cfg.correlation)
    timed("correlate", t)

    t = time.perf_counter()
    alerts_by_id = {a.alert_id: a for a in alerts}
    mapping = map_incidents(correlation.incidents, alerts_by_id)
    timed("map", t)

    t = time.perf_counter()
    context = build_context(alerts, assets, cfg.scoring)
    details: dict[str, ScoreDetail] = {}
    enriched = []
    for incident in correlation.incidents:
        detail = score_incident(incident, alerts_by_id, assets, context, cfg.scoring)
        details[incident.incident_id] = detail
        enriched.append(
            incident.model_copy(
                update={
                    "techniques": mapping.techniques[incident.incident_id],
                    "score": detail.score,
                }
            )
        )
    ranked = [
        RankedIncident(
            rank=n,
            tier=priority_tier(inc.score.risk_score, cfg.scoring),  # type: ignore[union-attr]
            incident=inc,
            detail=details[inc.incident_id],
        )
        for n, inc in enumerate(rank(enriched), start=1)
    ]
    timed("score", t)
    return PipelineResult(alerts, assets, correlation, mapping, context, ranked, timings)


def run(batch_dir: str | Path, config: PipelineConfig | None = None) -> PipelineResult:
    """Run the pipeline on a batch directory (alerts.jsonl + assets.csv)."""
    batch = Path(batch_dir)
    t = time.perf_counter()
    alerts = load_alerts(batch / "alerts.jsonl")
    assets = load_assets(batch / "assets.csv")
    ingest = time.perf_counter() - t
    result = process(alerts, assets, config)
    result.timings = {"ingest": ingest, **result.timings}
    return result


def report(result: PipelineResult, top: int = 10) -> str:
    n_alerts, n_inc = len(result.alerts), len(result.ranked)
    tiers = ", ".join(f"{t} {c}" for t, c in result.tier_counts().items())
    lines = [
        f"{n_alerts} alerts -> {n_inc} incidents ({tiers}); ATT&CK {result.mapping.attack_version}",
        "",
        f"Top {min(top, n_inc)}:",
    ]
    for r in result.ranked[:top]:
        inc, score = r.incident, r.incident.score
        assert score is not None
        lines.append(
            f"{r.rank:3}. [{r.tier}] {score.risk_score:5.1f}  {inc.incident_id}  "
            f"{len(inc.alert_ids)} alerts  {inc.first_seen:%H:%M}-{inc.last_seen:%H:%M} UTC"
        )
        lines.append(f"       {score.explanation}")
    if result.mapping.unmapped:
        lines += ["", f"Unmapped rules in {len(result.mapping.unmapped)} incidents."]
    total = sum(result.timings.values())
    stages = ", ".join(f"{k} {v:.2f}s" for k, v in result.timings.items())
    lines += ["", f"pipeline {total:.2f}s ({stages})"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m nullpunkt.pipeline", description="Correlate, map and rank a batch."
    )
    parser.add_argument("--batch", required=True, type=Path, help="batch directory")
    parser.add_argument("--config", default="configs/pipeline.yaml", type=Path)
    parser.add_argument("--top", type=int, default=10)
    args = parser.parse_args(argv)
    result = run(args.batch, load_pipeline_config(args.config))
    print(report(result, args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
