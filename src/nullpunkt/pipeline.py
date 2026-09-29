"""The Nullpunkt pipeline: ingest -> correlate -> map (ATT&CK) -> score -> rank -> brief.

    python -m nullpunkt.pipeline --batch data/generated/batch-001 [--briefs]

Reads only alerts.jsonl and assets.csv. Briefs (top N, Phi via Ollama, template fallback) are
optional; analyst review comes later.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path

from nullpunkt.attack.mapping import MappingResult, map_incidents
from nullpunkt.briefing.context import BriefContext
from nullpunkt.briefing.context import build_context as build_brief_context
from nullpunkt.briefing.engine import BriefCache, BriefingResult, brief_all
from nullpunkt.briefing.llm import LLMClient, OllamaClient
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
    """An incident with its rank, tier and full score detail."""

    rank: int
    tier: str
    incident: Incident  # techniques and score filled in
    detail: ScoreDetail


@dataclass
class PipelineResult:
    """Everything a run produced: the inputs, correlation, ATT&CK mapping, ranked incidents and
    optional briefs."""

    alerts: list[Alert]
    assets: dict[str, Asset]
    correlation: CorrelationResult
    mapping: MappingResult
    context: BatchContext
    ranked: list[RankedIncident]
    timings: dict[str, float]  # stage -> seconds
    briefing: BriefingResult | None = None
    brief_contexts: dict[str, BriefContext] | None = None

    def tier_counts(self) -> dict[str, int]:
        counts = Counter(r.tier for r in self.ranked)
        return {tier: counts.get(tier, 0) for tier in TIERS}


def process(
    alerts: list[Alert],
    assets: dict[str, Asset],
    config: PipelineConfig | None = None,
    briefs: bool = False,
    client: LLMClient | None = None,
) -> PipelineResult:
    """Run the pipeline in memory. With ``briefs``, brief the top N incidents using ``client``
    (the template fallback is used for every brief when ``client`` is None)."""
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
    result = PipelineResult(alerts, assets, correlation, mapping, context, ranked, timings)
    if briefs:
        t = time.perf_counter()
        _attach_briefs(result, cfg, client)
        timed("brief", t)
    return result


def _attach_briefs(result: PipelineResult, cfg: PipelineConfig, client: LLMClient | None) -> None:
    known_users = frozenset(a.user for a in result.alerts if a.user)
    alerts_by_id = {a.alert_id: a for a in result.alerts}
    top = result.ranked[: cfg.briefing.top_n]
    contexts = [
        build_brief_context(
            r.incident,
            r.detail,
            r.rank,
            r.tier,
            alerts_by_id,
            result.assets,
            result.context,
            cfg.scoring,
            cfg.site.timezone,
            known_users,
        )
        for r in top
    ]
    briefing = brief_all(contexts, client, cfg.briefing, BriefCache(cfg.briefing.cache_dir))
    result.briefing = briefing
    result.brief_contexts = {c.incident_id: c for c in contexts}
    result.ranked = [
        replace(r, incident=r.incident.model_copy(update={"brief": briefing.outcomes[iid].brief}))
        if (iid := r.incident.incident_id) in briefing.outcomes
        else r
        for r in result.ranked
    ]


def run(
    batch_dir: str | Path,
    config: PipelineConfig | None = None,
    briefs: bool = False,
    client: LLMClient | None = None,
) -> PipelineResult:
    """Run the pipeline on a batch directory (alerts.jsonl + assets.csv). With ``briefs`` and no
    ``client``, an Ollama client is created from the briefing config."""
    cfg = config or PipelineConfig()
    batch = Path(batch_dir)
    t = time.perf_counter()
    alerts = load_alerts(batch / "alerts.jsonl")
    assets = load_assets(batch / "assets.csv")
    ingest = time.perf_counter() - t
    if briefs and client is None:
        client = OllamaClient(cfg.briefing)
    result = process(alerts, assets, cfg, briefs=briefs, client=client)
    result.timings = {"ingest": ingest, **result.timings}
    return result


def report(result: PipelineResult, top: int = 10) -> str:
    """Text summary of a run: counts, tiers and the top incidents."""
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
    if result.briefing is not None:
        paths = ", ".join(f"{k} {v}" for k, v in sorted(result.briefing.paths().items()))
        lines += [
            "",
            f"Briefs ({result.briefing.model}, prompt {result.briefing.prompt_version}): "
            f"{paths}; {result.briefing.seconds:.1f}s",
        ]
        for r in result.ranked[: len(result.briefing.outcomes)]:
            outcome = result.briefing.outcomes[r.incident.incident_id]
            brief = outcome.brief
            lines += [
                "",
                f"--- {r.rank}. [{r.tier}] {r.incident.incident_id} ({brief.generated_by.value}, "
                f"{outcome.path}, confidence {brief.confidence.value})",
                *[f"  {line}" for line in brief.summary.splitlines()],
                f"  Assets: {', '.join(brief.affected_assets)}   Techniques: "
                f"{', '.join(brief.techniques)}",
                *[f"  - {entry}" for entry in brief.timeline],
                f"  Next: {brief.next_action}",
            ]
    if result.mapping.unmapped:
        lines += ["", f"Unmapped rules in {len(result.mapping.unmapped)} incidents."]
    total = sum(result.timings.values())
    stages = ", ".join(f"{k} {v:.2f}s" for k, v in result.timings.items())
    lines += ["", f"pipeline {total:.2f}s ({stages})"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point: run the pipeline on a batch and print the ranking."""
    parser = argparse.ArgumentParser(
        prog="python -m nullpunkt.pipeline",
        description="Correlate, map to ATT&CK and rank a batch; optionally brief the top ones.",
    )
    parser.add_argument("--batch", required=True, type=Path, help="batch directory")
    parser.add_argument(
        "--config", default="configs/pipeline.yaml", type=Path,
        help="pipeline config (default: configs/pipeline.yaml)",
    )  # fmt: skip
    parser.add_argument(
        "--top", type=int, default=10, help="ranked incidents to print (default: 10)"
    )
    parser.add_argument(
        "--briefs", action="store_true", help="brief the top incidents with Phi (needs Ollama)"
    )
    args = parser.parse_args(argv)
    result = run(args.batch, load_pipeline_config(args.config), briefs=args.briefs)
    print(report(result, args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
