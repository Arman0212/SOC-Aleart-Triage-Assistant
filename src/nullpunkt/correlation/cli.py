"""Command line: python -m nullpunkt.correlation --batch data/generated/batch-001

Reads only alerts.jsonl and assets.csv from the batch directory.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path

from nullpunkt.core.config import load_pipeline_config
from nullpunkt.correlation.engine import run_correlation
from nullpunkt.correlation.result import CorrelationResult
from nullpunkt.ingestion.loader import load_alerts, load_assets

SIZE_BUCKETS = ((1, 1), (2, 5), (6, 20), (21, 100), (101, None))


def _bucket(size: int) -> str:
    for lo, hi in SIZE_BUCKETS:
        if hi is None and size >= lo:
            return f"{lo}+"
        if hi is not None and lo <= size <= hi:
            return f"{lo}" if lo == hi else f"{lo}-{hi}"
    raise AssertionError(size)


def _short(items: list[str], n: int = 4) -> str:
    return ", ".join(items[:n]) + (f" (+{len(items) - n})" if len(items) > n else "")


def report(result: CorrelationResult, n_alerts: int, top: int) -> str:
    incidents = result.incidents
    lines = [
        f"{n_alerts} alerts -> {len(incidents)} incidents "
        f"({n_alerts / max(len(incidents), 1):.1f} alerts per incident)",
        "",
        "Incident sizes:",
    ]
    buckets = Counter(_bucket(len(inc.alert_ids)) for inc in incidents)
    for lo, _hi in SIZE_BUCKETS:
        label = _bucket(lo)
        lines.append(f"  {label:>7} alerts: {buckets.get(label, 0)}")
    lines += ["", f"Largest {top} incidents:"]
    for inc in sorted(incidents, key=lambda i: (-len(i.alert_ids), i.incident_id))[:top]:
        reasons = Counter(link.reason for link in result.links[inc.incident_id])
        lines.append(
            f"  {inc.incident_id}  {len(inc.alert_ids):4d} alerts  "
            f"{inc.first_seen:%H:%M}-{inc.last_seen:%H:%M} UTC  hosts: {_short(inc.hosts)}  "
            f"users: {_short(inc.users) or '-'}  links: {dict(sorted(reasons.items()))}"
        )
    lines += ["", f"Detected hubs ({len(result.hubs)}):"]
    for hub in sorted(result.hubs, key=lambda h: (-h.alerts, h.entity)):
        lines.append(f"  {hub.entity:28} {hub.alerts:4d} alerts  {'; '.join(hub.reasons)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m nullpunkt.correlation", description="Correlate a batch into incidents."
    )
    parser.add_argument("--batch", required=True, type=Path, help="batch directory")
    parser.add_argument("--config", default="configs/pipeline.yaml", type=Path)
    parser.add_argument("--top", type=int, default=10, help="largest incidents to list")
    args = parser.parse_args(argv)

    config = load_pipeline_config(args.config).correlation
    alerts = load_alerts(args.batch / "alerts.jsonl")
    assets = load_assets(args.batch / "assets.csv")
    started = time.perf_counter()
    result = run_correlation(alerts, assets, config)
    elapsed = time.perf_counter() - started
    print(report(result, len(alerts), args.top))
    print(f"\ncorrelated in {elapsed:.2f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
