"""Prepare a shift: run the pipeline (with briefs) on a batch and store everything in SQLite.

    nullpunkt-prepare-shift --batch data/generated/batch-001
    python -m nullpunkt.storage.prepare --batch data/generated/batch-001 --no-briefs

The app only reads and writes the database; it never runs correlation or the model itself.
Reads only alerts.jsonl and assets.csv from the batch directory.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from nullpunkt.briefing.llm import LLMClient
from nullpunkt.core.config import PipelineConfig, load_pipeline_config
from nullpunkt.pipeline import PipelineResult, run
from nullpunkt.storage.repository import BatchInfo, Repository, SQLiteRepository, resolve_db_path

DEFAULT_CONFIG = Path("configs/pipeline.yaml")


@dataclass(frozen=True)
class Prepared:
    batch: BatchInfo
    result: PipelineResult
    db_path: str | None = None


def prepare_shift(
    batch_dir: str | Path,
    repo: Repository,
    config: PipelineConfig | None = None,
    briefs: bool = True,
    client: LLMClient | None = None,
    replace: bool = False,
    batch_id: str | None = None,
) -> Prepared:
    cfg = config or PipelineConfig()
    batch_dir = Path(batch_dir)
    result = run(batch_dir, cfg, briefs=briefs, client=client)
    info = repo.save_shift(result, cfg, batch_id or batch_dir.name, str(batch_dir), replace=replace)
    return Prepared(info, result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nullpunkt-prepare-shift", description="Run the pipeline and store the shift."
    )
    parser.add_argument("--batch", required=True, type=Path, help="batch directory")
    parser.add_argument(
        "--config", type=Path, help="pipeline config (default: configs/pipeline.yaml if present)"
    )
    parser.add_argument("--db", help="SQLite path (default: DB_PATH or pipeline.yaml)")
    parser.add_argument("--no-briefs", action="store_true", help="skip Phi briefs")
    parser.add_argument("--replace", action="store_true", help="re-prepare an existing batch")
    args = parser.parse_args(argv)

    if args.config is not None:
        cfg = load_pipeline_config(args.config)
    elif DEFAULT_CONFIG.is_file():
        cfg = load_pipeline_config(DEFAULT_CONFIG)
    else:
        cfg = PipelineConfig()
    db_path = resolve_db_path(cfg.storage, args.db)
    repo = SQLiteRepository(db_path)
    try:
        prepared = prepare_shift(
            args.batch, repo, cfg, briefs=not args.no_briefs, replace=args.replace
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        repo.close()
    b, r = prepared.batch, prepared.result
    tiers = ", ".join(f"{t} {c}" for t, c in r.tier_counts().items())
    line = (
        f"prepared {b.batch_id} into {db_path}: {b.alert_count} alerts -> "
        f"{b.incident_count} incidents ({tiers})"
    )
    if r.briefing is not None:
        paths = ", ".join(f"{k} {v}" for k, v in sorted(r.briefing.paths().items()))
        line += f"; briefs: {paths} in {r.briefing.seconds:.1f}s"
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
