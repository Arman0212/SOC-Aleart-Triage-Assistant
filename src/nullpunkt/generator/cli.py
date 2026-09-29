"""Command line: python -m nullpunkt.generator --config ... --seed ... --out ..."""

from __future__ import annotations

import argparse
import sys
import time

from nullpunkt.generator.batch import generate, write_batch
from nullpunkt.generator.config import load_config


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point for nullpunkt-generate."""
    parser = argparse.ArgumentParser(
        prog="nullpunkt-generate", description="Generate a synthetic SOC shift batch."
    )
    parser.add_argument(
        "--config",
        default="configs/generator.yaml",
        help="YAML config (default: configs/generator.yaml)",
    )
    parser.add_argument("--seed", type=int, help="override the config seed")
    parser.add_argument(
        "--out", required=True, help="output directory, e.g. data/generated/batch-001"
    )
    args = parser.parse_args(argv)

    config = load_config(args.config, seed=args.seed)
    started = time.perf_counter()
    manifest = write_batch(generate(config), args.out)
    elapsed = time.perf_counter() - started

    counts = manifest["counts"]
    print(
        f"wrote {args.out}: {counts['alerts']} alerts ({counts['true_positives']} true positives), "
        f"{counts['assets']} assets, {len(manifest['scenarios'])} scenarios, "
        f"seed {manifest['seed']}, {elapsed:.2f}s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
