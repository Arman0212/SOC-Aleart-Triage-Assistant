"""The demo database: a prepared seed-42 shift with Phi briefs and no analyst activity.

    nullpunkt-demo-reset                 # restore it to DB_PATH (or pipeline.yaml's db_path)
    nullpunkt-demo-reset --check         # only check that the pristine copy is untouched

``data/demo/nullpunkt-demo.db`` is committed and built by ``scripts/make_demo_db.py``. The
container copies it to local disk at every start, so a restart is a reset; the app writes only to
the copy. Restoring replaces the file, so restart a running app afterwards: it keeps its open
connection to the old file.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from pathlib import Path

from nullpunkt.core.config import PipelineConfig, load_pipeline_config
from nullpunkt.storage.db import bundled_migrations
from nullpunkt.storage.repository import resolve_db_path

DEFAULT_PRISTINE = Path("data/demo/nullpunkt-demo.db")
PRISTINE_ENV = "DEMO_PRISTINE_DB"
DEFAULT_CONFIG = Path("configs/pipeline.yaml")

# Analyst activity. A pristine database has none of it.
ACTIVITY_TABLES = ("decisions", "openings", "flags", "study_sessions")


def pristine_problems(path: str | Path) -> list[str]:
    """Why ``path`` is not a usable pristine demo database; empty if it is. Opens it read-only."""
    path = Path(path)
    if not path.is_file():
        return [f"{path} does not exist"]
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True)
    try:
        problems = []
        if (check := conn.execute("PRAGMA integrity_check").fetchone()[0]) != "ok":
            problems.append(f"integrity check failed: {check}")
        latest = bundled_migrations()[-1].version
        if (version := conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]) != (
            latest
        ):
            problems.append(f"schema version {version}, expected {latest}")
        if conn.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 0:
            problems.append("no prepared shift")
        for table in ACTIVITY_TABLES:
            if n := conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]:
                problems.append(f"{n} rows in {table}")
        if n := conn.execute("SELECT COUNT(*) FROM incidents WHERE status != 'open'").fetchone()[0]:
            problems.append(f"{n} incidents are not open")
        events = {r[0] for r in conn.execute("SELECT DISTINCT event FROM audit_log")}
        if extra := sorted(events - {"shift_prepared"}):
            problems.append(f"audit log has activity: {', '.join(extra)}")
        return problems
    except sqlite3.DatabaseError as exc:
        return [f"not a nullpunkt database: {exc}"]
    finally:
        conn.close()


def reset_demo(pristine: str | Path, target: str | Path) -> Path:
    """Replace ``target`` with a copy of ``pristine`` (checked first). The copy is written next to
    the target and moved into place, so a failed copy never leaves a half-written database."""
    if problems := pristine_problems(pristine):
        raise ValueError(f"{pristine} is not a pristine demo database: {'; '.join(problems)}")
    target = Path(target)
    if target.resolve() == Path(pristine).resolve():
        raise ValueError("the target is the pristine copy itself")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    shutil.copyfile(pristine, tmp)
    for suffix in ("-wal", "-shm"):  # SQLite side files of the old database
        Path(f"{target}{suffix}").unlink(missing_ok=True)
    os.replace(tmp, target)
    return target


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point for nullpunkt-demo-reset."""
    parser = argparse.ArgumentParser(
        prog="nullpunkt-demo-reset",
        description="Restore the pristine demo database (restart a running app afterwards).",
    )
    parser.add_argument(
        "--pristine",
        type=Path,
        help=f"pristine demo database (default: {PRISTINE_ENV} or {DEFAULT_PRISTINE})",
    )
    parser.add_argument("--db", help="database to replace (default: DB_PATH or pipeline.yaml)")
    parser.add_argument("--check", action="store_true", help="only check the pristine database")
    args = parser.parse_args(argv)

    pristine = args.pristine or Path(os.environ.get(PRISTINE_ENV) or DEFAULT_PRISTINE)
    if args.check:
        if problems := pristine_problems(pristine):
            print(f"error: {pristine}: {'; '.join(problems)}", file=sys.stderr)
            return 1
        print(f"{pristine} is pristine")
        return 0
    cfg = load_pipeline_config(DEFAULT_CONFIG) if DEFAULT_CONFIG.is_file() else PipelineConfig()
    target = resolve_db_path(cfg.storage, args.db)
    try:
        reset_demo(pristine, target)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"restored {pristine} -> {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
