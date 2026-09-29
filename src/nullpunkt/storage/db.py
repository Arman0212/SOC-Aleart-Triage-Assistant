"""SQLite connection and versioned migrations.

Migrations are ``storage/migrations/NNN_name.sql`` files applied in order. Each applied version is
recorded in ``schema_version``, so opening an older database upgrades it in place and opening a
current one does nothing.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

MIGRATION_RE = re.compile(r"^(\d{3})_[a-z0-9_]+\.sql$")


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str


def bundled_migrations() -> list[Migration]:
    folder = files("nullpunkt.storage").joinpath("migrations")
    found = []
    for entry in folder.iterdir():
        match = MIGRATION_RE.match(entry.name)
        if match:
            found.append(Migration(int(match.group(1)), entry.name, entry.read_text("utf-8")))
    found.sort(key=lambda m: m.version)
    versions = [m.version for m in found]
    if versions != list(range(1, len(found) + 1)):
        raise RuntimeError(f"migration versions must be 1..n without gaps, got {versions}")
    return found


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (and create) the database. ``":memory:"`` gives a throwaway database."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(
        "PRAGMA journal_mode = WAL" if str(path) != ":memory:" else "PRAGMA journal_mode = MEMORY"
    )
    return conn


def current_version(conn: sqlite3.Connection) -> int:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return row[0] or 0


def migrate(conn: sqlite3.Connection, migrations: list[Migration] | None = None) -> list[int]:
    """Apply every migration newer than the database. Returns the versions applied."""
    pending = [m for m in (migrations or bundled_migrations()) if m.version > current_version(conn)]
    applied = []
    for m in pending:
        conn.execute("BEGIN")
        try:
            for statement in _statements(m.sql):
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)",
                (m.version, m.name, datetime.now(UTC).isoformat()),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        applied.append(m.version)
    return applied


def _statements(sql: str) -> list[str]:
    """Split a migration into statements, keeping trigger bodies (BEGIN ... END;) whole."""
    statements, buffer = [], []
    for line in sql.splitlines():
        stripped = line.strip()
        if not buffer and (not stripped or stripped.startswith("--")):
            continue
        buffer.append(line)
        candidate = "\n".join(buffer)
        if sqlite3.complete_statement(candidate):
            statements.append(candidate.strip())
            buffer = []
    if buffer and "\n".join(buffer).strip():
        raise ValueError("migration ends with an incomplete statement")
    return statements
