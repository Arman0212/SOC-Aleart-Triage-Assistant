"""Load and write batch files: alerts.jsonl (one Alert per line) and assets.csv.

Every error names the offending file and line so a broken batch can be fixed
by hand. Ground truth is deliberately not handled here; see
nullpunkt.evaluation.ground_truth.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TypeVar

from pydantic import ValidationError

from nullpunkt.core.schema import Alert, Asset, ContractModel

M = TypeVar("M", bound=ContractModel)


class DataFileError(ValueError):
    """A batch file is malformed. The message starts with `path:line`."""

    def __init__(self, path: Path, line: int, reason: str) -> None:
        super().__init__(f"{path}:{line}: {reason}")
        self.path = path
        self.line = line


def _validate(model: type[M], data: object, path: Path, line: int) -> M:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise DataFileError(path, line, f"invalid {model.__name__}: {exc}") from exc


def read_csv_models(path: str | Path, model: type[M]) -> Iterator[tuple[int, M]]:
    """Yield (line number, validated model) for each CSV row. Empty cells become None."""
    path = Path(path)
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            data = {key: (value if value != "" else None) for key, value in row.items()}
            yield reader.line_num, _validate(model, data, path, reader.line_num)


def load_alerts(path: str | Path) -> list[Alert]:
    """Load alerts.jsonl, rejecting invalid lines and duplicate IDs. Sorted by time."""
    path = Path(path)
    alerts: list[Alert] = []
    seen: dict[str, int] = {}
    with path.open(encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            if not raw.strip():
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise DataFileError(path, line_no, f"invalid JSON: {exc.msg}") from exc
            alert = _validate(Alert, data, path, line_no)
            if alert.alert_id in seen:
                raise DataFileError(
                    path,
                    line_no,
                    f"duplicate alert_id {alert.alert_id} (first seen on line "
                    f"{seen[alert.alert_id]})",
                )
            seen[alert.alert_id] = line_no
            alerts.append(alert)
    alerts.sort(key=lambda a: (a.timestamp, a.alert_id))
    return alerts


def load_assets(path: str | Path) -> dict[str, Asset]:
    """Load assets.csv into a dict keyed by host, rejecting duplicate hosts."""
    path = Path(path)
    assets: dict[str, Asset] = {}
    for line_no, asset in read_csv_models(path, Asset):
        if asset.host in assets:
            raise DataFileError(path, line_no, f"duplicate host {asset.host}")
        assets[asset.host] = asset
    return assets


def write_alerts(alerts: Iterable[Alert], path: str | Path) -> None:
    """Write alerts as JSON Lines, creating parent directories as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(alert.model_dump_json(exclude_none=True) + "\n")
