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


def write_csv_models(models: Iterable[ContractModel], model: type[M], path: str | Path) -> None:
    """Write models as CSV with one column per field: None as an empty cell, bools as
    true/false. Uses \\n line endings so output is byte-identical on every OS."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(model.model_fields)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(fields)
        for item in models:
            row = item.model_dump(mode="json")
            writer.writerow([_csv_cell(row[f]) for f in fields])


def _csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def write_assets(assets: Iterable[Asset], path: str | Path) -> None:
    """Write assets.csv in the format ``load_assets`` reads."""
    write_csv_models(assets, Asset, path)


def write_alerts(alerts: Iterable[Alert], path: str | Path) -> None:
    """Write alerts as JSON Lines, creating parent directories as needed.

    None fields are written as null so every line has the same keys.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(alert.model_dump_json() + "\n")
