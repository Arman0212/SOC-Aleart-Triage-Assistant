"""Load labels.csv. This is the ONLY place ground truth may be read.

Pipeline code (ingestion, correlation, scoring, attack, briefing, storage)
must never import this module; it only sees Alert and Asset. The generator is offline
tooling and is the only other package allowed to use it, to write labels.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from nullpunkt.core.schema import GroundTruth
from nullpunkt.ingestion.loader import DataFileError, read_csv_models, write_csv_models


def load_ground_truth(path: str | Path) -> dict[str, GroundTruth]:
    """Load labels.csv into a dict keyed by alert_id, rejecting duplicate IDs."""
    path = Path(path)
    labels: dict[str, GroundTruth] = {}
    for line_no, label in read_csv_models(path, GroundTruth):
        if label.alert_id in labels:
            raise DataFileError(path, line_no, f"duplicate alert_id {label.alert_id}")
        labels[label.alert_id] = label
    return labels


def write_ground_truth(labels: Iterable[GroundTruth], path: str | Path) -> None:
    """Write labels.csv in the format ``load_ground_truth`` reads."""
    write_csv_models(labels, GroundTruth, path)
