"""Load labels.csv. This is the ONLY place ground truth may be read.

Pipeline code (ingestion, correlation, scoring, attack, briefing, storage)
must never import this module; it only sees Alert and Asset.
"""

from __future__ import annotations

from pathlib import Path

from nullpunkt.core.schema import GroundTruth
from nullpunkt.ingestion.loader import DataFileError, read_csv_models


def load_ground_truth(path: str | Path) -> dict[str, GroundTruth]:
    """Load labels.csv into a dict keyed by alert_id, rejecting duplicate IDs."""
    path = Path(path)
    labels: dict[str, GroundTruth] = {}
    for line_no, label in read_csv_models(path, GroundTruth):
        if label.alert_id in labels:
            raise DataFileError(path, line_no, f"duplicate alert_id {label.alert_id}")
        labels[label.alert_id] = label
    return labels
