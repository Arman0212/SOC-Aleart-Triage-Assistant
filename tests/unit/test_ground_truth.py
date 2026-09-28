import ast
from pathlib import Path

import pytest

import nullpunkt
from nullpunkt.evaluation.ground_truth import load_ground_truth
from nullpunkt.ingestion.loader import DataFileError

HEADER = "alert_id,scenario_id,is_true_positive,true_technique"


def test_loads_true_and_false_positives(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text(f"{HEADER}\nALR-000001,SCN-01,true,T1078\nALR-000002,,false,\n")
    labels = load_ground_truth(path)
    assert labels["ALR-000001"].is_true_positive is True
    assert labels["ALR-000001"].true_technique == "T1078"
    fp = labels["ALR-000002"]
    assert fp.is_true_positive is False
    assert fp.scenario_id is None and fp.true_technique is None


def test_bad_technique_reports_file_and_line(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text(f"{HEADER}\nALR-000001,SCN-01,true,T12\n")
    with pytest.raises(DataFileError, match=r"labels\.csv:2: invalid GroundTruth"):
        load_ground_truth(path)


def test_bad_boolean_rejected(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text(f"{HEADER}\nALR-000001,,maybe,\n")
    with pytest.raises(DataFileError, match=":2:"):
        load_ground_truth(path)


def test_duplicate_alert_id_rejected(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text(f"{HEADER}\nALR-000001,,false,\nALR-000001,,false,\n")
    with pytest.raises(DataFileError, match=":3: duplicate alert_id"):
        load_ground_truth(path)


PACKAGE_ROOT = Path(nullpunkt.__file__).parent
# core defines GroundTruth; evaluation is the only package allowed to use it.
ALLOWED = {"core", "evaluation"}


def imported_names(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
            names.update(alias.name for alias in node.names)
    return names


@pytest.mark.parametrize(
    "path",
    [p for p in PACKAGE_ROOT.rglob("*.py") if p.relative_to(PACKAGE_ROOT).parts[0] not in ALLOWED],
    ids=lambda p: str(p.relative_to(PACKAGE_ROOT)),
)
def test_pipeline_code_never_touches_ground_truth(path):
    """Hard rule 2: only nullpunkt.evaluation may read labels."""
    names = imported_names(path)
    assert "GroundTruth" not in names
    assert not any(n.startswith("nullpunkt.evaluation") for n in names)
    assert "labels.csv" not in path.read_text()
