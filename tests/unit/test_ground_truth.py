import ast
from pathlib import Path

import pytest

import nullpunkt
from nullpunkt.evaluation.ground_truth import load_ground_truth, write_ground_truth
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
# core defines GroundTruth, evaluation reads labels, and the generator (offline tooling) writes
# them. Everything else is pipeline or app code and sees only Alert and Asset.
LABEL_ACCESS = {"core", "evaluation", "generator"}
# Scenario definitions are truth too, so only evaluation may look at the generator.
GENERATOR_ACCESS = {"generator", "evaluation"}
TRUTH_FILES = ("labels.csv", "manifest.json")


def imported_names(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
            names.update(alias.name for alias in node.names)
    return names


# The Streamlit scripts live outside the package, in app/ at the repo root; they are app code.
APP_ROOT = Path(__file__).parents[2] / "app"


def modules_outside(allowed: set[str]) -> list[Path]:
    package = [
        p for p in PACKAGE_ROOT.rglob("*.py") if p.relative_to(PACKAGE_ROOT).parts[0] not in allowed
    ]
    return package + sorted(APP_ROOT.rglob("*.py"))


def module_id(path: Path) -> str:
    if path.is_relative_to(APP_ROOT):
        return "repo:app/" + path.relative_to(APP_ROOT).as_posix()
    return path.relative_to(PACKAGE_ROOT).as_posix()


@pytest.mark.parametrize("path", modules_outside(LABEL_ACCESS), ids=module_id)
def test_pipeline_code_never_touches_ground_truth(path):
    """Hard rule 3: pipeline and app code never see labels."""
    names = imported_names(path)
    assert "GroundTruth" not in names
    assert not any(n.startswith("nullpunkt.evaluation") for n in names)
    text = path.read_text(encoding="utf-8")
    for name in TRUTH_FILES:
        assert name not in text


@pytest.mark.parametrize("path", modules_outside(GENERATOR_ACCESS), ids=module_id)
def test_pipeline_code_never_imports_generator(path):
    """Pipeline code (ingestion, correlation, attack, scoring, briefing, storage) and app/
    must not import the generator: its scenario definitions reveal the answers."""
    assert not any(n.startswith("nullpunkt.generator") for n in imported_names(path))


def test_guards_cover_the_app():
    """Both the app logic (src/nullpunkt/app/) and the Streamlit scripts (app/) are checked."""
    assert "app" not in LABEL_ACCESS | GENERATOR_ACCESS
    ids = {module_id(p) for p in modules_outside(LABEL_ACCESS)}
    assert {
        "repo:app/streamlit_app.py",
        "repo:app/pages/incident.py",
        "app/ui.py",
        "storage/prepare.py",
    } <= ids


def test_write_ground_truth_round_trips_byte_for_byte(sample_dir, tmp_path):
    labels = load_ground_truth(sample_dir / "labels.csv")
    path = tmp_path / "labels.csv"
    write_ground_truth(labels.values(), path)
    assert load_ground_truth(path) == labels
    assert path.read_bytes() == (sample_dir / "labels.csv").read_bytes()
