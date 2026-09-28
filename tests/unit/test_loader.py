import json

import pytest

from nullpunkt.core.schema import Alert
from nullpunkt.ingestion.loader import (
    DataFileError,
    load_alerts,
    load_assets,
    write_alerts,
    write_assets,
)


def alert_line(alert_id: str, timestamp: str, **extra) -> str:
    data = {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "source": "auth",
        "rule_name": "Login",
        "severity": "low",
        "host": "WS-1",
        "message": "login",
        **extra,
    }
    return json.dumps(data)


ASSET_HEADER = "host,ip,asset_type,owner,criticality"


class TestLoadAlerts:
    def test_sorted_by_time_and_blank_lines_skipped(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        path.write_text(
            "\n".join(
                [
                    alert_line("ALR-000002", "2026-10-01T10:00:00Z"),
                    "",
                    alert_line("ALR-000001", "2026-10-01T09:00:00Z"),
                    "   ",
                ]
            )
        )
        alerts = load_alerts(path)
        assert [a.alert_id for a in alerts] == ["ALR-000001", "ALR-000002"]

    def test_equal_timestamps_ordered_by_id(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        ts = "2026-10-01T09:00:00Z"
        path.write_text(alert_line("ALR-000009", ts) + "\n" + alert_line("ALR-000003", ts))
        assert [a.alert_id for a in load_alerts(path)] == ["ALR-000003", "ALR-000009"]

    def test_invalid_json_reports_file_and_line(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        path.write_text(alert_line("ALR-000001", "2026-10-01T09:00:00Z") + "\n{not json\n")
        with pytest.raises(DataFileError, match=r"alerts\.jsonl:2: invalid JSON") as exc:
            load_alerts(path)
        assert exc.value.line == 2

    def test_schema_error_reports_file_and_line(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        path.write_text(
            alert_line("ALR-000001", "2026-10-01T09:00:00Z")
            + "\n\n"
            + alert_line("ALR-000002", "2026-10-01T09:00:00")
        )
        with pytest.raises(DataFileError, match=r"alerts\.jsonl:3: invalid Alert"):
            load_alerts(path)

    def test_label_field_in_alert_rejected(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        path.write_text(alert_line("ALR-000001", "2026-10-01T09:00:00Z", is_true_positive=True))
        with pytest.raises(DataFileError, match=":1: invalid Alert"):
            load_alerts(path)

    def test_duplicate_id_rejected(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        path.write_text(
            alert_line("ALR-000001", "2026-10-01T09:00:00Z")
            + "\n"
            + alert_line("ALR-000001", "2026-10-01T10:00:00Z")
        )
        with pytest.raises(DataFileError, match=r":2: duplicate alert_id ALR-000001 .*line 1"):
            load_alerts(path)

    def test_error_is_a_value_error(self):
        assert issubclass(DataFileError, ValueError)


class TestLoadAssets:
    def test_keyed_by_host_with_empty_cells_as_none(self, tmp_path):
        path = tmp_path / "assets.csv"
        path.write_text(
            f"{ASSET_HEADER}\nDC01,10.0.0.10,domain_controller,it,5\nLT-1,10.0.4.1,laptop,a,1\n"
        )
        assets = load_assets(path)
        assert list(assets) == ["DC01", "LT-1"]
        assert assets["DC01"].criticality == 5

    def test_bad_row_reports_file_and_line(self, tmp_path):
        path = tmp_path / "assets.csv"
        path.write_text(
            f"{ASSET_HEADER}\nDC01,10.0.0.10,domain_controller,it,5\nX,1.1.1.1,db,a,9\n"
        )
        with pytest.raises(DataFileError, match=r"assets\.csv:3: invalid Asset"):
            load_assets(path)

    def test_empty_required_cell_rejected(self, tmp_path):
        path = tmp_path / "assets.csv"
        path.write_text(f"{ASSET_HEADER}\nDC01,,domain_controller,it,5\n")
        with pytest.raises(DataFileError, match=":2:"):
            load_assets(path)

    def test_duplicate_host_rejected(self, tmp_path):
        path = tmp_path / "assets.csv"
        row = "DC01,10.0.0.10,domain_controller,it,5"
        path.write_text(f"{ASSET_HEADER}\n{row}\n{row}\n")
        with pytest.raises(DataFileError, match=":3: duplicate host DC01"):
            load_assets(path)


def test_write_then_load_round_trips(tmp_path):
    alerts = [
        Alert.model_validate(json.loads(alert_line("ALR-000001", "2026-10-01T09:00:00Z"))),
        Alert.model_validate(
            json.loads(alert_line("ALR-000002", "2026-10-01T09:05:00Z", src_ip="10.0.0.1"))
        ),
    ]
    path = tmp_path / "nested" / "dir" / "alerts.jsonl"
    write_alerts(alerts, path)
    assert load_alerts(path) == alerts

    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert all(list(line) == list(Alert.model_fields) for line in lines)
    assert lines[0]["src_ip"] is None
    assert lines[1]["src_ip"] == "10.0.0.1"


def test_write_assets_round_trips_byte_for_byte(sample_dir, tmp_path):
    assets = load_assets(sample_dir / "assets.csv")
    path = tmp_path / "out" / "assets.csv"
    write_assets(assets.values(), path)
    assert load_assets(path) == assets
    assert path.read_bytes() == (sample_dir / "assets.csv").read_bytes()
