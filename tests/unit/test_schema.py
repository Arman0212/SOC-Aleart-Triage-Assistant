from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from nullpunkt.core.schema import (
    SEVERITY_WEIGHT,
    Alert,
    Asset,
    AssetType,
    GroundTruth,
    Severity,
    Source,
)


def alert_data(**overrides):
    data = {
        "alert_id": "ALR-000001",
        "timestamp": "2026-10-01T09:00:00Z",
        "source": "edr",
        "rule_name": "Office application spawned PowerShell",
        "severity": "medium",
        "host": "WS-FIN-12",
        "user": "j.meyer",
        "src_ip": "10.0.3.12",
        "dst_ip": "10.0.1.20",
        "message": "WINWORD.EXE spawned powershell.exe",
    }
    data.update(overrides)
    return data


def asset_data(**overrides):
    data = {
        "host": "FINDB01",
        "ip": "10.0.1.20",
        "asset_type": "database",
        "owner": "finance",
        "criticality": 5,
    }
    data.update(overrides)
    return data


def label_data(**overrides):
    data = {
        "alert_id": "ALR-000001",
        "scenario_id": "SCN-01",
        "is_true_positive": True,
        "true_technique": "T1059.001",
    }
    data.update(overrides)
    return data


class TestAlert:
    def test_valid(self):
        alert = Alert.model_validate(alert_data())
        assert alert.source is Source.EDR
        assert alert.severity is Severity.MEDIUM
        assert alert.timestamp == datetime(2026, 10, 1, 9, tzinfo=UTC)

    def test_optional_fields_default_to_none(self):
        data = alert_data()
        for key in ("user", "src_ip", "dst_ip"):
            del data[key]
        alert = Alert.model_validate(data)
        assert alert.user is alert.src_ip is alert.dst_ip is None

    def test_ipv6_accepted(self):
        assert Alert.model_validate(alert_data(src_ip="2001:db8::1")).src_ip == "2001:db8::1"

    def test_non_utc_offset_is_aware_and_accepted(self):
        alert = Alert.model_validate(alert_data(timestamp="2026-10-01T14:30:00+05:30"))
        assert alert.timestamp.utcoffset() == timedelta(hours=5, minutes=30)
        assert alert.timestamp == datetime(2026, 10, 1, 9, tzinfo=UTC)

    @pytest.mark.parametrize("ts", ["2026-10-01T09:00:00", datetime(2026, 10, 1, 9)])
    def test_naive_timestamp_rejected(self, ts):
        with pytest.raises(ValidationError, match="timezone-aware"):
            Alert.model_validate(alert_data(timestamp=ts))

    @pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
    @pytest.mark.parametrize("bad", ["10.0.0.256", "not-an-ip", ""])
    def test_bad_ip_rejected(self, field, bad):
        with pytest.raises(ValidationError):
            Alert.model_validate(alert_data(**{field: bad}))

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError, match="extra"):
            Alert.model_validate(alert_data(is_true_positive=True))

    @pytest.mark.parametrize("bad", ["ALR-1", "ALR-0000001", "alr-000001", "INC-0001"])
    def test_bad_alert_id_rejected(self, bad):
        with pytest.raises(ValidationError):
            Alert.model_validate(alert_data(alert_id=bad))

    @pytest.mark.parametrize(
        ("field", "bad"),
        [("severity", "urgent"), ("source", "siem"), ("rule_name", ""), ("host", "")],
    )
    def test_bad_values_rejected(self, field, bad):
        with pytest.raises(ValidationError):
            Alert.model_validate(alert_data(**{field: bad}))

    def test_missing_required_field_rejected(self):
        data = alert_data()
        del data["message"]
        with pytest.raises(ValidationError):
            Alert.model_validate(data)


class TestAsset:
    def test_valid(self):
        asset = Asset.model_validate(asset_data())
        assert asset.asset_type is AssetType.DATABASE
        assert asset.criticality == 5

    @pytest.mark.parametrize("crit", [0, 6, -1])
    def test_criticality_out_of_range(self, crit):
        with pytest.raises(ValidationError):
            Asset.model_validate(asset_data(criticality=crit))

    @pytest.mark.parametrize("crit", [1, 5])
    def test_criticality_bounds_inclusive(self, crit):
        assert Asset.model_validate(asset_data(criticality=crit)).criticality == crit

    def test_bad_ip_rejected(self):
        with pytest.raises(ValidationError):
            Asset.model_validate(asset_data(ip="999.1.1.1"))

    def test_unknown_asset_type_rejected(self):
        with pytest.raises(ValidationError):
            Asset.model_validate(asset_data(asset_type="printer"))

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            Asset.model_validate(asset_data(location="Berlin"))


class TestGroundTruth:
    def test_valid_true_positive(self):
        label = GroundTruth.model_validate(label_data())
        assert label.is_true_positive
        assert label.true_technique == "T1059.001"

    def test_valid_false_positive(self):
        label = GroundTruth.model_validate(
            label_data(scenario_id=None, is_true_positive=False, true_technique=None)
        )
        assert label.scenario_id is None
        assert label.true_technique is None

    @pytest.mark.parametrize("technique", ["T1078", "T1566.001"])
    def test_technique_ids_accepted(self, technique):
        assert GroundTruth.model_validate(label_data(true_technique=technique))

    @pytest.mark.parametrize("bad", ["T123", "T1566.1", "t1566", "TA0001", "1566", "T1566.0011"])
    def test_bad_technique_rejected(self, bad):
        with pytest.raises(ValidationError):
            GroundTruth.model_validate(label_data(true_technique=bad))

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            GroundTruth.model_validate(label_data(notes="obvious"))


def test_severity_weight_covers_every_severity_in_order():
    assert set(SEVERITY_WEIGHT) == set(Severity)
    weights = [SEVERITY_WEIGHT[s] for s in Severity]
    assert weights == sorted(weights)
