from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from nullpunkt.core.schema import (
    SEVERITY_WEIGHT,
    Alert,
    Asset,
    AssetType,
    Brief,
    BriefSource,
    Confidence,
    Decision,
    DecisionAction,
    GroundTruth,
    Incident,
    IncidentStatus,
    ScoreBreakdown,
    Severity,
    Source,
    Technique,
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

    @pytest.mark.parametrize("bad", ["scenario-1", "SCN-1", "SCN-001", "scn-01", ""])
    def test_bad_scenario_id_rejected(self, bad):
        with pytest.raises(ValidationError):
            GroundTruth.model_validate(label_data(scenario_id=bad))

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            GroundTruth.model_validate(label_data(notes="obvious"))


def test_severity_weight_covers_every_severity_in_order():
    assert set(SEVERITY_WEIGHT) == set(Severity)
    weights = [SEVERITY_WEIGHT[s] for s in Severity]
    assert weights == sorted(weights)


def technique_data(**overrides):
    data = {"technique_id": "T1059.001", "name": "PowerShell", "tactic": "execution"}
    data.update(overrides)
    return data


def score_data(**overrides):
    data = {
        "severity_weight": 2,
        "asset_criticality": 5,
        "stage_multiplier": 1.5,
        "noise_penalty": 1.0,
        "risk_score": 87.5,
        "explanation": "Medium-severity lateral movement on a criticality-5 database",
    }
    data.update(overrides)
    return data


def brief_data(**overrides):
    data = {
        "summary": "Phishing led to PowerShell and bulk reads on FINDB01.",
        "affected_assets": ["WS-FIN-12", "FINDB01"],
        "techniques": ["T1566.001", "T1059.001"],
        "timeline": ["09:12 attachment delivered", "09:41 bulk read on FINDB01"],
        "next_action": "Isolate WS-FIN-12 and reset j.meyer's credentials.",
        "confidence": "high",
        "generated_by": "llm",
        "validated": True,
    }
    data.update(overrides)
    return data


def incident_data(**overrides):
    data = {
        "incident_id": "INC-0001",
        "alert_ids": ["ALR-000003", "ALR-000005"],
        "first_seen": "2026-10-01T09:12:04Z",
        "last_seen": "2026-10-01T09:41:37Z",
        "hosts": ["WS-FIN-12", "FINDB01"],
    }
    data.update(overrides)
    return data


def decision_data(**overrides):
    data = {
        "incident_id": "INC-0001",
        "action": "approve",
        "analyst": "analyst1",
        "opened_at": "2026-10-01T10:00:00Z",
        "decided_at": "2026-10-01T10:02:30Z",
    }
    data.update(overrides)
    return data


class TestTechnique:
    def test_confirmed_defaults_to_true(self):
        assert Technique.model_validate(technique_data()).confirmed is True

    def test_unconfirmed(self):
        assert Technique.model_validate(technique_data(confirmed=False)).confirmed is False

    @pytest.mark.parametrize("bad", ["T59", "T1059.01", "TA0002", "t1059", "1059"])
    def test_bad_technique_id_rejected(self, bad):
        with pytest.raises(ValidationError):
            Technique.model_validate(technique_data(technique_id=bad))

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            Technique.model_validate(technique_data(url="https://attack.mitre.org"))


class TestScoreBreakdown:
    def test_valid(self):
        score = ScoreBreakdown.model_validate(score_data())
        assert score.risk_score == 87.5

    def test_noise_penalty_defaults_to_one(self):
        data = score_data()
        del data["noise_penalty"]
        assert ScoreBreakdown.model_validate(data).noise_penalty == 1.0

    @pytest.mark.parametrize("value", [0, 100])
    def test_risk_score_bounds_inclusive(self, value):
        assert ScoreBreakdown.model_validate(score_data(risk_score=value)).risk_score == value

    @pytest.mark.parametrize("bad", [100.01, 101, -0.01, -1])
    def test_risk_score_out_of_range(self, bad):
        with pytest.raises(ValidationError):
            ScoreBreakdown.model_validate(score_data(risk_score=bad))

    @pytest.mark.parametrize(
        ("field", "ok", "bad"),
        [
            ("severity_weight", [1, 4], [0, 5]),
            ("asset_criticality", [1, 5], [0, 6]),
            ("stage_multiplier", [1.0, 3.0], [0.99, 0]),
            ("noise_penalty", [0.01, 1.0], [0, -0.5, 1.01]),
        ],
    )
    def test_component_bounds(self, field, ok, bad):
        for value in ok:
            score = ScoreBreakdown.model_validate(score_data(**{field: value}))
            assert getattr(score, field) == value
        for value in bad:
            with pytest.raises(ValidationError):
                ScoreBreakdown.model_validate(score_data(**{field: value}))


class TestBrief:
    def test_valid(self):
        brief = Brief.model_validate(brief_data())
        assert brief.confidence is Confidence.HIGH
        assert brief.generated_by is BriefSource.LLM

    @pytest.mark.parametrize(("field", "bad"), [("confidence", "certain"), ("generated_by", "gpt")])
    def test_bad_enum_rejected(self, field, bad):
        with pytest.raises(ValidationError):
            Brief.model_validate(brief_data(**{field: bad}))

    def test_missing_field_rejected(self):
        data = brief_data()
        del data["next_action"]
        with pytest.raises(ValidationError):
            Brief.model_validate(data)


class TestIncident:
    def test_defaults(self):
        incident = Incident.model_validate(incident_data())
        assert incident.status is IncidentStatus.OPEN
        assert incident.score is None
        assert incident.brief is None
        assert incident.users == incident.ips == incident.techniques == []

    def test_list_defaults_are_not_shared(self):
        a = Incident.model_validate(incident_data())
        b = Incident.model_validate(incident_data())
        a.users.append("j.meyer")
        assert b.users == []

    def test_fully_enriched(self):
        incident = Incident.model_validate(
            incident_data(
                techniques=[technique_data()],
                score=score_data(),
                brief=brief_data(),
                status="approved",
            )
        )
        assert incident.techniques[0].technique_id == "T1059.001"
        assert incident.score is not None and incident.score.risk_score == 87.5
        assert incident.status is IncidentStatus.APPROVED

    @pytest.mark.parametrize("bad", ["INC-1", "INC-00001", "inc-0001", "ALR-000001"])
    def test_bad_incident_id_rejected(self, bad):
        with pytest.raises(ValidationError):
            Incident.model_validate(incident_data(incident_id=bad))

    def test_empty_alert_ids_rejected(self):
        with pytest.raises(ValidationError):
            Incident.model_validate(incident_data(alert_ids=[]))

    @pytest.mark.parametrize("field", ["first_seen", "last_seen"])
    def test_naive_timestamp_rejected(self, field):
        with pytest.raises(ValidationError, match="timezone-aware"):
            Incident.model_validate(incident_data(**{field: "2026-10-01T09:00:00"}))

    def test_nested_models_validated(self):
        with pytest.raises(ValidationError):
            Incident.model_validate(incident_data(score=score_data(risk_score=150)))


class TestDecision:
    def test_triage_seconds(self):
        decision = Decision.model_validate(decision_data())
        assert decision.action is DecisionAction.APPROVE
        assert decision.triage_seconds == 150.0

    def test_triage_seconds_across_offsets(self):
        decision = Decision.model_validate(
            decision_data(opened_at="2026-10-01T15:30:00+05:30", decided_at="2026-10-01T10:01:00Z")
        )
        assert decision.triage_seconds == 60.0

    def test_optional_fields_default_to_none(self):
        decision = Decision.model_validate(decision_data())
        assert decision.edited_brief is None and decision.notes is None

    @pytest.mark.parametrize("field", ["opened_at", "decided_at"])
    def test_naive_timestamp_rejected(self, field):
        with pytest.raises(ValidationError, match="timezone-aware"):
            Decision.model_validate(decision_data(**{field: datetime(2026, 10, 1, 10)}))

    def test_bad_incident_id_rejected(self):
        with pytest.raises(ValidationError):
            Decision.model_validate(decision_data(incident_id="INC-12"))


@pytest.mark.parametrize(
    ("model", "data", "field"),
    [
        (Incident, incident_data, "status"),
        (Decision, decision_data, "action"),
        (Brief, brief_data, "confidence"),
        (Brief, brief_data, "generated_by"),
    ],
    ids=["IncidentStatus", "DecisionAction", "Confidence", "BriefSource"],
)
def test_new_enums_reject_unknown_values(model, data, field):
    with pytest.raises(ValidationError):
        model.model_validate(data(**{field: "unknown"}))


@pytest.mark.parametrize(
    ("enum", "values"),
    [
        (IncidentStatus, {"open", "approved", "dismissed", "escalated"}),
        (DecisionAction, {"approve", "edit", "dismiss", "escalate"}),
        (Confidence, {"low", "medium", "high"}),
        (BriefSource, {"llm", "template"}),
    ],
)
def test_enum_values(enum, values):
    assert {member.value for member in enum} == values
    with pytest.raises(ValueError):
        enum("unknown")
