from datetime import UTC, datetime, timedelta

import pytest

from nullpunkt.core.schema import Alert, Asset, AssetType, GroundTruth, Incident
from nullpunkt.evaluation.metrics import correlation_metrics, is_single_activity

T0 = datetime(2026, 10, 1, 9, tzinfo=UTC)


def incident(n: int, alert_numbers: list[int], users: list[str] | None = None) -> Incident:
    return Incident(
        incident_id=f"INC-{n:04d}",
        alert_ids=[f"ALR-{a:06d}" for a in alert_numbers],
        first_seen=T0,
        last_seen=T0,
        hosts=["H"],
        users=users or [],
    )


def label(n: int, scenario: str | None) -> GroundTruth:
    return GroundTruth(
        alert_id=f"ALR-{n:06d}",
        scenario_id=scenario,
        is_true_positive=scenario is not None,
        true_technique="T1078" if scenario else None,
    )


@pytest.fixture
def labels():
    scenario = {1: "SCN-01", 2: "SCN-01", 3: "SCN-01", 4: "SCN-02"}
    return {f"ALR-{n:06d}": label(n, scenario.get(n)) for n in range(1, 11)}


def test_completeness_purity_and_counts(labels):
    incidents = [incident(1, [1, 2, 5, 6]), incident(2, [3, 4, 7, 8, 9, 10])]
    m = correlation_metrics(incidents, labels)
    scn1 = m.scenarios["SCN-01"]
    assert (scn1.incident_id, scn1.captured, scn1.incident_size) == ("INC-0001", 2, 4)
    assert scn1.completeness == pytest.approx(2 / 3)
    assert scn1.purity == pytest.approx(0.5)
    assert m.scenarios["SCN-02"].completeness == 1.0
    assert m.scenarios["SCN-02"].purity == pytest.approx(1 / 6)
    assert (m.alerts, m.incidents, m.largest_incident) == (10, 2, 6)
    assert m.reduction_ratio == 5.0
    assert m.largest_share == 0.6


def test_ties_prefer_the_smaller_incident(labels):
    incidents = [incident(1, [1, 5, 6, 7, 8]), incident(2, [2, 9]), incident(3, [3, 4, 10])]
    scn1 = correlation_metrics(incidents, labels).scenarios["SCN-01"]
    assert scn1.incident_id == "INC-0002"


ASSETS = {
    host: Asset(host=host, ip=ip, asset_type=t, owner="o", criticality=2)
    for host, ip, t in (
        ("WEB", "10.0.0.1", AssetType.WEB_SERVER),
        ("WS", "10.0.0.2", AssetType.WORKSTATION),
    )
}


def alert(n: int, host: str, user: str | None = None, src: str | None = None) -> Alert:
    return Alert(
        alert_id=f"ALR-{n:06d}",
        timestamp=T0 + timedelta(minutes=n),
        source="ids",
        rule_name="Exploit attempt signature",
        severity="high",
        host=host,
        user=user,
        src_ip=src,
        message="m",
    )


def test_single_activity_by_common_target():
    alerts = {
        a.alert_id: a for a in (alert(1, "WEB", src="192.0.2.1"), alert(2, "WEB", src="192.0.2.2"))
    }
    assert is_single_activity(incident(1, [1, 2]), alerts, ASSETS)


def test_single_activity_by_common_actor_across_targets():
    # The source 10.0.0.2 is normalised to host WS, the common actor.
    alerts = {a.alert_id: a for a in (alert(1, "WEB", src="10.0.0.2"), alert(2, "WS"))}
    assert is_single_activity(incident(1, [1, 2]), alerts, ASSETS)


def test_not_single_activity_without_common_entity_or_with_two_users():
    alerts = {
        a.alert_id: a for a in (alert(1, "WEB", src="192.0.2.1"), alert(2, "WS", src="192.0.2.2"))
    }
    assert not is_single_activity(incident(1, [1, 2]), alerts, ASSETS)
    same = {a.alert_id: a for a in (alert(1, "WEB", "alice"), alert(2, "WEB", "bob"))}
    assert not is_single_activity(incident(1, [1, 2], users=["alice", "bob"]), same, ASSETS)
