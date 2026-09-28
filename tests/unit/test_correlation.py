import random
from datetime import UTC, datetime, timedelta

import pytest

from nullpunkt.core.config import CorrelationConfig
from nullpunkt.core.schema import Alert, Asset, AssetType
from nullpunkt.correlation.engine import correlate, run_correlation
from nullpunkt.correlation.result import Link

T0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def _asset(host: str, ip: str, asset_type: AssetType, criticality: int) -> Asset:
    return Asset(host=host, ip=ip, asset_type=asset_type, owner="owner", criticality=criticality)


ASSETS = {
    a.host: a
    for a in (
        _asset("DC01", "10.10.0.10", AssetType.DOMAIN_CONTROLLER, 5),
        _asset("SRV", "10.10.0.20", AssetType.DATABASE, 5),
        _asset("WEB", "10.20.0.10", AssetType.WEB_SERVER, 3),
        _asset("VPN01", "10.20.0.5", AssetType.VPN_GATEWAY, 4),
        _asset("WS-1", "10.30.0.1", AssetType.WORKSTATION, 2),
        _asset("WS-2", "10.30.0.2", AssetType.WORKSTATION, 2),
        _asset("WS-3", "10.30.0.3", AssetType.WORKSTATION, 2),
    )
}


class Factory:
    def __init__(self) -> None:
        self.n = 0

    def __call__(
        self,
        minutes: float,
        rule: str,
        host: str,
        user: str | None = None,
        src: str | None = None,
        dst: str | None = None,
    ) -> Alert:
        self.n += 1
        return Alert(
            alert_id=f"ALR-{self.n:06d}",
            timestamp=T0 + timedelta(minutes=minutes),
            source="edr",
            rule_name=rule,
            severity="low",
            host=host,
            user=user,
            src_ip=src,
            dst_ip=dst,
            message="test",
        )


@pytest.fixture
def mk():
    return Factory()


def cfg(**overrides) -> CorrelationConfig:
    """Data-driven hub criteria off by default; inventory hints (DC01) stay on."""
    base = {"hub_min_share": 1.0, "hub_min_users": 50, "hub_min_fanout": 50, "window_minutes": 60}
    return CorrelationConfig(**{**base, **overrides})


def groups(incidents) -> list[list[str]]:
    return [inc.alert_ids for inc in incidents]


# --- linking window ----------------------------------------------------------------------------


def test_links_within_window(mk):
    a = mk(0, "Office application spawned PowerShell", "WS-1", "alice")
    b = mk(45, "LSASS memory access", "WS-1", "alice")
    assert groups(correlate([a, b], ASSETS, cfg())) == [[a.alert_id, b.alert_id]]


def test_no_link_outside_window(mk):
    a = mk(0, "Office application spawned PowerShell", "WS-1", "alice")
    b = mk(61, "LSASS memory access", "WS-1", "alice")
    assert groups(correlate([a, b], ASSETS, cfg())) == [[a.alert_id], [b.alert_id]]


def test_chaining_links_through_intermediate_alerts(mk):
    alerts = [mk(i * 50, "Large archive created", "WS-1", "alice") for i in range(4)]
    # 150 minutes end to end, but each step is 50 minutes; same rule also recurs.
    result = run_correlation(alerts, ASSETS, cfg(recurrence_min_alerts=99))
    assert len(result.incidents) == 1
    assert {link.reason for link in result.links["INC-0001"]} == {"entity"}


# --- hubs --------------------------------------------------------------------------------------


def test_hub_does_not_link_on_its_own(mk):
    # DC01 is a domain controller, so it is a hub by inventory hint.
    a = mk(0, "Failed login", "DC01", "alice", "10.30.0.1", "10.10.0.10")
    b = mk(5, "Account lockout", "DC01", "bob", "10.30.0.2", "10.10.0.10")
    result = run_correlation([a, b], ASSETS, cfg())
    assert len(result.incidents) == 2
    assert "host:DC01" in {h.entity for h in result.hubs}


def test_alert_on_hub_joins_through_other_entities(mk):
    a = mk(0, "Failed login", "DC01", "alice", "10.30.0.1", "10.10.0.10")
    b = mk(5, "Account lockout", "DC01", "bob", "10.30.0.2", "10.10.0.10")
    c = mk(10, "Office application spawned PowerShell", "WS-1", "alice")
    incidents = correlate([a, b, c], ASSETS, cfg())
    assert groups(incidents) == [[a.alert_id, c.alert_id], [b.alert_id]]


def test_hub_actor_does_not_link_on_its_own(mk):
    # adm-x acts on 3 hosts, so it is a fan-out hub; with the routine merge off, its alerts
    # must not link through the account even when they are minutes apart.
    alerts = [
        mk(0, "SMB admin share access", "WS-1", "adm-x"),
        mk(5, "Remote service creation", "WS-2", "adm-x"),
        mk(10, "Account enumeration via net.exe", "WS-3", "adm-x"),
    ]
    config = cfg(hub_min_fanout=3, hub_actor_routine=False)
    result = run_correlation(alerts, ASSETS, config)
    assert "user:adm-x" in {h.entity for h in result.hubs}
    assert len(result.incidents) == 3


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"hub_min_share": 0.5, "hub_min_alerts": 3}, "of alerts"),
        ({"hub_min_users": 3}, "shared by 3 users"),
        ({"hub_min_fanout": 3}, "acts on 3 hosts"),
    ],
)
def test_data_driven_hub_criteria(mk, overrides, reason):
    alerts = [
        mk(0, "SMB admin share access", "WS-1", "alice", "10.10.0.20"),
        mk(1, "SMB admin share access", "WS-2", "bob", "10.10.0.20"),
        mk(2, "SMB admin share access", "WS-3", "carol", "10.10.0.20"),
    ]
    hubs = {h.entity: h for h in run_correlation(alerts, ASSETS, cfg(**overrides)).hubs}
    assert "host:SRV" in hubs
    assert any(reason in r for r in hubs["host:SRV"].reasons)


def test_small_batches_have_no_volume_hubs(mk):
    alerts = [mk(i, "Large archive created", "WS-1", "alice") for i in range(3)]
    result = run_correlation(alerts, ASSETS, cfg(hub_min_share=0.5))  # hub_min_alerts = 20
    assert result.hubs == []


# --- roles and normalisation -------------------------------------------------------------------


def test_internal_ip_is_normalised_to_its_host(mk):
    a = mk(0, "Office application spawned PowerShell", "WS-1", "alice")
    b = mk(20, "Login from new source host", "SRV", "svc-x", "10.30.0.1", "10.10.0.20")
    result = run_correlation([a, b], ASSETS, cfg())
    assert groups(result.incidents) == [[a.alert_id, b.alert_id]]
    assert result.links["INC-0001"][0].entity == "host:WS-1"
    assert result.incidents[0].hosts == ["SRV", "WS-1"]


def test_two_actors_hitting_the_same_target_do_not_link(mk):
    a = mk(0, "SMB admin share access", "SRV", "alice", "10.30.0.1", "10.10.0.20")
    b = mk(5, "SMB admin share access", "SRV", "bob", "10.30.0.2", "10.10.0.20")
    assert len(correlate([a, b], ASSETS, cfg())) == 2


def test_activity_after_a_host_is_targeted_links(mk):
    exploit = mk(0, "Exploit attempt signature", "WEB", None, "203.0.113.9", "10.20.0.10")
    shell = mk(10, "Web server process spawned shell", "WEB")
    result = run_correlation([exploit, shell], ASSETS, cfg())
    assert len(result.incidents) == 1
    assert result.links["INC-0001"][0].reason == "target"


def test_scans_never_link_through_their_target(mk):
    scan = mk(0, "Inbound connection blocked", "WEB", None, "203.0.113.9", "10.20.0.10")
    shell = mk(10, "Web server process spawned shell", "WEB")
    assert len(correlate([scan, shell], ASSETS, cfg())) == 2


def test_external_destination_links(mk):
    a = mk(0, "Connection to newly registered domain", "WEB", "alice", "10.30.0.1", "198.51.100.7")
    b = mk(9, "Large outbound transfer", "WEB", "bob", "10.30.0.2", "198.51.100.7")
    result = run_correlation([a, b], ASSETS, cfg())
    assert len(result.incidents) == 1
    assert result.links["INC-0001"][0].entity == "ip:198.51.100.7"


def test_vpn_pool_address_is_internal_not_inbound(mk):
    # 10.50.x is not an asset, but it is inside the organisation's address space, so an LDAP
    # query from it is not "inbound noise" and its source still links.
    a = mk(0, "LDAP enumeration query", "DC01", "alice", "10.50.0.9")
    b = mk(20, "Internal network scan", "SRV", None, "10.50.0.9", "10.10.0.20")
    assert len(correlate([a, b], ASSETS, cfg())) == 1


# --- recurrence --------------------------------------------------------------------------------


def test_recurrence_keeps_repeated_bursts_together(mk):
    early = [mk(m, "Failed login", "DC01", "alice", "10.30.0.1") for m in (0, 1)]
    late = [mk(m, "Failed login", "DC01", "alice", "10.30.0.1") for m in (360, 361)]
    result = run_correlation(early + late, ASSETS, cfg())
    assert len(result.incidents) == 1
    assert any(link.reason == "recurrence" for link in result.links["INC-0001"])


def test_recurrence_does_not_merge_unrelated_users(mk):
    alice = [mk(m, "Failed login", "DC01", "alice", "10.30.0.1") for m in (0, 360)]
    bob = [mk(m, "Failed login", "DC01", "bob", "10.30.0.2") for m in (180, 540)]
    incidents = correlate(alice + bob, ASSETS, cfg())
    assert sorted(groups(incidents)) == sorted(
        [[a.alert_id for a in alice], [b.alert_id for b in bob]]
    )


def test_recurrence_max_users_guard_on_shared_source(mk):
    # Two people behind the same VPN exit node: same rule, same source, different users.
    a = mk(0, "Impossible travel login", "VPN01", "alice", "192.0.2.50", "10.20.0.5")
    b = mk(300, "Impossible travel login", "VPN01", "bob", "192.0.2.50", "10.20.0.5")
    assert len(correlate([a, b], ASSETS, cfg())) == 2


def test_recurrence_gap_limit(mk):
    alerts = [mk(m, "Failed login", "DC01", "alice", "10.30.0.1") for m in (0, 400)]
    assert len(correlate(alerts, ASSETS, cfg(recurrence_max_gap_minutes=120))) == 2
    assert len(correlate(alerts, ASSETS, cfg())) == 1


def test_hub_actor_routine_merges_across_rules(mk):
    alerts = [
        mk(0, "SMB admin share access", "WS-1", "adm-x", "10.10.0.20"),
        mk(200, "Remote service creation", "WS-2", "adm-x", "10.10.0.20"),
        mk(400, "Account enumeration via net.exe", "WS-3", "adm-x", "10.10.0.20"),
    ]
    on = run_correlation(alerts, ASSETS, cfg(hub_min_fanout=3))
    off = run_correlation(alerts, ASSETS, cfg(hub_min_fanout=3, hub_actor_routine=False))
    assert len(on.incidents) == 1
    assert {link.reason for link in on.links["INC-0001"]} == {"routine"}
    assert len(off.incidents) == 3


# --- output ------------------------------------------------------------------------------------


def test_incident_fields(mk):
    a = mk(0, "Suspicious attachment delivered", "WS-1", "alice", "198.51.100.3")
    b = mk(30, "Login from new source host", "SRV", "alice", "10.30.0.1", "10.10.0.20")
    (incident,) = correlate([b, a], ASSETS, cfg())
    assert incident.incident_id == "INC-0001"
    assert incident.alert_ids == [a.alert_id, b.alert_id]
    assert incident.first_seen == a.timestamp
    assert incident.last_seen == b.timestamp
    assert incident.hosts == ["SRV", "WS-1"]
    assert incident.users == ["alice"]
    assert incident.ips == ["10.10.0.20", "10.30.0.1", "198.51.100.3"]
    assert incident.techniques == [] and incident.score is None and incident.brief is None


def test_ids_follow_first_seen_and_ignore_input_order(mk):
    alerts = [
        mk(90, "Large archive created", "WS-2", "bob"),
        mk(0, "Large archive created", "WS-1", "alice"),
        mk(30, "Large archive created", "WS-3", "carol"),
    ]
    first = correlate(alerts, ASSETS, cfg())
    shuffled = alerts[:]
    random.Random(3).shuffle(shuffled)
    assert correlate(shuffled, ASSETS, cfg()) == first
    assert [(i.incident_id, i.users) for i in first] == [
        ("INC-0001", ["alice"]),
        ("INC-0002", ["carol"]),
        ("INC-0003", ["bob"]),
    ]


def test_link_reasons_explain_every_incident(mk):
    a = mk(0, "Office application spawned PowerShell", "WS-1", "alice")
    b = mk(12, "LSASS memory access", "WS-1", "alice")
    c = mk(200, "Large archive created", "WS-2", "bob")
    result = run_correlation([a, b, c], ASSETS, cfg())
    for incident in result.incidents:
        assert len(result.links[incident.incident_id]) == len(incident.alert_ids) - 1
    (link,) = result.links["INC-0001"]
    assert (link.alert_id, link.linked_to) == (b.alert_id, a.alert_id)
    assert link.describe() in {"same user alice, 12 min apart", "same host WS-1, 12 min apart"}
    assert result.explain("INC-0001")[0].startswith(f"{b.alert_id} + {a.alert_id}: same ")
    assert result.incident_of == {
        a.alert_id: "INC-0001",
        b.alert_id: "INC-0001",
        c.alert_id: "INC-0002",
    }


@pytest.mark.parametrize(
    ("link", "text"),
    [
        (Link("A", "B", "entity", "user:alice", 30), "same user alice, 30 s apart"),
        (
            Link("A", "B", "target", "host:WEB", 600),
            "activity on host WEB after it was targeted, 10 min apart",
        ),
        (
            Link("A", "B", "recurrence", "ip:192.0.2.1", 7200, "Port scan detected"),
            "'Port scan detected' recurring on IP 192.0.2.1, 2.0 h apart",
        ),
        (
            Link("A", "B", "routine", "user:adm-it", 60),
            "routine activity of hub user adm-it, 1 min apart",
        ),
    ],
)
def test_link_descriptions(link, text):
    assert link.describe() == text


def test_empty_input():
    assert correlate([], ASSETS, cfg()) == []
