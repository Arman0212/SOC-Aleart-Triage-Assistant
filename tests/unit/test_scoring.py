import random
from datetime import UTC, datetime, timedelta

import pytest

from nullpunkt.core.config import ScoringConfig
from nullpunkt.core.detection_rules import RULES
from nullpunkt.core.schema import Alert, Asset, AssetType, Incident, ScoreBreakdown
from nullpunkt.scoring.engine import (
    asset_at_risk,
    build_context,
    priority_tier,
    rank,
    score_incident,
)

T0 = datetime(2026, 10, 1, 3, 30, tzinfo=UTC)


def _asset(host: str, ip: str, asset_type: AssetType, criticality: int, owner: str = "it"):
    return Asset(host=host, ip=ip, asset_type=asset_type, owner=owner, criticality=criticality)


ASSETS = {
    a.host: a
    for a in (
        _asset("DC01", "10.10.0.10", AssetType.DOMAIN_CONTROLLER, 5),
        _asset("FINDB01", "10.10.0.20", AssetType.DATABASE, 5),
        _asset("FS01", "10.10.0.30", AssetType.FILE_SERVER, 4),
        _asset("MAIL01", "10.20.0.25", AssetType.MAIL_SERVER, 4),
        _asset("PROXY01", "10.10.0.70", AssetType.PROXY, 3),
        _asset("VPN01", "10.20.0.5", AssetType.VPN_GATEWAY, 4),
        _asset("WS-1", "10.30.0.1", AssetType.WORKSTATION, 2, owner="alice"),
        _asset("LT-1", "10.40.0.1", AssetType.LAPTOP, 1, owner="bob"),
    )
}


class Factory:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self, minutes, rule, host, severity="low", user=None, src=None, dst=None):
        self.n += 1
        return Alert(
            alert_id=f"ALR-{self.n:06d}",
            timestamp=T0 + timedelta(minutes=minutes),
            source="edr",
            rule_name=rule,
            severity=severity,
            host=host,
            user=user,
            src_ip=src,
            dst_ip=dst,
            message="m",
        )


@pytest.fixture
def mk():
    return Factory()


def incident_of(alerts: list[Alert], n: int = 1) -> Incident:
    alerts = sorted(alerts, key=lambda a: (a.timestamp, a.alert_id))
    return Incident(
        incident_id=f"INC-{n:04d}",
        alert_ids=[a.alert_id for a in alerts],
        first_seen=alerts[0].timestamp,
        last_seen=alerts[-1].timestamp,
        hosts=sorted({a.host for a in alerts}),
    )


def score(incident_alerts, batch_alerts=None, config=None):
    batch = batch_alerts if batch_alerts is not None else incident_alerts
    cfg = config or ScoringConfig()
    ctx = build_context(batch, ASSETS, cfg)
    by_id = {a.alert_id: a for a in batch}
    return score_incident(incident_of(incident_alerts), by_id, ASSETS, ctx, cfg)


# --- bounds ------------------------------------------------------------------------------------


def test_score_is_bounded_over_random_inputs():
    rng = random.Random(7)
    hosts = list(ASSETS)
    severities = ["low", "medium", "high", "critical"]
    for trial in range(300):
        mk = Factory()
        batch = [
            mk(
                rng.randint(0, 720),
                rng.choice(RULES).rule_name,
                rng.choice(hosts),
                rng.choice(severities),
                rng.choice([None, "alice", "bob", "carol"]),
                rng.choice([None, "10.30.0.1", "10.40.0.1", "198.51.100.9", "10.50.0.3"]),
            )
            for _ in range(rng.randint(1, 40))
        ]
        members = rng.sample(batch, rng.randint(1, len(batch)))
        config = ScoringConfig(
            stage_step=rng.choice([0.25, 1.0, 3.0]),
            tactic_cap=rng.randint(2, 15),
            routine_min_hours=rng.randint(2, 6),
            routine_penalty=rng.choice([0.01, 0.1, 1.0]),
        )
        detail = score(members, batch, config)
        assert isinstance(detail.score, ScoreBreakdown)
        assert 0 < detail.score.risk_score <= 100, trial
        assert detail.score.stage_multiplier >= 1
        assert 0 < detail.score.noise_penalty <= 1


def test_maximum_is_exactly_100(mk):
    # Critical alert on a criticality-5 asset, 4 distinct tactics (the cap), rarest rule seen once.
    alerts = [
        mk(0, "Directory replication request", "DC01", "critical", src="10.30.0.1"),
        mk(1, "Office application spawned PowerShell", "DC01", "low"),
        mk(2, "SMB admin share access", "DC01", "low"),
        mk(3, "Volume shadow copy deletion", "DC01", "low"),
    ]
    assert score(alerts).score.risk_score == 100.0


# --- severity x criticality pairing ------------------------------------------------------------


def test_severity_and_criticality_come_from_the_same_alert(mk):
    loud_on_laptop = mk(0, "Known malware hash detected", "LT-1", "critical", user="bob")
    quiet_on_db = mk(5, "Bulk read of database files", "FINDB01", "low", user="bob")
    detail = score([loud_on_laptop, quiet_on_db])
    s = detail.score
    # max(4 x 1, 1 x 5) = 5 -> the low alert on the database, not critical x 5 = 20.
    assert (s.severity_weight, s.asset_criticality) == (1, 5)
    assert detail.peak_alert == quiet_on_db.alert_id


# --- asset at risk -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule", "host", "user", "src", "expected"),
    [
        ("Failed login", "DC01", "alice", "10.30.0.1", ("WS-1", 2)),  # DC authenticates only
        ("Failed login", "VPN01", "bob", "10.50.0.3", ("LT-1", 1)),  # VPN pool -> owned laptop
        ("Impossible travel login", "VPN01", "bob", "198.51.100.9", ("LT-1", 1)),
        ("Connection to newly registered domain", "PROXY01", "alice", "10.30.0.1", ("WS-1", 2)),
        ("Spam campaign blocked", "MAIL01", None, "198.51.100.9", (None, 1)),  # relay, unresolved
        ("Suspicious attachment delivered", "MAIL01", "alice", "198.51.100.9", ("WS-1", 2)),
        ("Suspicious attachment delivered", "WS-1", "alice", "198.51.100.9", ("WS-1", 2)),
        ("Directory replication request", "DC01", None, "10.30.0.1", ("DC01", 5)),  # DCSync
        ("Internal network scan", "FS01", None, "10.50.0.3", ("FS01", 4)),  # not a relay
        ("SMB admin share access", "FINDB01", "alice", "10.30.0.1", ("FINDB01", 5)),
        ("Exploit attempt signature", "MAIL01", None, "198.51.100.9", ("MAIL01", 4)),
    ],
)
def test_asset_at_risk(mk, rule, host, user, src, expected):
    a = mk(0, rule, host, user=user, src=src)
    cfg = ScoringConfig()
    assert asset_at_risk(a, ASSETS, build_context([a], ASSETS, cfg), cfg) == expected


def test_login_incident_does_not_inherit_dc_criticality(mk):
    alerts = [mk(m, "Failed login", "DC01", user="alice", src="10.30.0.1") for m in range(3)]
    detail = score(alerts)
    assert detail.asset == "WS-1" and detail.score.asset_criticality == 2
    assert "WS-1" in detail.score.explanation and "DC01" not in detail.score.explanation


# --- volume, stage and noise -------------------------------------------------------------------


def test_duplicating_noise_alerts_never_raises_the_score(mk):
    base = [
        mk(0, "Failed login", "DC01", user="alice", src="10.30.0.1"),
        mk(1, "Successful login after failures", "DC01", "medium", "alice", "10.30.0.1"),
        mk(5, "Mass file access on share", "FS01", "medium", "alice", "10.30.0.1"),
        mk(9, "Large outbound transfer", "PROXY01", "medium", "alice", "10.30.0.1", "198.51.100.1"),
    ]
    other = [mk(30, "Failed login", "DC01", user="bob", src="10.40.0.1")]
    before = score(base, base + other).score.risk_score
    for copies in (5, 50):
        dupes = [
            mk(60 * (i % 12) + 2, "Failed login", "DC01", user="alice", src="10.30.0.1")
            for i in range(copies)
        ]
        after = score(base + dupes, base + dupes + other).score.risk_score
        assert after <= before


def test_more_tactics_raise_the_stage_multiplier(mk):
    one = [mk(0, "Mass file access on share", "FS01", "medium")]
    two = one + [mk(1, "Large archive created", "FS01")]  # same tactic: collection
    three = two + [mk(2, "Backup service stopped", "FS01")]  # + impact
    four = three + [mk(3, "Office application spawned PowerShell", "FS01")]  # + execution
    stages = [score(x).score.stage_multiplier for x in (one, two, three, four)]
    assert stages[0] == stages[1] == 1.0
    assert stages[1] < stages[2] < stages[3]


def test_tactics_beyond_the_cap_do_not_count(mk):
    alerts = [
        mk(0, "Suspicious attachment delivered", "WS-1", "medium", "alice", "198.51.100.9"),
        mk(1, "Office application spawned PowerShell", "WS-1", user="alice"),
        mk(2, "Login from new source host", "FS01", user="alice", src="10.30.0.1"),
        mk(3, "SMB admin share access", "FS01", "medium", "alice", "10.30.0.1"),
        mk(4, "Mass file access on share", "FS01", "medium", "alice"),
    ]
    detail = score(alerts, config=ScoringConfig(tactic_cap=4))
    assert len(detail.tactics) == 5
    assert detail.score.stage_multiplier == 4.0  # 1 + 1.0 x (4 - 1)
    assert "5 tactics (4 counted)" in detail.score.explanation


def test_tactics_listed_in_kill_chain_order(mk):
    alerts = [
        mk(0, "Mass file access on share", "FS01", "medium"),
        mk(1, "Suspicious attachment delivered", "WS-1", "medium", "alice", "198.51.100.9"),
    ]
    detail = score(alerts)
    assert detail.tactics == ("initial-access", "collection")
    assert "initial access → collection" in detail.score.explanation


def test_routine_pairs_are_excluded_from_evidence(mk):
    # alice's failed logins fire in 4 different hours: routine. The one-off exfil is evidence.
    typos = [mk(60 * h, "Failed login", "DC01", user="alice", src="10.30.0.1") for h in range(4)]
    exfil = mk(70, "Large outbound transfer", "PROXY01", "medium", "alice", "10.30.0.1", "1.2.3.4")
    detail = score([*typos, exfil])
    assert detail.evidence == (exfil.alert_id,)
    assert not detail.routine_only
    assert detail.peak_alert == exfil.alert_id


def test_routine_only_incident_is_penalised(mk):
    alerts = [mk(60 * h, "Failed login", "DC01", user="alice", src="10.30.0.1") for h in range(4)]
    cfg = ScoringConfig(routine_penalty=0.1)
    detail = score(alerts, config=cfg)
    assert detail.routine_only
    assert "routine activity" in detail.score.explanation
    unpenalised = score(alerts, config=ScoringConfig(routine_penalty=1.0)).score.risk_score
    assert detail.score.risk_score == pytest.approx(unpenalised * 0.1, abs=0.01)


def test_rare_rules_are_more_informative(mk):
    batch = [mk(i, "Failed login", "DC01", user="alice", src="10.30.0.1") for i in range(50)]
    rare = mk(100, "LSASS memory access", "WS-1", "high", "alice")
    ctx = build_context([*batch, rare], ASSETS, ScoringConfig())
    assert ctx.informativeness["LSASS memory access"] == 1.0
    assert 0 < ctx.informativeness["Failed login"] < 0.3


def test_explanation_mentions_the_driving_asset_and_rule(mk):
    alerts = [
        mk(0, "SMB admin share access", "FINDB01", "medium", "alice", "10.30.0.1"),
        mk(5, "Bulk read of database files", "FINDB01", "medium", "alice"),
    ]
    text = score(alerts).score.explanation
    assert text.startswith("critical asset FINDB01 (5) × medium severity (SMB admin share access)")


def test_unknown_host_and_unknown_rule_are_scored_conservatively(mk):
    a = mk(0, "Brand new rule", "NOT-IN-INVENTORY", "high")
    detail = score([a])
    assert detail.asset is None and detail.score.asset_criticality == 1
    assert "no mapped tactic" in detail.score.explanation


# --- tiers and ranking -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("risk", "tier"),
    [(100, "P1"), (23.0, "P1"), (22.99, "P2"), (6.2, "P2"), (3.8, "P3"), (3.79, "P4"), (0.1, "P4")],
)
def test_priority_tiers_use_fixed_thresholds(risk, tier):
    assert priority_tier(risk) == tier


def _scored(n, risk, crit, minute):
    return Incident(
        incident_id=f"INC-{n:04d}",
        alert_ids=["ALR-000001"],
        first_seen=T0 + timedelta(minutes=minute),
        last_seen=T0 + timedelta(minutes=minute),
        hosts=["H"],
        score=ScoreBreakdown(
            severity_weight=1,
            asset_criticality=crit,
            stage_multiplier=1,
            noise_penalty=1,
            risk_score=risk,
            explanation="x",
        ),
    )


def test_rank_is_deterministic_with_tie_breaks():
    incidents = [
        _scored(1, 10.0, 2, 5),
        _scored(2, 10.0, 5, 9),  # same risk, higher criticality wins
        _scored(3, 10.0, 2, 1),  # same risk and criticality, earlier wins
        _scored(4, 30.0, 1, 0),
    ]
    order = [i.incident_id for i in rank(incidents)]
    assert order == ["INC-0004", "INC-0002", "INC-0003", "INC-0001"]
    assert [i.incident_id for i in rank(list(reversed(incidents)))] == order


def test_rank_requires_scores():
    unscored = Incident(
        incident_id="INC-0001", alert_ids=["ALR-000001"], first_seen=T0, last_seen=T0, hosts=["H"]
    )
    with pytest.raises(ValueError, match="no score"):
        rank([unscored])
