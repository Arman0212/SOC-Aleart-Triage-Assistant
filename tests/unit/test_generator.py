import random
from datetime import UTC, datetime, time
from pathlib import Path

import pytest
from faker import Faker
from pydantic import ValidationError

from nullpunkt.core.schema import AssetType
from nullpunkt.generator.common import Clock, IpPool, largest_remainder
from nullpunkt.generator.config import GeneratorConfig, load_config
from nullpunkt.generator.inventory import HUB_HOSTS, build_inventory
from nullpunkt.generator.noise import CATEGORIES, generate_noise


class TestConfig:
    def test_defaults(self):
        cfg = GeneratorConfig()
        assert cfg.n_alerts == 3000
        assert cfg.company_timezone == "Asia/Kolkata"

    def test_shift_converted_from_ist_to_utc(self):
        cfg = GeneratorConfig()
        assert cfg.shift_start_utc == datetime(2026, 10, 1, 3, 30, tzinfo=UTC)
        assert cfg.shift_end_utc == datetime(2026, 10, 1, 15, 30, tzinfo=UTC)

    @pytest.mark.parametrize(
        ("utc_hour", "utc_minute", "expected"),
        [(3, 30, True), (12, 29, True), (12, 30, False), (15, 0, False), (3, 29, False)],
    )
    def test_business_hours_are_local(self, utc_hour, utc_minute, expected):
        # 09:00-18:00 IST is 03:30-12:30 UTC.
        instant = datetime(2026, 10, 1, utc_hour, utc_minute, tzinfo=UTC)
        assert GeneratorConfig().is_business_hours(instant) is expected

    def test_load_file_and_override_seed(self, tmp_path):
        path = tmp_path / "gen.yaml"
        path.write_text("seed: 1\nn_alerts: 800\nscenarios: [SCN-01]\n")
        cfg = load_config(path, seed=99)
        assert (cfg.seed, cfg.n_alerts, cfg.scenarios) == (99, 800, ["SCN-01"])

    def test_repo_config_loads(self):
        cfg = load_config(Path(__file__).parents[2] / "configs" / "generator.yaml")
        assert cfg == GeneratorConfig()

    @pytest.mark.parametrize(
        "bad",
        [
            {"company_timezone": "Mars/Olympus"},
            {"shift_start": "2026-10-01T09:00:00+05:30"},
            {"business_start": time(18), "business_end": time(9)},
            {"scenarios": ["SCN-99"]},
            {"scenarios": ["SCN-01", "SCN-01"]},
            {"n_hosts": 20},
            {"n_alerts": 10},
            {"shift_hours": 0},
            {"surprise": True},
        ],
    )
    def test_invalid(self, bad):
        with pytest.raises(ValidationError):
            GeneratorConfig.model_validate(bad)


@pytest.mark.parametrize(
    ("total", "weights"),
    [
        (3000, [0.13, 0.15, 0.08]),
        (7, [1, 1, 1]),
        (0, [1, 2]),
        (2951, [c.share for c in CATEGORIES]),
    ],
)
def test_largest_remainder_is_exact(total, weights):
    counts = largest_remainder(total, weights)
    assert sum(counts) == total
    assert all(c >= 0 for c in counts)


def test_noise_shares_sum_to_one():
    assert sum(c.share for c in CATEGORIES) == pytest.approx(1.0)
    assert len(CATEGORIES) >= 8


def test_ip_pool_is_unique_and_exhausts():
    pool = IpPool(["a", "b", "c"], random.Random(1))
    assert sorted(pool.take_many(3)) == ["a", "b", "c"]
    with pytest.raises(RuntimeError):
        pool.take()


def test_business_profile_favours_business_hours():
    clock = Clock(GeneratorConfig())
    rng = random.Random(7)
    samples = [clock.sample(rng, "business") for _ in range(4000)]
    share = sum(clock.is_business(s) for s in samples) / len(samples)
    # 9 of the 12 shift hours are business hours; 3:1 weighting pushes that to 90 %.
    assert 0.86 < share < 0.94
    off = [clock.sample(rng, "off_hours") for _ in range(4000)]
    assert sum(not clock.is_business(s) for s in off) / len(off) > 0.4


class TestInventory:
    @pytest.fixture
    def inv(self):
        return build_inventory(80, random.Random(42), _faker(42))

    def test_size_and_uniqueness(self, inv):
        assert len(inv.assets) == 80
        assert len({a.host for a in inv.assets}) == 80
        assert len({a.ip for a in inv.assets}) == 80
        assert len({u.user_id for u in inv.users}) == len(inv.users)

    def test_criticality_profile(self, inv):
        by_host = inv.by_host
        assert by_host["DC01"].criticality == 5
        assert by_host["FINDB01"].criticality == 5
        laptops = [a for a in inv.assets if a.asset_type is AssetType.LAPTOP]
        assert laptops and all(a.criticality == 1 for a in laptops)
        endpoints = [a for a in inv.assets if a.host.startswith(("WS-", "LT-"))]
        assert len(endpoints) == 64

    def test_every_user_has_a_primary_endpoint(self, inv):
        for user in inv.users:
            asset = inv.by_host[user.endpoint]
            assert asset.owner == user.user_id
            assert asset.ip == user.ip
            assert (user.vpn_ip is not None) == user.is_laptop

    def test_ip_plan(self, inv):
        for asset in inv.assets:
            if asset.asset_type is AssetType.LAPTOP:
                assert asset.ip.startswith("10.40.")
            elif asset.host.startswith("WS-"):
                assert asset.ip.startswith("10.30.")
            else:
                assert asset.ip.startswith(("10.10.", "10.20."))

    def test_hub_hosts_present(self, inv):
        assert set(HUB_HOSTS) <= set(inv.by_host)

    @pytest.mark.parametrize(
        ("host", "asset_type"),
        [
            ("JUMP01", AssetType.JUMP_HOST),
            ("PROXY01", AssetType.PROXY),
            ("WSUS01", AssetType.PATCH_SERVER),
            ("SCCM01", AssetType.SOFTWARE_DISTRIBUTION),
            ("VULNSCAN01", AssetType.VULN_SCANNER),
            ("BACKUP01", AssetType.BACKUP_SERVER),
            ("DC01", AssetType.DOMAIN_CONTROLLER),
            ("FINDB01", AssetType.DATABASE),
        ],
    )
    def test_infrastructure_uses_specific_asset_types(self, inv, host, asset_type):
        assert inv.by_host[host].asset_type is asset_type

    def test_only_endpoints_are_workstations_or_laptops(self, inv):
        for asset in inv.assets:
            endpoint = asset.host.startswith(("WS-", "LT-"))
            assert endpoint == (asset.asset_type in (AssetType.WORKSTATION, AssetType.LAPTOP))

    def test_departments_needed_by_scenarios_exist_at_minimum_size(self):
        inv = build_inventory(60, random.Random(0), _faker(0))
        depts = [u.dept for u in inv.users]
        assert depts.count("finance") >= 3
        assert depts.count("it") >= 4


def test_noise_needs_at_least_one_alert_per_category():
    cfg = GeneratorConfig()
    rng = random.Random(0)
    inv = build_inventory(80, rng, _faker(0))
    with pytest.raises(ValueError, match="at least"):
        generate_noise(len(CATEGORIES) - 1, inv, rng, Clock(cfg), [])


def _faker(seed: int) -> Faker:
    fake = Faker("en_US")
    fake.seed_instance(seed)
    return fake
