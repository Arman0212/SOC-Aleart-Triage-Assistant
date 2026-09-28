"""Synthetic company inventory: servers, endpoints, users, accounts and the IP plan.

IP plan:
    10.10.0.0/24  core servers          10.20.0.0/24  DMZ (web, mail, VPN)
    10.30.0.0/22  workstations          10.40.0.0/23  laptops
    10.50.0.0/24  VPN client pool       198.51.100/24, 203.0.113/24, 192.0.2/24  internet

Hub entities that legitimately appear in many unrelated alerts: DC01 (all domain auth),
PROXY01 (all proxy alerts), the shared admin account ``adm-it`` and VULNSCAN01's address.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field

from faker import Faker

from nullpunkt.core.schema import Asset, AssetType
from nullpunkt.generator.common import IpPool, largest_remainder

HUB_HOSTS = ("DC01", "PROXY01")
SHARED_ADMIN = "adm-it"
SERVICE_ACCOUNTS = ("svc-backup", "svc-sql", "svc-deploy", "svc-legacy", "svc-sccm")

# host, ip, type, owner, criticality. The schema has no type for jump, proxy, patch or
# scanner hosts; they use the closest existing AssetType.
SERVERS: tuple[tuple[str, str, AssetType, str, int], ...] = (
    ("DC01", "10.10.0.10", AssetType.DOMAIN_CONTROLLER, "it-infra", 5),
    ("DC02", "10.10.0.11", AssetType.DOMAIN_CONTROLLER, "it-infra", 5),
    ("FINDB01", "10.10.0.20", AssetType.DATABASE, "finance", 5),
    ("HRDB01", "10.10.0.21", AssetType.DATABASE, "hr", 4),
    ("FS01", "10.10.0.30", AssetType.FILE_SERVER, "it-infra", 4),
    ("FS02", "10.10.0.31", AssetType.FILE_SERVER, "it-infra", 3),
    ("BACKUP01", "10.10.0.40", AssetType.FILE_SERVER, "it-infra", 3),
    ("JUMP01", "10.10.0.50", AssetType.WORKSTATION, "it-infra", 4),
    ("SCCM01", "10.10.0.60", AssetType.WEB_SERVER, "it-infra", 3),
    ("WSUS01", "10.10.0.61", AssetType.WEB_SERVER, "it-infra", 2),
    ("PROXY01", "10.10.0.70", AssetType.WEB_SERVER, "it-infra", 3),
    ("VULNSCAN01", "10.10.0.80", AssetType.WORKSTATION, "secops", 2),
    ("VPN01", "10.20.0.5", AssetType.VPN_GATEWAY, "it-infra", 4),
    ("WEB01", "10.20.0.10", AssetType.WEB_SERVER, "web-team", 3),
    ("WEB02", "10.20.0.11", AssetType.WEB_SERVER, "web-team", 3),
    ("MAIL01", "10.20.0.25", AssetType.MAIL_SERVER, "it-infra", 4),
)
DMZ_HOSTS = ("VPN01", "WEB01", "WEB02", "MAIL01")

# department, host code, share of endpoints, share of those that are laptops
DEPARTMENTS: tuple[tuple[str, str, float, float], ...] = (
    ("finance", "FIN", 0.15, 0.2),
    ("hr", "HR", 0.08, 0.2),
    ("sales", "SAL", 0.20, 0.8),
    ("marketing", "MKT", 0.12, 0.6),
    ("engineering", "ENG", 0.22, 0.5),
    ("it", "IT", 0.10, 0.3),
    ("legal", "LEG", 0.05, 0.2),
    ("exec", "EXE", 0.08, 0.5),
)
HIGH_VALUE_DEPTS = ("finance", "exec")

EXTERNAL_PREFIXES = ("198.51.100", "203.0.113", "192.0.2")


@dataclass(frozen=True)
class User:
    user_id: str
    dept: str
    endpoint: str
    ip: str
    is_laptop: bool
    vpn_ip: str | None = None

    @property
    def admin_account(self) -> str:
        return f"adm-{self.user_id}"


@dataclass
class Inventory:
    assets: list[Asset]
    users: list[User]
    external_ips: IpPool
    vpn_ips: IpPool
    reserved: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.by_host = {a.host: a for a in self.assets}

    def ip_of(self, host: str) -> str:
        return self.by_host[host].ip

    def free_users(self, *, dept: str | None = None, laptop: bool | None = None) -> list[User]:
        """Users not reserved as scenario victims, optionally filtered."""
        return [
            u
            for u in self.users
            if u.user_id not in self.reserved
            and (dept is None or u.dept == dept)
            and (laptop is None or u.is_laptop == laptop)
        ]

    def reserve(self, *entities: str) -> None:
        self.reserved.update(entities)


def _user_ids(fake: Faker, n: int) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    while len(ids) < n:
        first = re.sub(r"[^a-z]", "", fake.first_name().lower())
        last = re.sub(r"[^a-z]", "", fake.last_name().lower())
        candidate = f"{first}.{last}"
        if first and last and candidate not in seen:
            seen.add(candidate)
            ids.append(candidate)
    return ids


def build_inventory(n_hosts: int, rng: random.Random, fake: Faker) -> Inventory:
    assets = [
        Asset(host=h, ip=ip, asset_type=t, owner=o, criticality=c) for h, ip, t, o, c in SERVERS
    ]
    n_endpoints = n_hosts - len(SERVERS)
    per_dept = largest_remainder(n_endpoints, [d[2] for d in DEPARTMENTS])
    user_ids = _user_ids(fake, n_endpoints)

    vpn_pool = IpPool([f"10.50.0.{i}" for i in range(10, 255)], rng)
    users: list[User] = []
    ws_index = lap_index = 0
    for (dept, code, _share, laptop_share), count in zip(DEPARTMENTS, per_dept, strict=True):
        n_laptops = round(count * laptop_share)
        for i in range(count):
            is_laptop = i >= count - n_laptops
            user_id = user_ids[len(users)]
            if is_laptop:
                host = f"LT-{code}-{i + 1:02d}"
                ip = f"10.40.{lap_index // 250}.{lap_index % 250 + 5}"
                lap_index += 1
                crit, asset_type = 1, AssetType.LAPTOP
            else:
                host = f"WS-{code}-{i + 1:02d}"
                ip = f"10.30.{ws_index // 250}.{ws_index % 250 + 5}"
                ws_index += 1
                crit = 3 if dept in HIGH_VALUE_DEPTS else 2
                asset_type = AssetType.WORKSTATION
            assets.append(
                Asset(host=host, ip=ip, asset_type=asset_type, owner=user_id, criticality=crit)
            )
            vpn_ip = vpn_pool.take() if is_laptop else None
            users.append(User(user_id, dept, host, ip, is_laptop, vpn_ip))

    external = [f"{p}.{i}" for p in EXTERNAL_PREFIXES for i in range(1, 255)]
    return Inventory(assets, users, IpPool(external, rng), vpn_pool)
