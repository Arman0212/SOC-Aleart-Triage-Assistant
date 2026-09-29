"""Injected intrusion scenarios, defined as data.

A scenario is a list of roles (who and what is involved) and a list of steps (which rule fires
on which role, after what delay, how many times). ``run_scenario`` binds roles against the
inventory and turns the steps into alert drafts. Messages are rendered later from the rule's
templates, exactly as for noise, so attack alerts cannot be told apart by their text.

See docs/scenarios.md for the story behind each scenario.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from nullpunkt.core.detection_rules import get_rule
from nullpunkt.generator.common import Draft, with_failure_facts
from nullpunkt.generator.inventory import Inventory, User

# Role kinds. Victim kinds identify entities that belong to the intrusion and are therefore kept
# out of the noise; server kinds are ordinary infrastructure that noise may also touch.
VICTIM_KINDS = frozenset(
    {"user", "endpoint_of", "endpoint_ip_of", "admin_of", "account", "external_ip", "vpn_ip"}
)
SERVER_KINDS = frozenset({"server", "server_ip"})


@dataclass(frozen=True)
class Role:
    kind: str
    arg: str = ""

    def __post_init__(self) -> None:
        if self.kind not in VICTIM_KINDS | SERVER_KINDS:
            raise ValueError(f"unknown role kind {self.kind!r}")


@dataclass(frozen=True)
class Step:
    rule: str
    host: str
    user: str | None = None
    src: str | None = None
    dst: str | None = None
    delay_min: tuple[int, int] = (0, 0)
    count: tuple[int, int] = (1, 1)
    gap_s: tuple[int, int] = (5, 60)

    def __post_init__(self) -> None:
        get_rule(self.rule)


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    name: str
    roles: dict[str, Role]
    steps: tuple[Step, ...]
    # Role whose user is deliberately also a password-typo noise user (the purity test).
    typo_overlap_role: str | None = None

    @property
    def max_window_s(self) -> int:
        return sum(s.delay_min[1] * 60 + (s.count[1] - 1) * s.gap_s[1] for s in self.steps)


@dataclass
class ScenarioRun:
    scenario: Scenario
    bindings: dict[str, str]
    drafts: list[Draft]
    victims: frozenset[str]
    overlap_user: str | None
    start: int
    end: int = field(init=False)

    def __post_init__(self) -> None:
        self.end = max(d.offset for d in self.drafts)


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "SCN-01",
        "Phishing to the finance database",
        roles={
            "victim": Role("user", "finance_workstation"),
            "ws": Role("endpoint_of", "victim"),
            "ws_ip": Role("endpoint_ip_of", "victim"),
            "sender": Role("external_ip"),
            "db": Role("server", "FINDB01"),
            "db_ip": Role("server_ip", "FINDB01"),
        },
        steps=(
            Step("Suspicious attachment delivered", "ws", "victim", src="sender"),
            Step("Office application spawned PowerShell", "ws", "victim", delay_min=(2, 12)),
            Step("Login from new source host", "db", "victim", "ws_ip", "db_ip", (8, 30)),
            Step("SMB admin share access", "db", "victim", "ws_ip", "db_ip", (1, 6)),
            Step("Bulk read of database files", "db", "victim", delay_min=(4, 15)),
        ),
    ),
    Scenario(
        "SCN-02",
        "VPN brute force and discovery",
        roles={
            "victim": Role("user", "laptop"),
            "attacker": Role("external_ip"),
            "vpn_ip": Role("vpn_ip"),
            "vpn": Role("server", "VPN01"),
            "vpn_gw": Role("server_ip", "VPN01"),
            "dc": Role("server", "DC01"),
            "target": Role("server", "FS01"),
            "target_ip": Role("server_ip", "FS01"),
        },
        steps=(
            Step(
                "Failed login", "vpn", "victim", "attacker", "vpn_gw", count=(6, 12), gap_s=(3, 20)
            ),
            Step("Successful login after failures", "vpn", "victim", "attacker", "vpn_gw", (1, 5)),
            Step("LDAP enumeration query", "dc", "victim", "vpn_ip", delay_min=(3, 15)),
            Step(
                "Internal network scan",
                "target",
                src="vpn_ip",
                dst="target_ip",
                delay_min=(2, 20),
                count=(3, 6),
                gap_s=(1, 10),
            ),
        ),
    ),
    Scenario(
        "SCN-03",
        "Web exploit, web shell and discovery",
        roles={
            "attacker": Role("external_ip"),
            "web": Role("server", "WEB02"),
            "web_ip": Role("server_ip", "WEB02"),
            "target": Role("server", "HRDB01"),
            "target_ip": Role("server_ip", "HRDB01"),
        },
        steps=(
            Step("Exploit attempt signature", "web", src="attacker", dst="web_ip", count=(1, 3)),
            Step("Web server process spawned shell", "web", delay_min=(2, 20)),
            Step("Account enumeration via net.exe", "web", delay_min=(3, 15)),
            Step(
                "Internal network scan",
                "target",
                src="web_ip",
                dst="target_ip",
                delay_min=(5, 30),
                count=(2, 5),
                gap_s=(1, 10),
            ),
        ),
    ),
    Scenario(
        "SCN-04",
        "Credential theft reaching the domain controller",
        roles={
            "victim": Role("user", "workstation"),
            "ws": Role("endpoint_of", "victim"),
            "ws_ip": Role("endpoint_ip_of", "victim"),
            "svc": Role("account", "svc-sql"),
            "dc": Role("server", "DC01"),
            "dc_ip": Role("server_ip", "DC01"),
        },
        steps=(
            Step("LSASS memory access", "ws", "victim"),
            Step(
                "Kerberos RC4 service ticket request",
                "dc",
                "victim",
                "ws_ip",
                "dc_ip",
                (5, 30),
                count=(4, 8),
                gap_s=(2, 15),
            ),
            Step("Privileged login from new host", "dc", "svc", "ws_ip", "dc_ip", (20, 60)),
            Step("Directory replication request", "dc", "svc", "ws_ip", "dc_ip", (2, 15)),
        ),
    ),
    Scenario(
        "SCN-05",
        "Data staging and exfiltration from a file server",
        roles={
            "victim": Role("user", "any"),
            "vpn_ip": Role("vpn_ip"),
            "dest": Role("external_ip"),
            "fs": Role("server", "FS02"),
            "fs_ip": Role("server_ip", "FS02"),
            "proxy": Role("server", "PROXY01"),
        },
        steps=(
            Step("Login from new source host", "fs", "victim", "vpn_ip", "fs_ip"),
            Step(
                "Mass file access on share",
                "fs",
                "victim",
                "vpn_ip",
                delay_min=(5, 30),
                count=(2, 4),
                gap_s=(60, 300),
            ),
            Step("Large archive created", "fs", "victim", delay_min=(10, 40)),
            Step("Large outbound transfer", "proxy", "victim", "fs_ip", "dest", (5, 30)),
        ),
        typo_overlap_role="victim",
    ),
    Scenario(
        "SCN-06",
        "Ransomware precursor on a file server",
        roles={
            "it_user": Role("user", "it"),
            "admin": Role("admin_of", "it_user"),
            "ws_ip": Role("endpoint_ip_of", "it_user"),
            "fs": Role("server", "FS01"),
            "fs_ip": Role("server_ip", "FS01"),
        },
        steps=(
            Step("SMB admin share access", "fs", "admin", "ws_ip", "fs_ip"),
            Step("Remote service creation", "fs", "admin", "ws_ip", delay_min=(1, 8)),
            Step("Backup service stopped", "fs", "admin", delay_min=(1, 10)),
            Step("Volume shadow copy deletion", "fs", "admin", delay_min=(1, 5)),
        ),
    ),
    Scenario(
        "SCN-07",
        "Infostealer on a laptop",
        roles={
            "victim": Role("user", "laptop"),
            "laptop": Role("endpoint_of", "victim"),
            "laptop_ip": Role("endpoint_ip_of", "victim"),
            "c2": Role("external_ip"),
            "proxy": Role("server", "PROXY01"),
        },
        steps=(
            Step("Unsigned executable launched from Downloads", "laptop", "victim"),
            Step("Browser credential store access", "laptop", "victim", delay_min=(1, 5)),
            Step(
                "Connection to newly registered domain",
                "proxy",
                "victim",
                "laptop_ip",
                "c2",
                (1, 10),
            ),
            Step("Large outbound transfer", "proxy", "victim", "laptop_ip", "c2", (1, 10)),
        ),
    ),
)

SCENARIOS_BY_ID = {s.scenario_id: s for s in SCENARIOS}


def _pick_user(inv: Inventory, rng: random.Random, which: str) -> User:
    if which == "finance_workstation":
        pool = inv.free_users(dept="finance", laptop=False)
    elif which == "laptop":
        pool = inv.free_users(laptop=True)
    elif which == "workstation":
        pool = [u for u in inv.free_users(laptop=False) if u.dept != "finance"]
    elif which == "it":
        pool = inv.free_users(dept="it")
    elif which == "any":
        pool = inv.free_users()
    else:
        raise ValueError(f"unknown user filter {which!r}")
    if not pool:
        raise RuntimeError(f"no free user matches {which!r}; increase n_hosts")
    return rng.choice(pool)


def bind_roles(
    scenario: Scenario, inv: Inventory, rng: random.Random
) -> tuple[dict[str, str], frozenset[str]]:
    """Resolve every role to a concrete entity. Returns (bindings, victim entities)."""
    users: dict[str, User] = {}
    bindings: dict[str, str] = {}
    victims: set[str] = set()
    for name, role in scenario.roles.items():
        if role.kind == "user":
            user = _pick_user(inv, rng, role.arg)
            users[name] = user
            value = user.user_id
        elif role.kind == "endpoint_of":
            value = users[role.arg].endpoint
        elif role.kind == "endpoint_ip_of":
            value = users[role.arg].ip
        elif role.kind == "admin_of":
            value = users[role.arg].admin_account
        elif role.kind in ("account", "server"):
            value = role.arg
        elif role.kind == "server_ip":
            value = inv.ip_of(role.arg)
        elif role.kind == "external_ip":
            value = inv.external_ips.take()
        else:  # vpn_ip
            value = inv.vpn_ips.take()
        bindings[name] = value
        if role.kind in VICTIM_KINDS:
            victims.add(value)
            inv.reserve(value)
    # A user's own endpoint belongs to them even when the scenario never touches it.
    for user in users.values():
        inv.reserve(user.endpoint, user.ip)
        if user.vpn_ip:
            inv.reserve(user.vpn_ip)
    return bindings, frozenset(victims)


def run_scenario(scenario: Scenario, inv: Inventory, rng: random.Random, start: int) -> ScenarioRun:
    bindings, victims = bind_roles(scenario, inv, rng)

    def resolve(role: str | None) -> str | None:
        return None if role is None else bindings[role]

    drafts: list[Draft] = []
    t = start
    for step in scenario.steps:
        t += rng.randint(step.delay_min[0] * 60, step.delay_min[1] * 60)
        for i in range(rng.randint(*step.count)):
            if i:
                t += rng.randint(*step.gap_s)
            drafts.append(
                Draft(
                    offset=t,
                    rule=get_rule(step.rule),
                    host=bindings[step.host],
                    user=resolve(step.user),
                    src_ip=resolve(step.src),
                    dst_ip=resolve(step.dst),
                    scenario_id=scenario.scenario_id,
                )
            )
    overlap = bindings[scenario.typo_overlap_role] if scenario.typo_overlap_role else None
    return ScenarioRun(scenario, bindings, with_failure_facts(drafts), victims, overlap, start)
