"""Benign background alerts, generated in natural clusters.

Each category owns a few cluster keys (a habitual typo user, a scanner IP, a backup job...).
Every key produces episodes: short bursts of related alerts that share the key's entities.
Keys never use scenario victims, except the one deliberate overlap: the SCN-05 user also has
password-typo noise (see docs/scenarios.md).
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, replace

from nullpunkt.generator.common import Clock, Draft, burst, draft, largest_remainder
from nullpunkt.generator.inventory import DMZ_HOSTS, SHARED_ADMIN, Inventory, User

Episode = Callable[[random.Random, int], list[Draft]]


@dataclass(frozen=True)
class NoiseKey:
    label: str
    entities: tuple[str, ...]
    episode: Episode


@dataclass(frozen=True)
class NoiseCategory:
    name: str
    share: float
    profile: str
    keys: Callable[[NoiseContext], list[NoiseKey]]


@dataclass
class NoiseContext:
    rng: random.Random
    inv: Inventory
    typo_overlap: list[User]

    def users(self, n: int, *, dept: str | None = None, laptop: bool | None = None) -> list[User]:
        """Pick up to ``n`` distinct users who are not scenario victims."""
        pool = self.inv.free_users(dept=dept, laptop=laptop)
        return self.rng.sample(pool, min(n, len(pool)))


# --- categories --------------------------------------------------------------------------------


def _typo_keys(ctx: NoiseContext) -> list[NoiseKey]:
    dc_ip = ctx.inv.ip_of("DC01")
    users = ctx.users(10 - len(ctx.typo_overlap)) + ctx.typo_overlap
    keys = []
    for u in users:

        def episode(rng: random.Random, start: int, u: User = u) -> list[Draft]:
            src = u.vpn_ip if u.vpn_ip and rng.random() < 0.5 else u.ip
            fails = rng.randint(1, 5)
            times = burst(rng, start, fails + 1, (2, 25))
            out = [draft("Failed login", t, "DC01", u.user_id, src, dc_ip) for t in times[:-1]]
            if fails >= 4 and rng.random() < 0.3:
                out.append(draft("Account lockout", times[-1], "DC01", u.user_id, src, dc_ip))
            elif rng.random() < 0.85:
                rule = "Successful login after failures"
                out.append(draft(rule, times[-1], "DC01", u.user_id, src, dc_ip))
            return out

        keys.append(NoiseKey(f"typos:{u.user_id}", (u.user_id,), episode))
    return keys


def _internet_scan_keys(ctx: NoiseContext) -> list[NoiseKey]:
    keys = []
    for scanner in ctx.inv.external_ips.take_many(4):

        def episode(rng: random.Random, start: int, scanner: str = scanner) -> list[Draft]:
            out: list[Draft] = []
            t = start
            for host in rng.sample(DMZ_HOSTS, rng.randint(2, len(DMZ_HOSTS))):
                dst = ctx.inv.ip_of(host)
                times = burst(rng, t, rng.randint(1, 4), (1, 30))
                for ts in times:
                    out.append(draft("Inbound connection blocked", ts, host, None, scanner, dst))
                t = times[-1]
                if rng.random() < 0.3:
                    t += rng.randint(1, 20)
                    out.append(draft("Port scan detected", t, host, None, scanner, dst))
                t += rng.randint(5, 90)
            return out

        keys.append(NoiseKey(f"internet-scan:{scanner}", (scanner,), episode))
    return keys


def _vuln_scanner_keys(ctx: NoiseContext) -> list[NoiseKey]:
    scanner_ip = ctx.inv.ip_of("VULNSCAN01")
    targets = [
        a.host for a in ctx.inv.assets if a.host not in ctx.inv.reserved and a.host != "VULNSCAN01"
    ]

    def episode(rng: random.Random, start: int) -> list[Draft]:
        out = []
        hosts = rng.sample(targets, rng.randint(3, 10))
        for t, host in zip(burst(rng, start, len(hosts), (2, 40)), hosts, strict=True):
            dst = ctx.inv.ip_of(host)
            out.append(draft("Internal network scan", t, host, None, scanner_ip, dst))
            if rng.random() < 0.2:
                rule = "Exploit attempt signature"
                out.append(draft(rule, t + rng.randint(1, 30), host, None, scanner_ip, dst))
        return out

    return [NoiseKey("vuln-scanner:VULNSCAN01", ("VULNSCAN01", scanner_ip), episode)]


SERVER_TARGETS = ("FS01", "FS02", "FINDB01", "HRDB01", "WEB01", "WEB02", "MAIL01", "WSUS01")


def _admin_session(account: str, src: str, ips: dict[str, str]) -> Episode:
    def episode(rng: random.Random, start: int) -> list[Draft]:
        out: list[Draft] = []
        t = start
        for host in rng.sample(SERVER_TARGETS, rng.randint(1, 3)):
            dst = ips[host]
            out.append(draft("SMB admin share access", t, host, account, src, dst))
            if rng.random() < 0.5:
                t += rng.randint(10, 120)
                out.append(draft("Remote service creation", t, host, account, src))
            if rng.random() < 0.3:
                t += rng.randint(10, 120)
                out.append(draft("Privileged login from new host", t, host, account, src, dst))
            if rng.random() < 0.3:
                t += rng.randint(10, 120)
                out.append(draft("Account enumeration via net.exe", t, host, account))
            if rng.random() < 0.2:
                t += rng.randint(10, 120)
                out.append(draft("LDAP enumeration query", t, "DC01", account, src))
            t += rng.randint(30, 600)
        return out

    return episode


def _admin_keys(ctx: NoiseContext) -> list[NoiseKey]:
    sessions = [(SHARED_ADMIN, ctx.inv.ip_of("JUMP01"), "JUMP01")]
    sessions.append(("svc-sccm", ctx.inv.ip_of("SCCM01"), "SCCM01"))
    for admin in ctx.users(1, dept="it"):
        sessions.append((admin.admin_account, admin.ip, admin.endpoint))
    ips = {h: ctx.inv.ip_of(h) for h in SERVER_TARGETS}
    return [
        NoiseKey(
            f"admin-tools:{account}", (account, origin, src), _admin_session(account, src, ips)
        )
        for account, src, origin in sessions
    ]


def _pua_keys(ctx: NoiseContext) -> list[NoiseKey]:
    keys = []
    for u in ctx.users(6, laptop=True):

        def episode(rng: random.Random, start: int, u: User = u) -> list[Draft]:
            times = burst(rng, start, rng.randint(1, 3), (30, 600))
            out = [
                draft("Potentially unwanted application", t, u.endpoint, u.user_id) for t in times
            ]
            if rng.random() < 0.2:
                t = times[-1] + rng.randint(5, 120)
                out.append(draft("Known malware hash detected", t, u.endpoint, u.user_id))
            return out

        keys.append(NoiseKey(f"pua:{u.endpoint}", (u.endpoint, u.user_id), episode))
    return keys


def _new_domain_keys(ctx: NoiseContext) -> list[NoiseKey]:
    keys = []
    for u in ctx.users(8):
        domains = ctx.inv.external_ips.take_many(ctx.rng.randint(1, 3))

        def episode(
            rng: random.Random, start: int, u: User = u, domains: list[str] = domains
        ) -> list[Draft]:
            dst = rng.choice(domains)
            return [
                draft("Connection to newly registered domain", t, "PROXY01", u.user_id, u.ip, dst)
                for t in burst(rng, start, rng.randint(1, 5), (5, 300))
            ]

        keys.append(NoiseKey(f"new-domain:{u.user_id}", (u.user_id, u.ip, *domains), episode))
    return keys


def _patched_server_keys(ctx: NoiseContext) -> list[NoiseKey]:
    sources = ctx.inv.external_ips.take_many(40)
    keys = []
    for host in ("WEB01", "MAIL01", "VPN01"):
        dst = ctx.inv.ip_of(host)

        def episode(
            rng: random.Random, start: int, host: str = host, dst: str = dst
        ) -> list[Draft]:
            return [
                draft("Exploit attempt signature", t, host, None, rng.choice(sources), dst)
                for t in burst(rng, start, rng.randint(1, 6), (1, 120))
            ]

        keys.append(NoiseKey(f"ids-patched:{host}", (host,), episode))
    return keys


def _backup_keys(ctx: NoiseContext) -> list[NoiseKey]:
    src = ctx.inv.ip_of("BACKUP01")
    cloud = ctx.inv.external_ips.take()

    def db_run(rng: random.Random, start: int) -> list[Draft]:
        out = []
        t = start
        for db in ("FINDB01", "HRDB01"):
            out.append(draft("Bulk read of database files", t, db, "svc-backup", src))
            t += rng.randint(120, 900)
        out.append(draft("Large archive created", t, "BACKUP01", "svc-backup"))
        if rng.random() < 0.4:
            t += rng.randint(60, 600)
            out.append(draft("Large outbound transfer", t, "PROXY01", "svc-backup", src, cloud))
        return out

    def file_run(rng: random.Random, start: int) -> list[Draft]:
        out = []
        t = start
        for fs in ("FS01", "FS02"):
            times = burst(rng, t, rng.randint(1, 2), (60, 300))
            for ts in times:
                out.append(draft("Mass file access on share", ts, fs, "svc-backup", src))
            t = times[-1]
            if rng.random() < 0.4:
                t += rng.randint(30, 300)
                out.append(draft("Volume shadow copy deletion", t, fs, "svc-backup"))
            t += rng.randint(120, 900)
        return out

    entities = ("svc-backup", "BACKUP01", src)
    return [
        NoiseKey("backup:databases", entities, db_run),
        NoiseKey("backup:file-servers", entities, file_run),
    ]


def _travel_keys(ctx: NoiseContext) -> list[NoiseKey]:
    egress = ctx.inv.external_ips.take_many(5)  # commercial VPN exit nodes, shared by users
    vpn_ip = ctx.inv.ip_of("VPN01")
    keys = []
    for u in ctx.users(8, laptop=True):

        def episode(rng: random.Random, start: int, u: User = u) -> list[Draft]:
            return [
                draft("Impossible travel login", t, "VPN01", u.user_id, rng.choice(egress), vpn_ip)
                for t in burst(rng, start, rng.randint(1, 2), (60, 1800))
            ]

        keys.append(NoiseKey(f"travel:{u.user_id}", (u.user_id,), episode))
    return keys


def _mail_keys(ctx: NoiseContext) -> list[NoiseKey]:
    recipients = ctx.inv.free_users()
    keys = []
    for sender in ctx.inv.external_ips.take_many(3):

        def episode(rng: random.Random, start: int, sender: str = sender) -> list[Draft]:
            times = burst(rng, start, rng.randint(1, 4), (5, 120))
            out = [draft("Spam campaign blocked", t, "MAIL01", None, sender) for t in times]
            if rng.random() < 0.3:
                r = rng.choice(recipients)
                t = times[-1] + rng.randint(5, 60)
                rule = "Suspicious attachment delivered"
                out.append(draft(rule, t, r.endpoint, r.user_id, sender))
            return out

        keys.append(NoiseKey(f"mail:{sender}", (sender,), episode))
    return keys


def _single(
    rule: str,
    host: str,
    user: str | None = None,
    src: str | None = None,
    dst: str | None = None,
    n: tuple[int, int] = (1, 2),
    gap: tuple[int, int] = (30, 600),
) -> Episode:
    """An episode of 1-2 (by default) alerts from one rule with fixed entities."""

    def episode(rng: random.Random, start: int) -> list[Draft]:
        return [
            draft(rule, t, host, user, src, dst) for t in burst(rng, start, rng.randint(*n), gap)
        ]

    return episode


def _lookalike_keys(ctx: NoiseContext) -> list[NoiseKey]:
    inv = ctx.inv
    dc_ip = inv.ip_of("DC01")
    keys = [
        NoiseKey(
            "lookalike:svc-legacy-rc4",
            ("svc-legacy",),
            _single(
                "Kerberos RC4 service ticket request",
                "DC01",
                "svc-legacy",
                inv.ip_of("HRDB01"),
                dc_ip,
                n=(1, 4),
                gap=(2, 30),
            ),
        ),
        NoiseKey(
            "lookalike:svc-deploy-shell",
            ("svc-deploy", "WEB01"),
            _single("Web server process spawned shell", "WEB01", "svc-deploy"),
        ),
        NoiseKey(
            "lookalike:dc02-replication",
            ("DC02",),
            _single("Directory replication request", "DC01", None, inv.ip_of("DC02"), dc_ip),
        ),
        NoiseKey(
            "lookalike:wsus-patching",
            ("WSUS01", "svc-sccm"),
            _single("Backup service stopped", "WSUS01", "svc-sccm", n=(1, 1)),
        ),
    ]
    for u in ctx.users(1, dept="finance", laptop=False):
        keys.append(
            NoiseKey(
                f"lookalike:finance-addin:{u.user_id}",
                (u.user_id, u.endpoint),
                _single("Office application spawned PowerShell", u.endpoint, u.user_id),
            )
        )
    for u in ctx.users(1, laptop=False):
        keys.append(
            NoiseKey(
                f"lookalike:av-scan:{u.endpoint}",
                (u.endpoint,),
                _single("LSASS memory access", u.endpoint, u.user_id, n=(1, 1)),
            )
        )
    for u in ctx.users(1):
        keys.append(
            NoiseKey(
                f"lookalike:password-manager:{u.user_id}",
                (u.user_id, u.endpoint),
                _single("Browser credential store access", u.endpoint, u.user_id),
            )
        )
    for u in ctx.users(1):
        keys.append(
            NoiseKey(
                f"lookalike:downloads:{u.user_id}",
                (u.user_id, u.endpoint),
                _single("Unsigned executable launched from Downloads", u.endpoint, u.user_id),
            )
        )
    onedrive = inv.external_ips.take()
    for u in ctx.users(1):
        keys.append(
            NoiseKey(
                f"lookalike:cloud-sync:{u.user_id}",
                (u.user_id, u.ip, onedrive),
                _single("Large outbound transfer", "PROXY01", u.user_id, u.ip, onedrive),
            )
        )
    return keys


def _new_host_keys(ctx: NoiseContext) -> list[NoiseKey]:
    inv = ctx.inv
    endpoints = inv.free_users()
    keys = []
    for helper in ctx.users(2, dept="it"):

        def episode(rng: random.Random, start: int, helper: User = helper) -> list[Draft]:
            out = []
            for t in burst(rng, start, rng.randint(1, 3), (120, 1200)):
                target = rng.choice(endpoints)
                rule = "Login from new source host"
                out.append(draft(rule, t, target.endpoint, helper.user_id, helper.ip, target.ip))
            return out

        keys.append(NoiseKey(f"new-host:helpdesk:{helper.user_id}", (helper.user_id,), episode))
    for u in ctx.users(2, laptop=True):

        def remote(rng: random.Random, start: int, u: User = u) -> list[Draft]:
            fs = rng.choice(("FS01", "FS02"))
            rule = "Login from new source host"
            return [draft(rule, start, fs, u.user_id, u.vpn_ip, inv.ip_of(fs))]

        keys.append(NoiseKey(f"new-host:remote:{u.user_id}", (u.user_id,), remote))
    return keys


CATEGORIES: tuple[NoiseCategory, ...] = (
    NoiseCategory("password-typos", 0.13, "business", _typo_keys),
    NoiseCategory("internet-scans", 0.15, "flat", _internet_scan_keys),
    NoiseCategory("internal-vuln-scanner", 0.08, "flat", _vuln_scanner_keys),
    NoiseCategory("approved-admin-tools", 0.10, "business", _admin_keys),
    NoiseCategory("pua-detections", 0.05, "business", _pua_keys),
    NoiseCategory("new-domains", 0.11, "business", _new_domain_keys),
    NoiseCategory("ids-patched-servers", 0.09, "flat", _patched_server_keys),
    NoiseCategory("off-hours-backups", 0.08, "off_hours", _backup_keys),
    NoiseCategory("impossible-travel", 0.06, "flat", _travel_keys),
    NoiseCategory("mail-filtering", 0.07, "business", _mail_keys),
    NoiseCategory("benign-lookalikes", 0.05, "business", _lookalike_keys),
    NoiseCategory("new-host-logins", 0.03, "business", _new_host_keys),
)


@dataclass(frozen=True)
class NoiseResult:
    drafts: list[Draft]
    keys: dict[str, list[NoiseKey]]  # category name -> keys


def fill_category(
    category: NoiseCategory,
    keys: list[NoiseKey],
    quota: int,
    rng: random.Random,
    clock: Clock,
) -> list[Draft]:
    """Produce exactly ``quota`` alerts: every key gets one episode first, then keys are
    drawn with fixed per-key weights (some users are simply noisier than others)."""
    weights = [rng.uniform(0.5, 2.0) for _ in keys]
    out: list[Draft] = []
    turn = 0
    while len(out) < quota:
        if turn < len(keys):
            key = keys[turn]
        else:
            key = rng.choices(keys, weights)[0]
        turn += 1
        episode = key.episode(rng, clock.sample(rng, category.profile))
        episode = [d for d in episode if d.offset < clock.seconds]
        out.extend(
            replace(d, category=category.name, cluster=key.label)
            for d in episode[: quota - len(out)]
        )
    return out


def generate_noise(
    total: int, inv: Inventory, rng: random.Random, clock: Clock, typo_overlap: list[User]
) -> NoiseResult:
    if total < len(CATEGORIES):
        raise ValueError(f"need at least {len(CATEGORIES)} noise alerts, got {total}")
    ctx = NoiseContext(rng, inv, typo_overlap)
    quotas = largest_remainder(total, [c.share for c in CATEGORIES])
    drafts: list[Draft] = []
    keys: dict[str, list[NoiseKey]] = {}
    for category, quota in zip(CATEGORIES, quotas, strict=True):
        keys[category.name] = category.keys(ctx)
        drafts.extend(fill_category(category, keys[category.name], quota, rng, clock))
    return NoiseResult(drafts, keys)
