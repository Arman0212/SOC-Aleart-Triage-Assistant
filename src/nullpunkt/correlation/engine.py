"""Correlation: group alerts into incidents.

1. Entities. Each alert has a host, an optional user, and source/destination IPs. IPs that
   belong to an inventory asset become that host, so "login on FINDB01 from 10.30.0.7" links
   to the workstation WS-FIN-03. External IPs stay IP entities.
2. Roles. Actors are the user and the source. The host is *local* when nobody else acted on
   it (no source, or the source is the host itself) and a *target* otherwise. An external
   destination (C2, exfiltration) counts as active.
3. Hubs are detected from the batch (volume, user diversity, fan-out, inventory hints) and
   never create links on their own.
4. Linking. Alerts are processed in time order; each alert links to the previous alert that
   shared one of its non-hub entities within ``window_minutes`` (per-entity chaining, so the
   pass is linear after sorting). Active occurrences link to each other; a target links only
   to activity on that host, never to another target. Scan rules never link through their
   target, and host links need a non-hub actor (or no actor at all), so routine activity of
   hubs cannot stitch hosts together.
5. Recurrence. The same rule on the same key entity stays one incident across the shift if
   the group involves at most ``recurrence_max_users`` users. Optionally all single-user
   activity of a fan-out hub actor becomes one routine incident.
6. Connected components (union-find) become incidents, numbered by (first_seen, first alert).

Union-find rather than networkx: every successful union is recorded as a ``Link``, which is
exactly the explanation the UI needs, and no graph object has to be built. See
docs/architecture.md and docs/correlation_tuning.md.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from ipaddress import ip_address

from nullpunkt.core.config import CorrelationConfig
from nullpunkt.core.detection_rules import RULES_BY_NAME
from nullpunkt.core.schema import Alert, Asset, Incident
from nullpunkt.correlation.result import CorrelationResult, HubStat, Link, split_entity


@dataclass(frozen=True)
class _Row:
    host: str
    user: str | None
    src: str | None
    dst: str | None
    actors: tuple[str, ...]  # user/src entities other than the host itself
    local: bool
    inbound: bool  # source is an external IP
    scan: bool
    ts: float


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, i: int, j: int) -> bool:
        ri, rj = self.find(i), self.find(j)
        if ri == rj:
            return False
        # Attach the later root under the earlier one so roots stay deterministic.
        if ri < rj:
            ri, rj = rj, ri
        self.parent[ri] = rj
        return True


def _entities(alerts: list[Alert], assets: dict[str, Asset], cfg: CorrelationConfig) -> list[_Row]:
    host_of_ip = {asset.ip: host for host, asset in assets.items()}

    def is_external(ip: str | None) -> bool:
        if ip is None or ip in host_of_ip:
            return False
        address = ip_address(ip)
        return not any(address in net for net in cfg.internal_networks)

    def ip_entity(ip: str | None) -> str | None:
        if ip is None:
            return None
        return f"host:{host_of_ip[ip]}" if ip in host_of_ip else f"ip:{ip}"

    rows = []
    for a in alerts:
        host = f"host:{a.host}"
        user = f"user:{a.user}" if a.user else None
        src, dst = ip_entity(a.src_ip), ip_entity(a.dst_ip)
        rule = RULES_BY_NAME.get(a.rule_name)
        scan = rule is not None and rule.technique.startswith(cfg.scan_technique_prefixes)
        actors = tuple(sorted({x for x in (user, src) if x and x != host}))
        rows.append(
            _Row(
                host=host,
                user=user,
                src=src,
                dst=dst,
                actors=actors,
                local=src is None or src == host,
                inbound=is_external(a.src_ip),
                scan=scan,
                ts=a.timestamp.timestamp(),
            )
        )
    return rows


def _entity_stats(
    rows: list[_Row], assets: dict[str, Asset], cfg: CorrelationConfig
) -> list[HubStat]:
    """Statistics for every entity; ``reasons`` is empty for entities that are not hubs."""
    n = len(rows)
    count: Counter[str] = Counter()
    users_of: dict[str, set[str]] = defaultdict(set)
    fanout_of: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        present = {x for x in (r.host, r.user, r.src, r.dst) if x}
        for x in present:
            count[x] += 1
            if r.user and x != r.user:
                users_of[x].add(r.user)
        for actor in r.actors:
            fanout_of[actor].add(r.host)

    hints = set(cfg.hub_hint_types)
    stats = []
    for entity in sorted(count):
        share = count[entity] / n
        kind, value = split_entity(entity)
        reasons = []
        if share >= cfg.hub_min_share and count[entity] >= cfg.hub_min_alerts:
            reasons.append(f"in {share:.1%} of alerts")
        if kind != "user" and len(users_of[entity]) >= cfg.hub_min_users:
            reasons.append(f"shared by {len(users_of[entity])} users")
        if len(fanout_of[entity]) >= cfg.hub_min_fanout:
            reasons.append(f"acts on {len(fanout_of[entity])} hosts")
        if (
            kind == "host"
            and value in assets
            and assets[value].asset_type in hints
            and share >= cfg.hub_hint_min_share
        ):
            reasons.append(f"{assets[value].asset_type.value} in inventory")
        stats.append(
            HubStat(
                entity=entity,
                alerts=count[entity],
                share=share,
                distinct_users=len(users_of[entity]),
                fanout=len(fanout_of[entity]),
                reasons=tuple(reasons),
            )
        )
    return stats


def detect_hubs(
    rows: list[_Row], assets: dict[str, Asset], cfg: CorrelationConfig
) -> list[HubStat]:
    return [s for s in _entity_stats(rows, assets, cfg) if s.reasons]


def entity_stats(
    alerts: list[Alert], assets: dict[str, Asset], config: CorrelationConfig | None = None
) -> dict[str, HubStat]:
    """Hub statistics for every entity in the batch, hub or not (for margin reporting)."""
    cfg = config or CorrelationConfig()
    rows = _entities(alerts, assets, cfg)
    return {s.entity: s for s in _entity_stats(rows, assets, cfg)}


def run_correlation(
    alerts: list[Alert], assets: dict[str, Asset], config: CorrelationConfig | None = None
) -> CorrelationResult:
    cfg = config or CorrelationConfig()
    alerts = sorted(alerts, key=lambda a: (a.timestamp, a.alert_id))
    rows = _entities(alerts, assets, cfg)
    hub_stats = detect_hubs(rows, assets, cfg)
    hubs = {h.entity for h in hub_stats}
    fanout_hubs = {h.entity for h in hub_stats if any("acts on" in r for r in h.reasons)}
    window = cfg.window_minutes * 60

    uf = _UnionFind(len(alerts))
    links: list[tuple[int, int, str, str, str | None]] = []

    def join(i: int, j: int, reason: str, entity: str, rule: str | None = None) -> None:
        if uf.union(i, j):
            links.append((i, j, reason, entity, rule))

    # Per-entity chaining.
    last_active: dict[str, int] = {}
    last_target: dict[str, int] = {}
    for i, r in enumerate(rows):
        anchored = not r.actors or any(a not in hubs for a in r.actors)
        active = set(r.actors)
        if r.inbound and not r.scan:
            # Inbound noise rotates through internet sources; only the target and the
            # signature are stable, so an external source links only when it is scanning.
            active.discard(r.src)
        if r.dst and r.dst.startswith("ip:"):
            active.add(r.dst)
        if r.local:
            active.add(r.host)
        for entity in sorted(active):
            if entity in hubs or (entity == r.host and not anchored):
                continue
            for pointer, reason in ((last_active, "entity"), (last_target, "target")):
                j = pointer.get(entity)
                if j is not None and r.ts - rows[j].ts <= window:
                    join(i, j, reason, entity)
            last_active[entity] = i
        if not r.local and not r.scan and r.host not in hubs and anchored:
            j = last_active.get(r.host)
            if j is not None and r.ts - rows[j].ts <= window:
                join(i, j, "target", r.host)
            last_target[r.host] = i

    # Recurrence and hub routines.
    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, (a, r) in enumerate(zip(alerts, rows, strict=True)):
        if r.inbound and not r.scan and not r.local:
            keys = [r.host]  # inbound noise: sources rotate, the target and signature do not
        else:
            keys = [x for x in (r.user, r.src) if x]
        for key in keys:
            groups[("recurrence", a.rule_name + "\0" + key)].append(i)
        if cfg.hub_actor_routine:
            for actor in r.actors:
                if actor in fanout_hubs:
                    groups[("routine", actor)].append(i)
    max_gap = (
        None if cfg.recurrence_max_gap_minutes is None else cfg.recurrence_max_gap_minutes * 60
    )
    for (reason, key), members in groups.items():
        if len(members) < cfg.recurrence_min_alerts:
            continue
        if len({rows[i].user for i in members if rows[i].user}) > cfg.recurrence_max_users:
            continue
        rule, _, entity = key.rpartition("\0")
        for p, q in zip(members, members[1:], strict=False):
            if max_gap is None or rows[q].ts - rows[p].ts <= max_gap:
                join(q, p, reason, entity, rule or None)

    return _build_result(alerts, rows, uf, links, hub_stats, cfg)


def _build_result(
    alerts: list[Alert],
    rows: list[_Row],
    uf: _UnionFind,
    links: list[tuple[int, int, str, str, str | None]],
    hub_stats: list[HubStat],
    cfg: CorrelationConfig,
) -> CorrelationResult:
    members: dict[int, list[int]] = defaultdict(list)
    for i in range(len(alerts)):
        members[uf.find(i)].append(i)
    # Alerts are time-sorted, so each member list is too; order components by first alert.
    components = sorted(
        members.values(), key=lambda m: (alerts[m[0]].timestamp, alerts[m[0]].alert_id)
    )
    if len(components) > 9999:
        raise ValueError(f"{len(components)} incidents exceed the INC-#### ID space")

    incidents: list[Incident] = []
    incident_of: dict[str, str] = {}
    root_to_id: dict[int, str] = {}
    for n, comp in enumerate(components, start=1):
        incident_id = f"INC-{n:04d}"
        root_to_id[uf.find(comp[0])] = incident_id
        hosts, users, ips = set(), set(), set()
        for i in comp:
            a, r = alerts[i], rows[i]
            hosts.update(
                split_entity(x)[1] for x in (r.host, r.src, r.dst) if x and x.startswith("host:")
            )
            if a.user:
                users.add(a.user)
            ips.update(ip for ip in (a.src_ip, a.dst_ip) if ip)
            incident_of[a.alert_id] = incident_id
        incidents.append(
            Incident(
                incident_id=incident_id,
                alert_ids=[alerts[i].alert_id for i in comp],
                first_seen=alerts[comp[0]].timestamp,
                last_seen=alerts[comp[-1]].timestamp,
                hosts=sorted(hosts),
                users=sorted(users),
                ips=sorted(ips),
            )
        )

    by_incident: dict[str, list[Link]] = {inc.incident_id: [] for inc in incidents}
    for i, j, reason, entity, rule in links:
        link = Link(
            alert_id=alerts[i].alert_id,
            linked_to=alerts[j].alert_id,
            reason=reason,
            entity=entity,
            gap_seconds=abs(rows[i].ts - rows[j].ts),
            rule_name=rule,
        )
        by_incident[root_to_id[uf.find(i)]].append(link)
    for incident_links in by_incident.values():
        incident_links.sort(key=lambda link: (link.alert_id, link.linked_to))
    return CorrelationResult(incidents, by_incident, hub_stats, cfg, incident_of)


def correlate(
    alerts: list[Alert], assets: dict[str, Asset], config: CorrelationConfig | None = None
) -> list[Incident]:
    """Group alerts into incidents. Use ``run_correlation`` for link reasons and hubs."""
    return run_correlation(alerts, assets, config).incidents
