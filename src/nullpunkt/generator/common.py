"""Small building blocks shared by the generator modules."""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import timedelta
from fractions import Fraction

from nullpunkt.core.detection_rules import DetectionRule, get_rule
from nullpunkt.generator.config import GeneratorConfig

# Probability weight of an instant inside vs outside business hours.
BUSINESS_WEIGHT = 3.0
OFF_HOURS_WEIGHT = 1.0


@dataclass(frozen=True)
class Draft:
    """An alert before IDs and messages are assigned. Offsets are seconds from shift start."""

    offset: int
    rule: DetectionRule
    host: str
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    scenario_id: str | None = None
    category: str | None = None  # noise category
    cluster: str | None = None  # noise cluster key label
    facts: tuple[tuple[str, str], ...] = ()  # message fields fixed by what really happened


FAILURE_SUMMARY_RULES = ("Successful login after failures", "Account lockout")


def with_failure_facts(drafts: list[Draft]) -> list[Draft]:
    """Give each "Successful login after failures" / "Account lockout" draft the real number of
    failed logins immediately before it (same user and host) and how many minutes they spanned,
    so its message states what actually happened."""
    out: list[Draft] = []
    for d in drafts:
        if d.rule.rule_name in FAILURE_SUMMARY_RULES:
            failures: list[Draft] = []
            for prev in reversed(out):
                if (prev.rule.rule_name, prev.user, prev.host) != ("Failed login", d.user, d.host):
                    break
                failures.append(prev)
            if failures:
                span = d.offset - failures[-1].offset
                minutes = max(1, -(-span // 60))
                d = replace(d, facts=(("n", str(len(failures))), ("minutes", str(minutes))))
        out.append(d)
    return out


def draft(
    rule_name: str,
    offset: int,
    host: str,
    user: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
) -> Draft:
    """An alert for ``rule_name`` at ``offset`` seconds into the shift, before rendering."""
    return Draft(offset, get_rule(rule_name), host, user, src_ip, dst_ip)


class Clock:
    """Samples offsets within the shift, weighted towards (or away from) business hours."""

    def __init__(self, config: GeneratorConfig) -> None:
        self.config = config
        self.seconds = config.shift_seconds
        start = config.shift_start_utc
        # Precompute business-hours membership per minute so sampling stays cheap.
        minutes = (self.seconds + 59) // 60
        self._business = [
            config.is_business_hours(start + timedelta(minutes=m)) for m in range(minutes)
        ]

    def is_business(self, offset: int) -> bool:
        return self._business[min(offset // 60, len(self._business) - 1)]

    def sample(self, rng: random.Random, profile: str, latest: int | None = None) -> int:
        """Sample an offset in [0, latest]. profile: 'business', 'off_hours' or 'flat'."""
        latest = self.seconds - 1 if latest is None else latest
        top = max(BUSINESS_WEIGHT, OFF_HOURS_WEIGHT)
        while True:
            offset = rng.randint(0, latest)
            if profile == "flat":
                return offset
            business = self.is_business(offset)
            if profile == "business":
                weight = BUSINESS_WEIGHT if business else OFF_HOURS_WEIGHT
            elif profile == "off_hours":
                weight = OFF_HOURS_WEIGHT if business else BUSINESS_WEIGHT
            else:
                raise ValueError(f"unknown time profile {profile!r}")
            if rng.random() * top < weight:
                return offset


class IpPool:
    """Hands out unique addresses from a fixed list, in a seeded random order."""

    def __init__(self, addresses: Sequence[str], rng: random.Random) -> None:
        self._free = list(addresses)
        rng.shuffle(self._free)

    def take(self) -> str:
        if not self._free:
            raise RuntimeError("IP pool exhausted")
        return self._free.pop()

    def take_many(self, n: int) -> list[str]:
        return [self.take() for _ in range(n)]


def largest_remainder(total: int, weights: Sequence[float]) -> list[int]:
    """Split ``total`` into integers proportional to ``weights`` that sum exactly to it.

    Uses exact fractions: float ``sum()`` changed in Python 3.12 (compensated summation), and a
    one-ulp difference would shift a quota by one and break cross-version determinism.
    """
    exact = [Fraction(w) for w in weights]
    weight_sum = sum(exact, Fraction(0))
    raw = [total * w / weight_sum for w in exact]
    counts = [int(r) for r in raw]
    by_remainder = sorted(range(len(raw)), key=lambda i: (-(raw[i] - counts[i]), i))
    for i in by_remainder[: total - sum(counts)]:
        counts[i] += 1
    return counts


def burst(rng: random.Random, start: int, n: int, gap: tuple[int, int]) -> list[int]:
    """Offsets for ``n`` events starting at ``start`` with random gaps (seconds)."""
    offsets = [start]
    for _ in range(n - 1):
        offsets.append(offsets[-1] + rng.randint(*gap))
    return offsets
