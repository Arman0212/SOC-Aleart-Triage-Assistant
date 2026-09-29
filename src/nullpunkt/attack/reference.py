"""MITRE ATT&CK reference data (a committed subset of Enterprise ATT&CK, see
scripts/build_attack_subset.py). Loaded from package data; no network access."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from importlib.resources import files


@dataclass(frozen=True)
class Tactic:
    id: str  # e.g. TA0001
    shortname: str  # e.g. initial-access
    name: str  # e.g. Initial Access


@dataclass(frozen=True)
class TechniqueInfo:
    id: str
    name: str
    tactics: tuple[str, ...]  # official tactic short names, kill-chain order


@dataclass(frozen=True)
class AttackReference:
    """The bundled ATT&CK subset: version, source, tactics in kill-chain order and techniques."""

    version: str
    source: str
    tactics: tuple[Tactic, ...]  # kill-chain order
    techniques: dict[str, TechniqueInfo]

    def tactic(self, shortname: str) -> Tactic:
        for tactic in self.tactics:
            if tactic.shortname == shortname:
                return tactic
        raise KeyError(f"unknown ATT&CK tactic {shortname!r}")

    def tactic_index(self, shortname: str) -> int:
        """Position in the kill chain (0 = reconnaissance)."""
        return self.tactics.index(self.tactic(shortname))


@cache
def load_reference() -> AttackReference:
    """The bundled Enterprise ATT&CK subset: tactics in kill-chain order and the catalog's
    techniques."""
    raw = json.loads(
        files("nullpunkt.attack").joinpath("data/attack_subset.json").read_text(encoding="utf-8")
    )
    return AttackReference(
        version=raw["attack_version"],
        source=raw["source"],
        tactics=tuple(Tactic(t["id"], t["shortname"], t["name"]) for t in raw["tactics"]),
        techniques={
            tid: TechniqueInfo(tid, t["name"], tuple(t["tactics"]))
            for tid, t in raw["techniques"].items()
        },
    )
