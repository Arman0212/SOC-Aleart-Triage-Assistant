"""Pipeline configuration (configs/pipeline.yaml).

One section per pipeline stage. Only ``correlation`` exists so far; scoring and briefing add
their own sections here later.
"""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from nullpunkt.core.schema import AssetType


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CorrelationConfig(_Section):
    """Settings for nullpunkt.correlation. Defaults are the tuned values from
    docs/correlation_tuning.md."""

    # Linking: an alert links to the previous alert sharing an entity within this window.
    window_minutes: float = Field(default=150, gt=0)

    # Hub detection. An entity is a hub if ANY of these holds.
    hub_min_share: float = Field(default=0.08, gt=0, le=1)
    """...it appears in at least this share of all alerts (and in at least ``hub_min_alerts``
    alerts, so a small batch does not turn everything into a hub)."""
    hub_min_alerts: int = Field(default=20, ge=1)
    hub_min_users: int = Field(default=6, ge=2)
    """...it co-occurs with at least this many distinct users (non-user entities)."""
    hub_min_fanout: int = Field(default=6, ge=2)
    """...as an actor (user or source) it acts on at least this many distinct hosts."""
    hub_hint_types: tuple[AssetType, ...] = (
        AssetType.DOMAIN_CONTROLLER,
        AssetType.PROXY,
        AssetType.VULN_SCANNER,
        AssetType.BACKUP_SERVER,
        AssetType.SOFTWARE_DISTRIBUTION,
    )
    """...it is an inventory asset of one of these types and appears in at least
    ``hub_hint_min_share`` of alerts (a SOC knows its own busy infrastructure)."""
    hub_hint_min_share: float = Field(default=0.01, gt=0, le=1)

    # The organisation's own address space. Sources outside it are external (inbound).
    internal_networks: tuple[IPv4Network | IPv6Network, ...] = (
        IPv4Network("10.0.0.0/8"),
        IPv4Network("172.16.0.0/12"),
        IPv4Network("192.168.0.0/16"),
    )

    # Rules whose technique starts with one of these prefixes are scans: they never link
    # through the host they touched (a probe is not evidence anything happened there).
    scan_technique_prefixes: tuple[str, ...] = ("T1595", "T1046")

    # Recurrence: the same rule on the same key entity stays one incident across the shift.
    recurrence_min_alerts: int = Field(default=2, ge=2)
    recurrence_max_users: int = Field(default=1, ge=0)
    """A recurring group links only if it involves at most this many distinct users."""
    recurrence_max_gap_minutes: float | None = Field(default=None, gt=0)
    """None = no limit; otherwise a recurring group splits on longer gaps."""

    hub_actor_routine: bool = True
    """Merge all single-user activity of a fan-out hub actor (shared admin, service account,
    scanner) into one routine incident, across rules."""


class PipelineConfig(_Section):
    correlation: CorrelationConfig = CorrelationConfig()


def load_pipeline_config(path: str | Path) -> PipelineConfig:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return PipelineConfig.model_validate(data)
