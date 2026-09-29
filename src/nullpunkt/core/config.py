"""Pipeline configuration (configs/pipeline.yaml).

One section per concern: ``site`` (display settings) and one per pipeline stage (``correlation``,
``scoring``, ``briefing``).
"""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


class ScoringConfig(_Section):
    """Settings for nullpunkt.scoring. Defaults are the tuned values from
    docs/scoring_evaluation.md.

    risk = 100 x (severity x criticality of the riskiest alert-on-asset / 20)
               x (stage multiplier / its maximum) x noise penalty
    """

    stage_step: float = Field(default=1.0, gt=0)
    """Stage multiplier = 1 + stage_step x (distinct tactics - 1), up to ``tactic_cap`` tactics."""
    tactic_cap: int = Field(default=4, ge=2, le=15)
    routine_min_hours: int = Field(default=3, ge=2)
    """A (rule, actor) pair firing in at least this many different hours of the batch is routine."""
    routine_penalty: float = Field(default=0.1, gt=0, le=1)
    """Multiplier for incidents made only of routine alerts."""
    relay_asset_types: tuple[AssetType, ...] = (
        AssetType.DOMAIN_CONTROLLER,
        AssetType.PROXY,
        AssetType.MAIL_SERVER,
        AssetType.VPN_GATEWAY,
    )
    """Infrastructure that carries other assets' traffic. A source-side alert on one of these
    never takes its criticality; if the source cannot be resolved, criticality is 1."""
    tier_thresholds: tuple[float, float, float] = (23.0, 6.2, 3.8)
    """Minimum risk score for P1, P2 and P3; anything lower is P4. Fixed thresholds, not ranks."""

    @model_validator(mode="after")
    def _descending(self) -> ScoringConfig:
        p1, p2, p3 = self.tier_thresholds
        if not 0 < p3 < p2 < p1 <= 100:
            raise ValueError("tier_thresholds must satisfy 0 < P3 < P2 < P1 <= 100")
        return self


class BriefingConfig(_Section):
    """Settings for nullpunkt.briefing. ``OLLAMA_MODEL`` and ``OLLAMA_HOST`` (environment or
    .env) override ``model`` and ``host``."""

    model: str = "phi4-mini"
    host: str = "http://localhost:11434"
    timeout_seconds: float = Field(default=120, gt=0)
    top_n: int = Field(default=10, ge=0)
    max_retries: int = Field(default=1, ge=0, le=3)
    prompt_version: str = Field(default="v1", pattern=r"^v\d+$")
    temperature: float = Field(default=0.0, ge=0)
    seed: int = 42
    num_ctx: int = Field(default=8192, ge=1024)
    cache_dir: str | None = "data/generated/brief_cache"
    """Where validated LLM briefs are cached; None disables the cache."""


class SiteConfig(_Section):
    timezone: str = "Asia/Kolkata"
    """Company time zone for display (briefs, UI). Must match configs/generator.yaml."""

    @field_validator("timezone")
    @classmethod
    def _known_zone(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown time zone {v!r}") from exc
        return v


class PipelineConfig(_Section):
    site: SiteConfig = SiteConfig()
    correlation: CorrelationConfig = CorrelationConfig()
    scoring: ScoringConfig = ScoringConfig()
    briefing: BriefingConfig = BriefingConfig()


def load_pipeline_config(path: str | Path) -> PipelineConfig:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return PipelineConfig.model_validate(data)
