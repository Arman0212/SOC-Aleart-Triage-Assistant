"""Generator configuration (configs/generator.yaml).

Shift start and business hours are given in the company's local time zone and converted to
UTC; everything the generator writes is UTC.
"""

from __future__ import annotations

from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCENARIO_IDS = ("SCN-01", "SCN-02", "SCN-03", "SCN-04", "SCN-05", "SCN-06", "SCN-07")


class GeneratorConfig(BaseModel):
    """configs/generator.yaml: seed, size, shift window, business hours and scenarios."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seed: int = 42
    n_hosts: int = Field(default=80, ge=60, le=500)
    n_alerts: int = Field(default=3000, ge=500, le=999_999)
    company_timezone: str = "Asia/Kolkata"
    shift_start: datetime = Field(
        default=datetime(2026, 10, 1, 9, 0), description="naive, in company_timezone"
    )
    shift_hours: float = Field(default=12, gt=0, le=24)
    business_start: time = time(9, 0)
    business_end: time = time(18, 0)
    scenarios: list[str] = Field(default_factory=lambda: list(SCENARIO_IDS))

    @field_validator("company_timezone")
    @classmethod
    def _known_zone(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown time zone {v!r}") from exc
        return v

    @field_validator("shift_start")
    @classmethod
    def _naive_local(cls, v: datetime) -> datetime:
        if v.tzinfo is not None:
            raise ValueError("shift_start is local time in company_timezone; omit the offset")
        return v

    @field_validator("scenarios")
    @classmethod
    def _known_scenarios(cls, v: list[str]) -> list[str]:
        unknown = sorted(set(v) - set(SCENARIO_IDS))
        if unknown:
            raise ValueError(f"unknown scenarios: {unknown}")
        if len(set(v)) != len(v):
            raise ValueError("scenarios must not repeat")
        return v

    @model_validator(mode="after")
    def _business_window(self) -> GeneratorConfig:
        if self.business_end <= self.business_start:
            raise ValueError("business_end must be after business_start")
        return self

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.company_timezone)

    @property
    def shift_start_utc(self) -> datetime:
        return self.shift_start.replace(tzinfo=self.tz).astimezone(UTC)

    @property
    def shift_end_utc(self) -> datetime:
        return self.shift_start_utc + timedelta(hours=self.shift_hours)

    @property
    def shift_seconds(self) -> int:
        return int(self.shift_hours * 3600)

    def is_business_hours(self, instant: datetime) -> bool:
        local = instant.astimezone(self.tz).time()
        return self.business_start <= local < self.business_end


def load_config(path: str | Path, seed: int | None = None) -> GeneratorConfig:
    """Load a YAML config; ``seed`` (e.g. from the CLI) overrides the file's seed."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if seed is not None:
        data["seed"] = seed
    return GeneratorConfig.model_validate(data)
