"""Nullpunkt data contract.

Every module imports its data types from here. The pipeline only ever sees
Alert and Asset; GroundTruth lives in a separate file and is read only by the
evaluation package, so the system can never peek at the answers.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0"

ALERT_ID_PATTERN = r"^ALR-\d{6}$"
INCIDENT_ID_PATTERN = r"^INC-\d{4}$"
TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"


class Source(StrEnum):
    FIREWALL = "firewall"
    EDR = "edr"
    IDS = "ids"
    AUTH = "auth"
    EMAIL = "email"
    PROXY = "proxy"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AssetType(StrEnum):
    DOMAIN_CONTROLLER = "domain_controller"
    DATABASE = "database"
    FILE_SERVER = "file_server"
    MAIL_SERVER = "mail_server"
    VPN_GATEWAY = "vpn_gateway"
    WEB_SERVER = "web_server"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"


class ContractModel(BaseModel):
    """Base for every contract model: unknown fields are an error."""

    model_config = ConfigDict(extra="forbid")


def require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware UTC, e.g. 2026-10-01T09:00:00Z")
    return value


def check_ip(value: str | None) -> str | None:
    if value is not None:
        ipaddress.ip_address(value)
    return value


class Alert(ContractModel):
    """One alert exactly as the SOC sees it. Never contains ground truth."""

    alert_id: str = Field(pattern=ALERT_ID_PATTERN)
    timestamp: datetime
    source: Source
    rule_name: str = Field(min_length=1)
    severity: Severity
    host: str = Field(min_length=1)
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    message: str

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return require_utc(v)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _ips(cls, v: str | None) -> str | None:
        return check_ip(v)


class Asset(ContractModel):
    host: str = Field(min_length=1)
    ip: str
    asset_type: AssetType
    owner: str
    criticality: int = Field(ge=1, le=5)

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        return check_ip(v)


class GroundTruth(ContractModel):
    """Hidden label for one alert. Only nullpunkt.evaluation may load these."""

    alert_id: str = Field(pattern=ALERT_ID_PATTERN)
    scenario_id: str | None = None
    is_true_positive: bool
    true_technique: str | None = Field(default=None, pattern=TECHNIQUE_PATTERN)