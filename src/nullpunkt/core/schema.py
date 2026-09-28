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
SCENARIO_ID_PATTERN = r"^SCN-\d{2}$"


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
    scenario_id: str | None = Field(default=None, pattern=SCENARIO_ID_PATTERN)
    is_true_positive: bool
    true_technique: str | None = Field(default=None, pattern=TECHNIQUE_PATTERN)


class IncidentStatus(StrEnum):
    OPEN = "open"
    APPROVED = "approved"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"


class DecisionAction(StrEnum):
    APPROVE = "approve"
    EDIT = "edit"
    DISMISS = "dismiss"
    ESCALATE = "escalate"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class BriefSource(StrEnum):
    LLM = "llm"
    TEMPLATE = "template"


class Technique(ContractModel):
    technique_id: str = Field(pattern=TECHNIQUE_PATTERN)
    name: str
    tactic: str
    confirmed: bool = True


class ScoreBreakdown(ContractModel):
    severity_weight: int = Field(ge=1, le=4)
    asset_criticality: int = Field(ge=1, le=5)
    stage_multiplier: float = Field(ge=1.0)
    noise_penalty: float = Field(default=1.0, gt=0, le=1.0)
    risk_score: float = Field(ge=0, le=100)
    explanation: str


class Brief(ContractModel):
    summary: str
    affected_assets: list[str]
    techniques: list[str]
    timeline: list[str]
    next_action: str
    confidence: Confidence
    generated_by: BriefSource
    validated: bool


class Incident(ContractModel):
    incident_id: str = Field(pattern=INCIDENT_ID_PATTERN)
    alert_ids: list[str] = Field(min_length=1)
    first_seen: datetime
    last_seen: datetime
    hosts: list[str]
    users: list[str] = []
    ips: list[str] = []
    techniques: list[Technique] = []
    score: ScoreBreakdown | None = None
    brief: Brief | None = None
    status: IncidentStatus = IncidentStatus.OPEN

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return require_utc(v)


class Decision(ContractModel):
    """One analyst action. MTTT is computed from these records."""

    incident_id: str = Field(pattern=INCIDENT_ID_PATTERN)
    action: DecisionAction
    analyst: str
    opened_at: datetime
    decided_at: datetime
    edited_brief: str | None = None
    notes: str | None = None

    @field_validator("opened_at", "decided_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return require_utc(v)

    @property
    def triage_seconds(self) -> float:
        return (self.decided_at - self.opened_at).total_seconds()
