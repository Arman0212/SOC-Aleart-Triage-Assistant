"""The baseline arm's alert list: raw alerts only, sorted the way a SIEM list is (severity, then
time), with simple search and filters. No incidents, scores, tiers, ATT&CK or briefs."""

from __future__ import annotations

from nullpunkt.app.views import local_time
from nullpunkt.core.schema import SEVERITY_WEIGHT, Alert

COLUMNS = ("Time", "Severity", "Source", "Rule", "Host", "User", "Source IP", "Destination IP",
           "Message", "Alert")  # fmt: skip


def alert_table(alerts: list[Alert], tz: str) -> list[dict]:
    ordered = sorted(alerts, key=lambda a: (-SEVERITY_WEIGHT[a.severity], a.timestamp, a.alert_id))
    return [
        dict(
            zip(
                COLUMNS,
                (
                    local_time(a.timestamp, tz, "%H:%M:%S"),
                    a.severity.value,
                    a.source.value,
                    a.rule_name,
                    a.host,
                    a.user or "",
                    a.src_ip or "",
                    a.dst_ip or "",
                    a.message,
                    a.alert_id,
                ),
                strict=True,
            )
        )
        for a in ordered
    ]


def filter_alerts(
    rows: list[dict],
    query: str = "",
    severities: list[str] | None = None,
    sources: list[str] | None = None,
    host: str = "",
    user: str = "",
) -> list[dict]:
    """Case-insensitive search over rule, message, host, user and IPs; empty filters match all."""
    q, h, u = query.strip().lower(), host.strip().lower(), user.strip().lower()
    out = []
    for r in rows:
        if severities and r["Severity"] not in severities:
            continue
        if sources and r["Source"] not in sources:
            continue
        if h and h not in r["Host"].lower():
            continue
        if u and u not in r["User"].lower():
            continue
        if q:
            haystack = " ".join(
                (r["Rule"], r["Message"], r["Host"], r["User"], r["Source IP"],
                 r["Destination IP"], r["Alert"])
            ).lower()  # fmt: skip
            if q not in haystack:
                continue
        out.append(r)
    return out
