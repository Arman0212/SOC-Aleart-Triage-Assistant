"""Detection rule catalog: the rules our (synthetic) SOC runs.

A real SOC knows which ATT&CK technique each of its rules is written to detect, so the
pipeline may use this catalog. What it must never know is whether a particular alert from a
rule is a true positive; that lives only in labels.csv. Every rule fires as noise, and many
also fire during real intrusions.

One technique per rule, always: a true positive's ``true_technique`` is its rule's technique.
Each rule also records the tactic it detects that technique in and which asset its alerts put
at risk (see ``DetectionRule``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from nullpunkt.core.schema import Severity, Source

AssetAtRisk = Literal["host", "source"]


@dataclass(frozen=True)
class DetectionRule:
    """One detection rule.

    ``tactic`` is the ATT&CK tactic (v19.2 short name) the rule detects its technique in; it must
    be one of that technique's official tactics. ``asset_at_risk`` says which asset an alert from
    this rule threatens: ``"host"`` for the alert's host, ``"source"`` for the asset the activity
    comes from. Rules whose alerts sit on infrastructure doing its normal job (the DC
    authenticating a login, the proxy carrying a request, the mail gateway filtering mail, the
    VPN concentrator) are ``"source"``, so that infrastructure never lends its criticality.
    """

    rule_name: str
    source: Source
    severity: Severity
    technique: str
    tactic: str
    asset_at_risk: AssetAtRisk


RULES: tuple[DetectionRule, ...] = (
    # auth
    DetectionRule(
        "Failed login", Source.AUTH, Severity.LOW, "T1110.001", "credential-access", "source"
    ),
    DetectionRule(
        "Successful login after failures",
        Source.AUTH,
        Severity.MEDIUM,
        "T1078",
        "initial-access",
        "source",
    ),
    DetectionRule(
        "Account lockout", Source.AUTH, Severity.MEDIUM, "T1110", "credential-access", "source"
    ),
    DetectionRule(
        "Impossible travel login", Source.AUTH, Severity.HIGH, "T1078", "initial-access", "source"
    ),
    DetectionRule(
        "Login from new source host", Source.AUTH, Severity.LOW, "T1078", "stealth", "host"
    ),
    DetectionRule(
        "Privileged login from new host",
        Source.AUTH,
        Severity.MEDIUM,
        "T1078.002",
        "privilege-escalation",
        "host",
    ),
    DetectionRule(
        "Kerberos RC4 service ticket request",
        Source.AUTH,
        Severity.LOW,
        "T1558.003",
        "credential-access",
        "source",
    ),
    DetectionRule(
        "Directory replication request",
        Source.AUTH,
        Severity.HIGH,
        "T1003.006",
        "credential-access",
        "host",
    ),
    DetectionRule(
        "LDAP enumeration query", Source.AUTH, Severity.LOW, "T1087.002", "discovery", "source"
    ),
    # email
    DetectionRule(
        "Suspicious attachment delivered",
        Source.EMAIL,
        Severity.MEDIUM,
        "T1566.001",
        "initial-access",
        "source",
    ),
    DetectionRule(
        "Spam campaign blocked", Source.EMAIL, Severity.LOW, "T1566", "initial-access", "source"
    ),
    # edr
    DetectionRule(
        "Office application spawned PowerShell",
        Source.EDR,
        Severity.MEDIUM,
        "T1059.001",
        "execution",
        "host",
    ),
    DetectionRule(
        "Bulk read of database files", Source.EDR, Severity.MEDIUM, "T1005", "collection", "host"
    ),
    DetectionRule(
        "Mass file access on share", Source.EDR, Severity.MEDIUM, "T1039", "collection", "host"
    ),
    DetectionRule(
        "Large archive created", Source.EDR, Severity.LOW, "T1560.001", "collection", "host"
    ),
    DetectionRule(
        "Account enumeration via net.exe",
        Source.EDR,
        Severity.LOW,
        "T1087.002",
        "discovery",
        "host",
    ),
    DetectionRule(
        "Web server process spawned shell",
        Source.EDR,
        Severity.HIGH,
        "T1505.003",
        "persistence",
        "host",
    ),
    DetectionRule(
        "LSASS memory access", Source.EDR, Severity.HIGH, "T1003.001", "credential-access", "host"
    ),
    DetectionRule(
        "Remote service creation", Source.EDR, Severity.MEDIUM, "T1569.002", "execution", "host"
    ),
    DetectionRule("Backup service stopped", Source.EDR, Severity.HIGH, "T1489", "impact", "host"),
    DetectionRule(
        "Volume shadow copy deletion", Source.EDR, Severity.HIGH, "T1490", "impact", "host"
    ),
    DetectionRule(
        "Unsigned executable launched from Downloads",
        Source.EDR,
        Severity.LOW,
        "T1204.002",
        "execution",
        "host",
    ),
    DetectionRule(
        "Browser credential store access",
        Source.EDR,
        Severity.MEDIUM,
        "T1555.003",
        "credential-access",
        "host",
    ),
    DetectionRule(
        "Potentially unwanted application",
        Source.EDR,
        Severity.MEDIUM,
        "T1204.002",
        "execution",
        "host",
    ),
    DetectionRule(
        "Known malware hash detected",
        Source.EDR,
        Severity.CRITICAL,
        "T1204.002",
        "execution",
        "host",
    ),
    # ids
    DetectionRule(
        "SMB admin share access",
        Source.IDS,
        Severity.MEDIUM,
        "T1021.002",
        "lateral-movement",
        "host",
    ),
    DetectionRule(
        "Internal network scan", Source.IDS, Severity.MEDIUM, "T1046", "discovery", "source"
    ),
    DetectionRule(
        "Exploit attempt signature", Source.IDS, Severity.HIGH, "T1190", "initial-access", "host"
    ),
    # firewall
    DetectionRule(
        "Inbound connection blocked",
        Source.FIREWALL,
        Severity.LOW,
        "T1595.001",
        "reconnaissance",
        "host",
    ),
    DetectionRule(
        "Port scan detected", Source.FIREWALL, Severity.HIGH, "T1595.001", "reconnaissance", "host"
    ),
    # proxy
    DetectionRule(
        "Connection to newly registered domain",
        Source.PROXY,
        Severity.HIGH,
        "T1071.001",
        "command-and-control",
        "source",
    ),
    DetectionRule(
        "Large outbound transfer",
        Source.PROXY,
        Severity.MEDIUM,
        "T1567.002",
        "exfiltration",
        "source",
    ),
)

RULES_BY_NAME: dict[str, DetectionRule] = {rule.rule_name: rule for rule in RULES}


def get_rule(rule_name: str) -> DetectionRule:
    """The catalog entry for ``rule_name``; KeyError if the rule is unknown."""
    try:
        return RULES_BY_NAME[rule_name]
    except KeyError:
        raise KeyError(f"unknown detection rule: {rule_name!r}") from None
