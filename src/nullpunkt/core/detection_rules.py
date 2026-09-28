"""Detection rule catalog: the rules our (synthetic) SOC runs.

A real SOC knows which ATT&CK technique each of its rules is written to detect, so the
pipeline may use this catalog. What it must never know is whether a particular alert from a
rule is a true positive; that lives only in labels.csv. Every rule fires as noise, and many
also fire during real intrusions.

One technique per rule, always: a true positive's ``true_technique`` is its rule's technique.
"""

from __future__ import annotations

from dataclasses import dataclass

from nullpunkt.core.schema import Severity, Source


@dataclass(frozen=True)
class DetectionRule:
    rule_name: str
    source: Source
    severity: Severity
    technique: str


RULES: tuple[DetectionRule, ...] = (
    # auth
    DetectionRule("Failed login", Source.AUTH, Severity.LOW, "T1110.001"),
    DetectionRule("Successful login after failures", Source.AUTH, Severity.MEDIUM, "T1078"),
    DetectionRule("Account lockout", Source.AUTH, Severity.MEDIUM, "T1110"),
    DetectionRule("Impossible travel login", Source.AUTH, Severity.HIGH, "T1078"),
    DetectionRule("Login from new source host", Source.AUTH, Severity.LOW, "T1078"),
    DetectionRule("Privileged login from new host", Source.AUTH, Severity.MEDIUM, "T1078.002"),
    DetectionRule("Kerberos RC4 service ticket request", Source.AUTH, Severity.LOW, "T1558.003"),
    DetectionRule("Directory replication request", Source.AUTH, Severity.HIGH, "T1003.006"),
    DetectionRule("LDAP enumeration query", Source.AUTH, Severity.LOW, "T1087.002"),
    # email
    DetectionRule("Suspicious attachment delivered", Source.EMAIL, Severity.MEDIUM, "T1566.001"),
    DetectionRule("Spam campaign blocked", Source.EMAIL, Severity.LOW, "T1566"),
    # edr
    DetectionRule(
        "Office application spawned PowerShell", Source.EDR, Severity.MEDIUM, "T1059.001"
    ),
    DetectionRule("Bulk read of database files", Source.EDR, Severity.MEDIUM, "T1005"),
    DetectionRule("Mass file access on share", Source.EDR, Severity.MEDIUM, "T1039"),
    DetectionRule("Large archive created", Source.EDR, Severity.LOW, "T1560.001"),
    DetectionRule("Account enumeration via net.exe", Source.EDR, Severity.LOW, "T1087.002"),
    DetectionRule("Web server process spawned shell", Source.EDR, Severity.HIGH, "T1505.003"),
    DetectionRule("LSASS memory access", Source.EDR, Severity.HIGH, "T1003.001"),
    DetectionRule("Remote service creation", Source.EDR, Severity.MEDIUM, "T1569.002"),
    DetectionRule("Backup service stopped", Source.EDR, Severity.HIGH, "T1489"),
    DetectionRule("Volume shadow copy deletion", Source.EDR, Severity.HIGH, "T1490"),
    DetectionRule(
        "Unsigned executable launched from Downloads", Source.EDR, Severity.LOW, "T1204.002"
    ),
    DetectionRule("Browser credential store access", Source.EDR, Severity.MEDIUM, "T1555.003"),
    DetectionRule("Potentially unwanted application", Source.EDR, Severity.MEDIUM, "T1204.002"),
    DetectionRule("Known malware hash detected", Source.EDR, Severity.CRITICAL, "T1204.002"),
    # ids
    DetectionRule("SMB admin share access", Source.IDS, Severity.MEDIUM, "T1021.002"),
    DetectionRule("Internal network scan", Source.IDS, Severity.MEDIUM, "T1046"),
    DetectionRule("Exploit attempt signature", Source.IDS, Severity.HIGH, "T1190"),
    # firewall
    DetectionRule("Inbound connection blocked", Source.FIREWALL, Severity.LOW, "T1595.001"),
    DetectionRule("Port scan detected", Source.FIREWALL, Severity.HIGH, "T1595.001"),
    # proxy
    DetectionRule(
        "Connection to newly registered domain", Source.PROXY, Severity.HIGH, "T1071.001"
    ),
    DetectionRule("Large outbound transfer", Source.PROXY, Severity.MEDIUM, "T1567.002"),
)

RULES_BY_NAME: dict[str, DetectionRule] = {rule.rule_name: rule for rule in RULES}


def get_rule(rule_name: str) -> DetectionRule:
    try:
        return RULES_BY_NAME[rule_name]
    except KeyError:
        raise KeyError(f"unknown detection rule: {rule_name!r}") from None
