"""Alert message templates, one set per detection rule.

``render_message`` is the only way a message is produced, and it takes no scenario
information, so noise and attack alerts from the same rule are drawn from the same templates
and the same vocabularies. Templates may reference the alert's own fields ({host}, {user},
{src_ip}, {dst_ip}) or any vocabulary in ``VOCAB``.
"""

from __future__ import annotations

import random
import string

from faker import Faker

from nullpunkt.generator.common import Draft

TEMPLATES: dict[str, tuple[str, ...]] = {
    "Failed login": (
        "Failed logon for {user} from {src_ip}: bad password",
        "Authentication failure for {user} (event 4625) from {src_ip}",
    ),
    "Successful login after failures": (
        "{user} logged on from {src_ip} after {n} failed attempts",
        "Successful logon for {user} following {n} failures within {minutes} minutes",
    ),
    "Account lockout": ("Account {user} locked out after {n} failed attempts from {src_ip}",),
    "Impossible travel login": (
        "Login for {user} from {city_b} {minutes} minutes after login from {city_a}",
        "{user} authenticated from {src_ip} ({city_b}); previous session from {city_a}",
    ),
    "Login from new source host": (
        "First interactive logon by {user} to {host} from {src_ip}",
        "{user} logged on to {host} from a source not seen in 30 days ({src_ip})",
    ),
    "Privileged login from new host": (
        "Privileged account {user} logged on to {host} from {src_ip} for the first time",
        "Admin logon by {user} on {host}; source {src_ip} not in baseline",
    ),
    "Kerberos RC4 service ticket request": (
        "TGS request with RC4 encryption for {spn} by {user}",
        "Kerberos service ticket (etype 0x17) requested by {user} for {spn}",
    ),
    "Directory replication request": (
        "DRSGetNCChanges replication request to {host} from {src_ip}",
        "Directory replication (DS-Replication-Get-Changes) requested from {src_ip}",
    ),
    "LDAP enumeration query": (
        "{user} ran LDAP query for {ldap_target} returning {count} objects",
        "Broad LDAP search by {user} from {src_ip}: {ldap_target}",
    ),
    "Suspicious attachment delivered": (
        "Macro-enabled attachment {attachment} delivered to {user} from {src_ip}",
        "Email '{subject}' with attachment {attachment} delivered to {user}",
    ),
    "Spam campaign blocked": (
        "{count} messages from {src_ip} blocked by the mail gateway ('{subject}')",
        "Bulk mail campaign from {src_ip} quarantined: {count} recipients",
    ),
    "Office application spawned PowerShell": (
        "{office_app} spawned powershell.exe with {ps_args}",
        "PowerShell started by {office_app} for {user} ({ps_args})",
    ),
    "Bulk read of database files": (
        "Database files ({db_files}) read sequentially on {host}: {size} in {minutes} minutes",
        "{user} read {size} of {db_files} on {host}",
    ),
    "Mass file access on share": (
        "{user} accessed {count} files on {share} within {minutes} minutes",
        "High-volume file reads on {host} ({share}) by {user}: {count} files",
    ),
    "Large archive created": (
        "Archive {archive} ({size}) created on {host} by {user}",
        "{user} created compressed archive {archive} of {size}",
    ),
    "Account enumeration via net.exe": (
        "net.exe {net_args} executed on {host}",
        "Local and domain group enumeration on {host} ({net_args})",
    ),
    "Web server process spawned shell": (
        "{web_proc} spawned {shell} on {host}",
        "Shell {shell} launched by web server process {web_proc}",
    ),
    "LSASS memory access": (
        "Process {lsass_proc} opened lsass.exe with PROCESS_VM_READ on {host}",
        "Handle to lsass.exe requested by {lsass_proc}",
    ),
    "Remote service creation": (
        "Service {svc_name} created remotely on {host} from {src_ip}",
        "New service {svc_name} installed on {host} by {user}",
    ),
    "Backup service stopped": (
        "Service {backup_svc} stopped on {host} by {user}",
        "{backup_svc} service state changed to stopped on {host}",
    ),
    "Volume shadow copy deletion": (
        "{vss_cmd} executed on {host} by {user}",
        "Shadow copies removed on {host} ({vss_cmd})",
    ),
    "Unsigned executable launched from Downloads": (
        "Unsigned {exe} started from Downloads by {user}",
        "{user} ran {exe} from the Downloads folder (no valid signature)",
    ),
    "Browser credential store access": (
        "{cred_proc} read {browser} Login Data on {host}",
        "{browser} credential database accessed by {cred_proc}",
    ),
    "Potentially unwanted application": (
        "{pua} detected on {host}; file quarantined",
        "PUA {pua} found in {user}'s profile",
    ),
    "Known malware hash detected": (
        "File hash matches {pua} in Downloads; file quarantined",
        "Reputation match for {exe} ({pua}); file quarantined",
    ),
    "SMB admin share access": (
        "{admin_share} accessed on {host} from {src_ip}",
        "Administrative share {admin_share} on {host} mounted by {user}",
    ),
    "Internal network scan": (
        "{src_ip} probed {port_count} ports on {host} in {secs} seconds",
        "Sequential connection attempts from {src_ip} to {host}: {port_count} ports",
    ),
    "Exploit attempt signature": (
        "IDS signature '{signature}' matched traffic from {src_ip} to {host}",
        "{signature} payload from {src_ip} against {host}",
    ),
    "Inbound connection blocked": (
        "Inbound TCP/{port} from {src_ip} to {dst_ip} denied",
        "Firewall dropped connection from {src_ip} to {host}:{port}",
    ),
    "Port scan detected": (
        "{src_ip} probed {port_count} ports on {host} in {secs} seconds",
        "Horizontal scan from {src_ip} detected at the perimeter ({port_count} ports)",
    ),
    "Connection to newly registered domain": (
        "HTTPS request to {domain} (registered {days} days ago) from {src_ip}",
        "{user} connected to uncategorised domain {domain}",
    ),
    "Large outbound transfer": (
        "{size} uploaded to {dst_ip} ({domain}) from {src_ip}",
        "Outbound transfer of {size} by {user} to {domain}",
    ),
}


def _size(rng: random.Random, fake: Faker) -> str:
    return f"{rng.uniform(0.4, 24.0):.1f} GB"


def _domain(rng: random.Random, fake: Faker) -> str:
    suffix = rng.choice(("-cdn", "-app", "-files", "-sync", "-portal", "-docs"))
    return f"{fake.domain_word()}{suffix}.{rng.choice(('xyz', 'top', 'io', 'net', 'site'))}"


def _pick(*options: str):
    return lambda rng, fake: rng.choice(options)


def _int(lo: int, hi: int):
    return lambda rng, fake: str(rng.randint(lo, hi))


VOCAB = {
    "n": _int(2, 9),
    "count": _int(40, 4000),
    "minutes": _int(2, 45),
    "secs": _int(5, 60),
    "days": _int(1, 20),
    "port": _pick("22", "23", "445", "1433", "3389", "5900", "8080"),
    "port_count": _int(50, 2048),
    "size": _size,
    "domain": _domain,
    "city_a": lambda rng, fake: fake.city(),
    "city_b": lambda rng, fake: fake.city(),
    "spn": _pick(
        "MSSQLSvc/finsql.corp.local:1433",
        "HTTP/intranet.corp.local",
        "CIFS/fs02.corp.local",
        "MSSQLSvc/hrsql.corp.local:1433",
    ),
    "ldap_target": _pick(
        "(objectClass=user)", "Domain Admins membership", "(servicePrincipalName=*)"
    ),
    "attachment": _pick("Invoice_Q3.docm", "Payment_Details.xlsm", "Scan_0931.docm"),
    "subject": _pick("Invoice Q3", "Payment overdue", "Shared document", "Password expiry notice"),
    "office_app": _pick("WINWORD.EXE", "EXCEL.EXE"),
    "ps_args": _pick(
        "-EncodedCommand", "-ExecutionPolicy Bypass", "-NoProfile -WindowStyle Hidden"
    ),
    "db_files": _pick("*.mdf, *.ldf", "*.mdf, *.bak", "*.bak"),
    "share": _pick(r"\\corp\finance", r"\\corp\projects", r"\\corp\hr", r"\\corp\legal"),
    "archive": _pick("export.7z", "q3_backup.zip", "data.rar", "archive.zip"),
    "net_args": _pick('group "Domain Admins" /domain', "user /domain", "localgroup administrators"),
    "web_proc": _pick("w3wp.exe", "httpd", "java"),
    "shell": _pick("cmd.exe", "powershell.exe", "/bin/sh"),
    "lsass_proc": _pick("rundll32.exe", "taskmgr.exe", "procdump64.exe", "MsMpEng.exe"),
    "svc_name": _pick("PSEXESVC", "CcmExecHelper", "RemoteUpdater", "WinSvcHost"),
    "backup_svc": _pick("VSS", "wbengine", "SQLWriter", "Veeam Backup Service"),
    "vss_cmd": _pick(
        "vssadmin delete shadows /all /quiet",
        "wmic shadowcopy delete",
        "vssadmin delete shadows /for=D: /oldest",
    ),
    "exe": _pick("setup_x64.exe", "invoice_viewer.exe", "pdf_converter.exe", "Update.exe"),
    "cred_proc": _pick("KeePass.exe", "1Password.exe", "BitwardenHelper.exe", "svc_update.exe"),
    "browser": _pick("Chrome", "Edge", "Firefox"),
    "pua": _pick("Adware.Bundler", "PUA.DriverUpdater", "PUA.BrowserMiner", "Toolbar.Search"),
    "admin_share": _pick("ADMIN$", "C$", "ADMIN$ and C$"),
    "signature": _pick(
        "CVE-2021-44228 Log4j JNDI lookup",
        "CVE-2023-34362 MOVEit SQL injection",
        "CVE-2021-26855 Exchange SSRF",
        "CVE-2024-3400 PAN-OS command injection",
        "Generic SQL injection UNION SELECT",
    ),
}

_DRAFT_FIELDS = ("host", "user", "src_ip", "dst_ip")


def template_fields(template: str) -> list[str]:
    return [name for _, name, _, _ in string.Formatter().parse(template) if name]


def render_message(d: Draft, rng: random.Random, fake: Faker) -> str:
    template = rng.choice(TEMPLATES[d.rule.rule_name])
    facts = dict(d.facts)
    values: dict[str, str] = {}
    for name in template_fields(template):
        if name in facts:
            values[name] = facts[name]
        elif name in _DRAFT_FIELDS:
            value = getattr(d, name)
            if value is None:
                raise ValueError(f"{d.rule.rule_name!r} template needs {name} but it is empty")
            values[name] = value
        else:
            values[name] = VOCAB[name](rng, fake)
    return template.format(**values)
