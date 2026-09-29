"""Response playbook, one first-response action per ATT&CK tactic (v19.2 short names).

The model chooses and adapts from these entries; it does not invent actions. The template
fallback uses the same entries.
"""

from __future__ import annotations

PLAYBOOK: dict[str, str] = {
    "reconnaissance": (
        "Confirm the probes were blocked and block the scanning source if it persists."
    ),
    "resource-development": (
        "Block the attacker infrastructure seen (domains, IPs) at the perimeter."
    ),
    "initial-access": (
        "Identify and block the entry point: quarantine the email, block the sender or source "
        "IP, or patch or isolate the exposed service."
    ),
    "execution": "Collect the process tree and kill or quarantine the malicious process.",
    "persistence": (
        "Remove the persistence (web shell, service or scheduled task) and hunt for others on "
        "the same host."
    ),
    "privilege-escalation": (
        "Revoke the elevated rights and sessions, and review recent privileged logons."
    ),
    "stealth": "Treat the account as compromised: reset its password and revoke its sessions.",
    "defense-impairment": (
        "Restore the disabled security control and check what ran while it was off."
    ),
    "credential-access": (
        "Reset the exposed credentials, including service accounts, and revoke Kerberos tickets "
        "and sessions."
    ),
    "discovery": "Find who ran the enumeration and check what they accessed next.",
    "lateral-movement": (
        "Isolate the source host of the lateral movement and block its admin access to the target."
    ),
    "collection": "Identify what data was accessed and preserve the access logs as evidence.",
    "command-and-control": "Block the destination at the proxy and isolate the infected host.",
    "exfiltration": (
        "Block the exfiltration destination, preserve evidence and estimate what data left."
    ),
    "impact": "Isolate the affected server now and verify backups before any recovery.",
}


def playbook_for(tactics: tuple[str, ...] | list[str]) -> list[dict[str, str]]:
    """Playbook entries for the given tactics (kill-chain order in), most urgent first: the
    furthest tactic the incident reached is the most urgent to contain."""
    return [{"tactic": t, "action": PLAYBOOK[t]} for t in reversed(list(tactics)) if t in PLAYBOOK]
