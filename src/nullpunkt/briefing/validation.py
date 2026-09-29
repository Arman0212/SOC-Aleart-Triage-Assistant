"""The hallucination guard: a brief may only state what the incident contains.

A draft is rejected when:
- the JSON does not parse into ``BriefDraft``;
- an affected asset is not one of the incident's hosts (a trailing annotation such as
  "FINDB01 (database, criticality 5)" is stripped first), or the list is empty;
- a technique is not on the incident;
- the summary, timeline or next action mention an IP address, technique ID, host-like name,
  service/admin account or batch user that is not a trusted fact of this incident (identifiers
  that only occur inside untrusted alert messages are not trusted), or copy an identifier from
  the prompt's fictional example;
- they claim a stage the incident did not reach ("exfiltration", "data theft", "took over the
  account", "lateral movement", ...; see ``TACTIC_CLAIMS``);
- the summary has more than two lines or two sentences (or more than 400 characters), the
  timeline is outside 1-8 entries, or the next action has more than three sentences.

It cannot catch a wrong attribution between two valid facts (right host, wrong action).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from nullpunkt.briefing.context import BriefContext
from nullpunkt.briefing.prompt import EXAMPLE_TOKENS
from nullpunkt.core.schema import Confidence

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9$_.-]*[A-Za-z0-9$]|[A-Za-z0-9]")
HOST_RE = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*")
ACCOUNT_RE = re.compile(r"\b(?:adm|svc)-[a-z0-9]+(?:[.-][a-z0-9]+)*")
CVE_RE = re.compile(r"CVE-\d{4}-\d+")
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")


@dataclass(frozen=True)
class TacticClaim:
    """A phrase that claims the incident reached a stage, and the tactics that justify it."""

    label: str
    pattern: re.Pattern[str]
    justified_by: frozenset[str]


def _claim(label: str, pattern: str, *tactics: str) -> TacticClaim:
    return TacticClaim(label, re.compile(pattern, re.I), frozenset(tactics))


# Phrases (including common paraphrases) that claim a stage was reached.
TACTIC_CLAIMS: tuple[TacticClaim, ...] = (
    _claim("exfiltration", r"exfil|data leak|leaked (the )?data|leak(ed|ing)? (of )?data",
           "exfiltration"),
    _claim("data theft", r"data theft|\bst(o|ea)l(e|en|ing)?\b.{0,20}\bdata\b|"
           r"\bdata\b.{0,20}\b(stolen|theft)\b", "exfiltration", "collection"),
    _claim("account takeover", r"took over (the |an |their |its )?account|account takeover|"
           r"hijack\w* (the |an |their |its )?account", "credential-access", "stealth"),
    _claim("credential theft", r"credential (access|theft|dump)|st(o|ea)l(e|en|ing)? "
           r"(the |their |its )?credentials|dump(ed|ing)? (the |their )?credentials",
           "credential-access"),
    _claim("lateral movement", r"\blateral(ly)?\b|\bpivot(ed|ing|s)?\b", "lateral-movement"),
    _claim("privilege escalation", r"privilege escalation|escalat\w* (its |their )?privilege",
           "privilege-escalation"),
    _claim("persistence", r"\bpersistence\b", "persistence"),
    _claim("command and control", r"command[- ]and[- ]control|\bC2\b", "command-and-control"),
    _claim("reconnaissance", r"\breconnaissance\b", "reconnaissance"),
    _claim("impact", r"\bransomware\b|inhibit\w* (system )?recovery", "impact"),
    _claim("defense impairment", r"defen[cs]e impairment", "defense-impairment"),
)  # fmt: skip

MAX_SUMMARY_CHARS = 400
MAX_TIMELINE = 8
MAX_ACTION_SENTENCES = 3


class BriefDraft(BaseModel):
    """What the model must return (the JSON schema passed to Ollama's ``format``)."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1)
    affected_assets: list[str]
    techniques: list[str]
    timeline: list[str]
    next_action: str = Field(min_length=1)
    confidence: Confidence


DRAFT_SCHEMA = BriefDraft.model_json_schema()


@dataclass(frozen=True)
class Validated:
    draft: BriefDraft | None
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.draft is not None and not self.errors


def _sentences(text: str) -> list[str]:
    return [s for s in SENTENCE_RE.split(text.strip()) if s.strip()]


def _host_like(token: str) -> bool:
    return (
        len(token) >= 4
        and HOST_RE.fullmatch(token) is not None
        and any(c.isdigit() for c in token)
        and sum(c.isalpha() for c in token) >= 2
        and not token.startswith("CVE-")
    )


def _strip_annotation(asset: str) -> str:
    return re.split(r"\s*[(\[,:]", asset.strip(), maxsplit=1)[0].strip()


def check_identifiers(text: str, where: str, ctx: BriefContext) -> list[str]:
    t = ctx.trusted
    errors = []
    for token in sorted(EXAMPLE_TOKENS):
        if token in text:
            errors.append(f"{where} copies '{token}' from the prompt's example")
    for ip in sorted(set(IP_RE.findall(text))):
        if ip not in t.ips:
            errors.append(f"{where} mentions IP address {ip}, which is not in this incident")
    for tech in sorted(set(TECHNIQUE_RE.findall(text))):
        if tech not in t.techniques:
            errors.append(f"{where} mentions technique {tech}, which is not on this incident")
    scrubbed = CVE_RE.sub(" ", TECHNIQUE_RE.sub(" ", IP_RE.sub(" ", text)))
    allowed_hosts = t.hosts | t.other
    for token in sorted({tok.rstrip(".") for tok in TOKEN_RE.findall(scrubbed)}):
        if _host_like(token) and token not in allowed_hosts and token not in EXAMPLE_TOKENS:
            errors.append(f"{where} mentions host '{token}', which is not in this incident")
    words = set(re.findall(r"[a-z0-9][a-z0-9._-]*[a-z0-9]", text))
    for user in sorted(t.known_users & words):
        if user not in t.users:
            errors.append(f"{where} mentions user '{user}', who is not in this incident")
    for account in sorted({a.rstrip(".") for a in ACCOUNT_RE.findall(text)}):
        if account not in t.users:
            errors.append(f"{where} mentions account '{account}', which is not in this incident")
    for claim in TACTIC_CLAIMS:
        if claim.pattern.search(text) and not claim.justified_by & t.tactics:
            reached = " or ".join(sorted(x.replace("-", " ") for x in claim.justified_by))
            errors.append(f"{where} claims {claim.label}, but the incident never reached {reached}")
    return errors


def validate(raw: str, ctx: BriefContext) -> Validated:
    try:
        draft = BriefDraft.model_validate(json.loads(raw))
    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
        first = str(exc).splitlines()[0]
        return Validated(None, (f"the answer is not valid JSON for the brief schema ({first})",))

    errors: list[str] = []
    hosts = set(ctx.incident.hosts)
    assets = [_strip_annotation(a) for a in draft.affected_assets]
    if not assets:
        errors.append("affected_assets is empty")
    for asset in assets:
        if asset not in hosts:
            errors.append(f"affected_assets lists '{asset}', which is not a host of this incident")
    for tech in draft.techniques:
        if tech not in ctx.trusted.techniques:
            errors.append(f"techniques lists '{tech}', which is not on this incident")

    lines = [line for line in draft.summary.splitlines() if line.strip()]
    if len(lines) > 2:
        errors.append(f"summary has {len(lines)} lines; the limit is 2")
    if len(_sentences(draft.summary)) > 2:
        errors.append(f"summary has {len(_sentences(draft.summary))} sentences; the limit is 2")
    if len(draft.summary) > MAX_SUMMARY_CHARS:
        errors.append(
            f"summary is {len(draft.summary)} characters; the limit is {MAX_SUMMARY_CHARS}"
        )
    if not 1 <= len(draft.timeline) <= MAX_TIMELINE:
        errors.append(f"timeline has {len(draft.timeline)} entries; allowed 1 to {MAX_TIMELINE}")
    if len(_sentences(draft.next_action)) > MAX_ACTION_SENTENCES:
        errors.append(
            f"next_action has {len(_sentences(draft.next_action))} sentences; "
            f"the limit is {MAX_ACTION_SENTENCES}"
        )

    errors += check_identifiers(draft.summary, "summary", ctx)
    for n, entry in enumerate(draft.timeline, start=1):
        errors += check_identifiers(entry, f"timeline entry {n}", ctx)
    errors += check_identifiers(draft.next_action, "next_action", ctx)
    for asset in draft.affected_assets:
        errors += [e for e in check_identifiers(asset, "affected_assets", ctx) if "copies" in e]

    cleaned = draft.model_copy(update={"affected_assets": list(dict.fromkeys(assets))})
    return Validated(cleaned, tuple(dict.fromkeys(errors)))
