"""Generate shift briefs: context -> model -> validation -> (retry) -> brief or template.

Confidence comes from the evidence only (``evidence_confidence``); the model's self-reported
confidence is recorded for transparency but never used.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from nullpunkt.briefing.context import BriefContext
from nullpunkt.briefing.llm import LLMClient, LLMError
from nullpunkt.briefing.prompt import load_prompt, user_message
from nullpunkt.briefing.template import template_brief
from nullpunkt.briefing.validation import DRAFT_SCHEMA, BriefDraft, validate
from nullpunkt.core.config import BriefingConfig
from nullpunkt.core.schema import Brief, BriefSource, Confidence


def evidence_confidence(ctx: BriefContext) -> Confidence:
    """high: non-routine evidence covering >= 3 tactics and >= 2 distinct rules;
    medium: non-routine evidence covering >= 2 tactics; low: anything else."""
    tactics = len(ctx.evidence_tactics)
    if not ctx.routine_only and tactics >= 3 and ctx.evidence_rules >= 2:
        return Confidence.HIGH
    if not ctx.routine_only and tactics >= 2:
        return Confidence.MEDIUM
    return Confidence.LOW


@dataclass
class BriefOutcome:
    """How one brief was produced: the brief, its source, attempts, latency and any fallback
    reason."""

    incident_id: str
    brief: Brief
    generated_by: BriefSource
    attempts: int  # model calls made (0 for cache hits and skipped calls)
    latency_seconds: float
    prompt_version: str
    model: str
    cache_hit: bool = False
    fallback_reason: str | None = None
    model_confidence: str | None = None  # recorded, never used
    validation_errors: list[list[str]] = field(default_factory=list)  # per rejected attempt
    raw_replies: list[str] = field(default_factory=list)

    @property
    def fallback_used(self) -> bool:
        return self.generated_by is BriefSource.TEMPLATE

    @property
    def retries(self) -> int:
        return max(self.attempts - 1, 0)

    @property
    def path(self) -> str:
        """first-pass, after-retry, cached, cached-fallback or fallback."""
        if self.cache_hit:
            return "cached-fallback" if self.fallback_used else "cached"
        if self.fallback_used:
            return "fallback"
        return "first-pass" if self.attempts == 1 else "after-retry"


@dataclass
class BriefingResult:
    """All briefs of a run, in rank order, with the prompt version, model and total time."""

    outcomes: dict[str, BriefOutcome]  # incident_id -> outcome, in rank order
    prompt_version: str
    model: str
    seconds: float

    def paths(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for o in self.outcomes.values():
            counts[o.path] = counts.get(o.path, 0) + 1
        return counts


class BriefCache:
    """Validated LLM briefs keyed by a hash of (context, prompt, model, options)."""

    def __init__(self, directory: str | Path | None) -> None:
        self.directory = Path(directory) if directory else None

    @staticmethod
    def key(
        ctx: BriefContext, prompt_version: str, prompt_sha: str, model: str, options: dict
    ) -> str:
        payload = json.dumps(
            {
                "context": ctx.data,
                "prompt_version": prompt_version,
                "prompt_sha256": prompt_sha,
                "model": model,
                "options": options,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(self, key: str) -> dict | None:
        if self.directory is None:
            return None
        path = self.directory / f"{key}.json"
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def put(self, key: str, entry: dict) -> None:
        if self.directory is None:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / f"{key}.json").write_text(
            json.dumps(entry, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
        )


def _to_brief(draft: BriefDraft, confidence: Confidence, source: BriefSource) -> Brief:
    return Brief(
        summary=draft.summary.strip(),
        affected_assets=draft.affected_assets,
        techniques=list(dict.fromkeys(draft.techniques)),
        timeline=draft.timeline,
        next_action=draft.next_action.strip(),
        confidence=confidence,
        generated_by=source,
        validated=True,
    )


def generate_brief(
    ctx: BriefContext,
    client: LLMClient | None,
    config: BriefingConfig | None = None,
    cache: BriefCache | None = None,
    skip_reason: str | None = None,
) -> BriefOutcome:
    """Brief one incident. ``client=None`` or ``skip_reason`` goes straight to the template."""
    cfg = config or BriefingConfig()
    prompt = load_prompt(cfg.prompt_version)
    confidence = evidence_confidence(ctx)
    model = client.model if client else "none"
    started = time.perf_counter()
    options = {"temperature": cfg.temperature, "seed": cfg.seed, "num_ctx": cfg.num_ctx}
    key = BriefCache.key(ctx, prompt.version, prompt.sha256, model, options)

    def done(**kw) -> BriefOutcome:
        return BriefOutcome(
            incident_id=ctx.incident_id,
            latency_seconds=time.perf_counter() - started,
            prompt_version=prompt.version,
            model=model,
            **kw,
        )

    def fallback(reason: str, **kw) -> BriefOutcome:
        draft = template_brief(ctx, confidence)
        return done(
            brief=_to_brief(draft, confidence, BriefSource.TEMPLATE),
            generated_by=BriefSource.TEMPLATE,
            fallback_reason=reason,
            **kw,
        )

    if client is None or skip_reason:
        return fallback(skip_reason or "no model client", attempts=0)

    if cache is not None and (hit := cache.get(key)) and "draft" in hit:
        draft = BriefDraft.model_validate(hit["draft"])
        return done(
            brief=_to_brief(draft, confidence, BriefSource.LLM),
            generated_by=BriefSource.LLM,
            attempts=0,
            cache_hit=True,
            model_confidence=hit.get("model_confidence"),
        )

    if cache is not None and (hit := cache.get(key)) and hit.get("source") == "template":
        # A deterministic model (temperature 0, fixed seed) failed validation on this exact
        # context before; it would fail again, so reuse the fallback instead of re-asking.
        return fallback(
            f"{hit['reason']} (cached)",
            attempts=0,
            cache_hit=True,
            validation_errors=hit.get("validation_errors", []),
        )

    errors: list[list[str]] = []
    replies: list[str] = []
    feedback: list[str] | None = None
    for attempt in range(1, cfg.max_retries + 2):
        try:
            raw = client.generate(prompt.text, user_message(ctx.data, feedback), DRAFT_SCHEMA)
        except LLMError as exc:
            return fallback(
                f"model {exc.kind}: {exc}",
                attempts=attempt,
                validation_errors=errors,
                raw_replies=replies,
            )
        replies.append(raw)
        checked = validate(raw, ctx)
        if checked.ok:
            assert checked.draft is not None
            if cache is not None:
                cache.put(
                    key,
                    {
                        "draft": checked.draft.model_dump(mode="json"),
                        "model_confidence": checked.draft.confidence.value,
                        "prompt_version": prompt.version,
                        "model": model,
                    },
                )
            return done(
                brief=_to_brief(checked.draft, confidence, BriefSource.LLM),
                generated_by=BriefSource.LLM,
                attempts=attempt,
                model_confidence=checked.draft.confidence.value,
                validation_errors=errors,
                raw_replies=replies,
            )
        errors.append(list(checked.errors))
        feedback = list(checked.errors)
    reason = f"failed validation {len(errors)} times"
    if cache is not None:
        # Cached so a re-run is instant; transient failures (timeout, unreachable) are not.
        cache.put(
            key,
            {"source": "template", "reason": reason, "validation_errors": errors, "model": model},
        )
    return fallback(reason, attempts=len(errors), validation_errors=errors, raw_replies=replies)


def brief_all(
    contexts: Sequence[BriefContext],
    client: LLMClient | None,
    config: BriefingConfig | None = None,
    cache: BriefCache | None = None,
) -> BriefingResult:
    """Brief several incidents in order. If the model is unreachable once, the rest go straight
    to the template instead of waiting for the same failure again."""
    cfg = config or BriefingConfig()
    started = time.perf_counter()
    outcomes: dict[str, BriefOutcome] = {}
    skip: str | None = None
    for ctx in contexts:
        outcome = generate_brief(ctx, client, cfg, cache, skip_reason=skip)
        outcomes[ctx.incident_id] = outcome
        if outcome.fallback_reason and "unreachable" in outcome.fallback_reason:
            skip = "model unreachable earlier in this run"
    return BriefingResult(
        outcomes=outcomes,
        prompt_version=cfg.prompt_version,
        model=client.model if client else "none",
        seconds=time.perf_counter() - started,
    )
