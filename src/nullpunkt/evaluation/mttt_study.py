"""Before/after study analysis (labels used only here): python -m nullpunkt.evaluation.mttt_study

    python -m nullpunkt.evaluation.mttt_study --db data/generated/study.db \\
        --batch study-A=data/generated/study-A --batch study-B=data/generated/study-B \\
        --out docs/mttt_study.md

Method (docs/study_protocol.md):
- Only sessions with purpose "study" count; the first completed one per participant and arm is
  used (later ones are listed as excluded).
- Detection. Tool arm: the first approve, edit or escalate on an incident containing any alert of
  the attack. Baseline arm: the first flag on any alert of the attack. Time to detect is measured
  from session start, so queue or list scanning is included in both arms.
- Undetected attacks are censored at the time box tau. With only this administrative censoring,
  the restricted mean time to detect (RMST) is the mean of min(t, tau), which equals the area
  under the Kaplan-Meier curve up to tau. Per participant and arm: mean over the batch's attacks;
  per arm: mean over participants. Improvement = 1 - RMST(tool) / RMST(baseline); target >= 50 %.
- Paired comparison: exact two-sided Wilcoxon signed-rank p on per-participant RMST differences,
  reported as descriptive only (with n = 5 the smallest possible p is 0.0625).
"""

from __future__ import annotations

import argparse
import itertools
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean

from nullpunkt.app.metrics import first_decisions
from nullpunkt.core.schema import DecisionAction, GroundTruth
from nullpunkt.evaluation.ground_truth import load_ground_truth
from nullpunkt.storage.repository import SessionRecord, SQLiteRepository

TARGET_IMPROVEMENT = 0.50
ARMS = ("baseline", "tool")

# The pre-registered counterbalancing schedule (docs/study_protocol.md): (arm, batch) in order.
SCHEDULE: dict[str, list[tuple[str, str]]] = {
    "P1": [("baseline", "study-A"), ("tool", "study-B")],
    "P2": [("tool", "study-A"), ("baseline", "study-B")],
    "P3": [("baseline", "study-B"), ("tool", "study-A")],
    "P4": [("tool", "study-B"), ("baseline", "study-A")],
    "P5": [("baseline", "study-A"), ("tool", "study-B")],
}


@dataclass
class ArmResult:
    participant: str
    arm: str
    batch_id: str
    session_id: str
    tau_seconds: float
    detections: dict[str, float | None]  # scenario -> seconds from session start (None: missed)
    false_positives: int
    actions: int  # flags (baseline) or decisions (tool)
    mttt_seconds: float | None = None  # tool arm: first-decision MTTT
    end_reason: str | None = None

    @property
    def attacks(self) -> int:
        return len(self.detections)

    @property
    def detected(self) -> int:
        return sum(t is not None for t in self.detections.values())

    @property
    def rmst_seconds(self) -> float:
        return mean(min(t, self.tau_seconds) if t is not None else self.tau_seconds
                    for t in self.detections.values())  # fmt: skip


@dataclass
class StudyResult:
    results: list[ArmResult]
    excluded: list[tuple[SessionRecord, str]] = field(default_factory=list)

    def arm(self, arm: str) -> list[ArmResult]:
        return [r for r in self.results if r.arm == arm]

    def rmst(self, arm: str) -> float | None:
        rs = self.arm(arm)
        return mean(r.rmst_seconds for r in rs) if rs else None

    def detection_rate(self, arm: str) -> float | None:
        rs = self.arm(arm)
        total = sum(r.attacks for r in rs)
        return sum(r.detected for r in rs) / total if total else None

    def improvement(self) -> float | None:
        base, tool = self.rmst("baseline"), self.rmst("tool")
        if not base or tool is None:
            return None
        return 1 - tool / base

    def paired(self) -> list[tuple[str, float, float]]:
        """(participant, baseline RMST, tool RMST) for participants with both arms."""
        by = {(r.participant, r.arm): r for r in self.results}
        people = sorted({r.participant for r in self.results})
        return [
            (p, by[(p, "baseline")].rmst_seconds, by[(p, "tool")].rmst_seconds)
            for p in people
            if (p, "baseline") in by and (p, "tool") in by
        ]


# --- statistics ----------------------------------------------------------------------------------


def km_median(times: list[float | None], tau: float) -> float | None:
    """Kaplan-Meier median time to detect, with misses censored at tau. None if the survival
    curve never drops to 0.5 or below within tau ("not reached")."""
    events = sorted(t for t in times if t is not None and t <= tau)
    at_risk, survival = len(times), 1.0
    for t, group in itertools.groupby(events):
        d = len(list(group))
        survival *= 1 - d / at_risk
        at_risk -= d
        if survival <= 0.5:
            return t
    return None


def wilcoxon_exact_p(differences: list[float]) -> float | None:
    """Exact two-sided Wilcoxon signed-rank p-value (zeros dropped, ties get average ranks)."""
    d = [x for x in differences if x != 0]
    n = len(d)
    if n == 0:
        return None
    order = sorted(range(n), key=lambda i: abs(d[i]))
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(d[order[j + 1]]) == abs(d[order[i]]):
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    observed = sum(r for r, x in zip(ranks, d, strict=True) if x > 0)
    total = sum(ranks)
    centre = total / 2
    extreme = 0
    for signs in itertools.product((0, 1), repeat=n):
        w = sum(r for r, s in zip(ranks, signs, strict=True) if s)
        if abs(w - centre) >= abs(observed - centre) - 1e-9:
            extreme += 1
    return extreme / 2**n


# --- scoring sessions ----------------------------------------------------------------------------


def _scenario_of(labels: dict[str, GroundTruth]) -> dict[str, str]:
    return {a: g.scenario_id for a, g in labels.items() if g.scenario_id}


def score_session(
    repo: SQLiteRepository, session: SessionRecord, labels: dict[str, GroundTruth]
) -> ArmResult:
    scenario_of = _scenario_of(labels)
    attacks = sorted(set(scenario_of.values()))
    detections: dict[str, float | None] = dict.fromkeys(attacks)
    start = session.started_at
    deadline = session.deadline
    tau = float(session.time_box_seconds or 0)

    def record(scenario: str, seconds: float) -> None:
        if detections[scenario] is None or seconds < detections[scenario]:
            detections[scenario] = seconds

    if session.arm == "baseline":
        flags = [f for f in repo.flags(session.session_id)
                 if deadline is None or f.flagged_at <= deadline]  # fmt: skip
        noise = set()
        for f in flags:
            scenario = scenario_of.get(f.alert_id)
            if scenario:
                record(scenario, (f.flagged_at - start).total_seconds())
            else:
                noise.add(f.alert_id)
        return ArmResult(
            session.analyst, "baseline", session.batch_id, session.session_id, tau, detections,
            false_positives=len(noise), actions=len(flags), end_reason=session.end_reason,
        )  # fmt: skip

    decisions = [d for d in repo.decisions(session.batch_id, session_id=session.session_id)
                 if deadline is None or d.decided_at <= deadline]  # fmt: skip
    alerts_of: dict[str, list[str]] = {}
    noise_incidents = set()
    for d in decisions:
        if d.action is DecisionAction.DISMISS:
            continue
        if d.incident_id not in alerts_of:
            alerts_of[d.incident_id] = repo.incident(
                session.batch_id, d.incident_id
            ).incident.alert_ids
        scenarios = {scenario_of[a] for a in alerts_of[d.incident_id] if a in scenario_of}
        for scenario in scenarios:
            record(scenario, (d.decided_at - start).total_seconds())
        if not scenarios:
            noise_incidents.add(d.incident_id)
    firsts = first_decisions(decisions)
    return ArmResult(
        session.analyst, "tool", session.batch_id, session.session_id, tau, detections,
        false_positives=len(noise_incidents), actions=len(decisions),
        mttt_seconds=mean(d.triage_seconds for d in firsts.values()) if firsts else None,
        end_reason=session.end_reason,
    )  # fmt: skip


def analyse(
    repo: SQLiteRepository, labels_by_batch: dict[str, dict[str, GroundTruth]]
) -> StudyResult:
    result = StudyResult(results=[])
    seen: set[tuple[str, str]] = set()
    for session in repo.sessions():
        if session.arm is None:
            continue
        if session.purpose != "study":
            result.excluded.append((session, f"purpose {session.purpose}"))
            continue
        if session.running:
            result.excluded.append((session, "still running"))
            continue
        if session.batch_id not in labels_by_batch:
            result.excluded.append((session, f"no labels given for {session.batch_id}"))
            continue
        key = (session.analyst, session.arm)
        if key in seen:
            result.excluded.append((session, "repeat of an earlier session for this arm"))
            continue
        seen.add(key)
        result.results.append(score_session(repo, session, labels_by_batch[session.batch_id]))
    return result


# --- report --------------------------------------------------------------------------------------


def _mmss(seconds: float | None) -> str:
    if seconds is None:
        return "–"
    s = int(round(seconds))
    return f"{s // 60}:{s % 60:02d}"


def _pct(x: float | None) -> str:
    return "–" if x is None else f"{x:.0%}"


def schedule_check(study: StudyResult, repo: SQLiteRepository) -> list[str]:
    """Differences between what was run and the pre-registered schedule."""
    notes = []
    order: dict[str, list[tuple[str, str]]] = {}
    for s in repo.sessions():
        if s.arm and s.purpose == "study" and not s.running:
            order.setdefault(s.analyst, [])
            if (s.arm, s.batch_id) not in order[s.analyst]:
                order[s.analyst].append((s.arm, s.batch_id))
    for p, planned in SCHEDULE.items():
        actual = order.get(p, [])
        if actual[: len(planned)] != planned:
            notes.append(f"{p}: planned {planned}, ran {actual or 'nothing'}")
    for p in sorted(set(order) - set(SCHEDULE)):
        notes.append(f"{p} is not in the schedule")
    return notes


def to_markdown(study: StudyResult, repo: SQLiteRepository) -> str:
    base, tool = study.rmst("baseline"), study.rmst("tool")
    improvement = study.improvement()
    paired = study.paired()
    p = wilcoxon_exact_p([b - t for _, b, t in paired]) if paired else None
    taus = sorted({r.tau_seconds for r in study.results})
    tau_text = ", ".join(_mmss(t) for t in taus) or "–"
    if improvement is None:
        verdict = "Not enough data to compare the arms."
    elif improvement >= TARGET_IMPROVEMENT:
        verdict = f"**Target met**: time to detect fell by {improvement:.0%} (target ≥ 50 %)."
    else:
        verdict = (
            f"**Target not met**: time to detect fell by {improvement:.0%}, short of the ≥ 50 % "
            "target."
        )

    lines = [
        "# Before/after study: time to detect",
        "",
        "Generated by `python -m nullpunkt.evaluation.mttt_study` from the study database and "
        "the batches' labels. Protocol: [study_protocol.md](study_protocol.md).",
        "",
        "## Headline",
        "",
        verdict,
        "",
        "| | Baseline (raw alert list) | Tool (Nullpunkt) |",
        "|---|---|---|",
        f"| Participants | {len(study.arm('baseline'))} | {len(study.arm('tool'))} |",
        f"| Restricted mean time to detect (τ = {tau_text}) | {_mmss(base)} | {_mmss(tool)} |",
        f"| Detection rate within the time box | {_pct(study.detection_rate('baseline'))} "
        f"| {_pct(study.detection_rate('tool'))} |",
        "| Kaplan–Meier median time to detect | "
        + " | ".join(_km_text(study, arm) for arm in ARMS)
        + " |",
        "| False positives per participant (mean) | "
        + " | ".join(_mean_text([r.false_positives for r in study.arm(a)]) for a in ARMS)
        + " |",
        "| First-decision MTTT (tool arm only) | – | "
        + _mmss(_maybe_mean([r.mttt_seconds for r in study.arm("tool")]))
        + " |",
        "",
        f"Improvement in restricted mean time to detect: **{_pct(improvement)}**. "
        f"Exact two-sided Wilcoxon signed-rank p on the {len(paired)} paired participants: "
        f"{'–' if p is None else f'{p:.3f}'} (descriptive only; with n = 5 the smallest "
        "possible p is 0.0625, so no significance claim is possible).",
        "",
        "## Per participant",
        "",
        "| Participant | Arm | Batch | Detected | Time to each detection (m:ss) | RMST | "
        "False positives | Actions | First-decision MTTT | Session end |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in sorted(study.results, key=lambda r: (r.participant, r.session_id)):
        times = ", ".join(f"{s[-2:]} {_mmss(t) if t is not None else 'missed'}"
                          for s, t in r.detections.items())  # fmt: skip
        lines.append(
            f"| {r.participant} | {r.arm} | {r.batch_id} | {r.detected}/{r.attacks} | {times} | "
            f"{_mmss(r.rmst_seconds)} | {r.false_positives} | {r.actions} | "
            f"{_mmss(r.mttt_seconds) if r.arm == 'tool' else '–'} | {r.end_reason or '–'} |"
        )
    lines += [
        "",
        "## Paired comparison",
        "",
        "| Participant | Baseline RMST | Tool RMST | Difference |",
        "|---|---|---|---|",
    ]
    for person, b, t in paired:
        lines.append(f"| {person} | {_mmss(b)} | {_mmss(t)} | {_mmss(b - t)} |")
    lines += ["", "## Detection per attack", "", "| Attack | Baseline | Tool |", "|---|---|---|"]
    attacks = sorted({s for r in study.results for s in r.detections})
    for s in attacks:
        cells = []
        for arm in ARMS:
            got = [r.detections[s] for r in study.arm(arm) if s in r.detections]
            cells.append(f"{sum(t is not None for t in got)}/{len(got)}" if got else "–")
        lines.append(f"| {s} | {cells[0]} | {cells[1]} |")

    lines += ["", "## Method", "", *METHOD, ""]
    deviations = schedule_check(study, repo)
    lines += ["## Schedule and exclusions", ""]
    lines += [f"- Deviation from the schedule: {d}" for d in deviations] or [
        "- All five participants followed the pre-registered schedule."
    ]
    lines += [f"- Excluded {s.session_id} ({s.analyst}, {s.arm}, {s.batch_id}): {why}"
              for s, why in study.excluded] or ["- No sessions were excluded."]  # fmt: skip
    lines += ["", "## Limitations", "", *LIMITATIONS]
    return "\n".join(lines).rstrip() + "\n"


def _maybe_mean(values: list[float | None]) -> float | None:
    got = [v for v in values if v is not None]
    return mean(got) if got else None


def _mean_text(values: list[int]) -> str:
    return f"{mean(values):.1f}" if values else "–"


def _km_text(study: StudyResult, arm: str) -> str:
    rs = study.arm(arm)
    if not rs:
        return "–"
    tau = min(r.tau_seconds for r in rs)
    median = km_median([t for r in rs for t in r.detections.values()], tau)
    return _mmss(median) if median is not None else f"not reached within {_mmss(tau)}"


METHOD = [
    "- **Design:** crossover. Each participant did one 15-minute arm on each study batch, in the "
    "pre-registered order. study-A (seed 42) holds SCN-01, SCN-03, SCN-05 and SCN-07; study-B "
    "(seed 2026) holds SCN-02, SCN-04 and SCN-06, so nobody saw an attack type twice.",
    "- **Detection:** tool arm, the first approve, edit or escalate on an incident containing "
    "any alert of the attack; baseline arm, the first flag on any alert of the attack (lenient "
    "towards the baseline). Time is measured from session start, so scanning the list or queue "
    "counts in both arms.",
    "- **Censoring:** undetected attacks are censored at the time box τ. The restricted mean "
    "time to detect (RMST) is the mean of min(t, τ), equal to the area under the Kaplan–Meier "
    "curve up to τ. Per participant and arm it is averaged over the batch's attacks, then "
    "averaged over participants per arm.",
    "- **False positives:** tool arm, incidents approved, edited or escalated that contain no "
    "attack alert; baseline arm, distinct noise alerts flagged.",
    "- **First-decision MTTT** (tool arm only): mean time from opening an incident to its first "
    "decision. The baseline has no incidents, so it has no comparable MTTT; the headline uses "
    "time to detect instead. Brief generation (about 3–6 minutes per batch) ran before the "
    "sessions and is not part of these times.",
]

LIMITATIONS = [
    "- **Small n.** Five participants; no significance claim is possible (see the p-value note).",
    "- **Synthetic data.** Attacks and noise come from our own generator, and the system was "
    "tuned on data from the same generator (other seeds), so real-world performance may differ.",
    "- **Unequal batches.** study-A has four attacks and study-B three; counterbalancing puts "
    "each batch in both arms, but with five participants the split is uneven (P5 repeats P1's "
    "order and batches).",
    "- **Learning effects.** The second arm benefits from practice with the task, whichever arm "
    "it is; counterbalancing spreads this over both arms but cannot remove it with n = 5.",
    "- **Priming.** Participants saw the Round 1 deck, which describes the product's goal and may "
    "prime them to look for low-severity activity on critical assets. This affects both arms "
    "equally.",
    "- **Facilitator.** The facilitator built the system and knows the answers; the protocol "
    "scripts everything they say and keeps them out of view during timed arms.",
    "- **Lenient baseline detection.** One flagged alert counts as detecting a whole attack; "
    "this favours the baseline, so the measured improvement is conservative.",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument(
        "--batch", action="append", required=True, metavar="ID=DIR",
        help="batch id and its generated directory (for labels.csv); repeat per batch",
    )  # fmt: skip
    parser.add_argument("--out", type=Path, default=Path("docs/mttt_study.md"))
    args = parser.parse_args(argv)

    labels = {}
    for item in args.batch:
        batch_id, _, directory = item.partition("=")
        labels[batch_id] = load_ground_truth(Path(directory) / "labels.csv")
    repo = SQLiteRepository(args.db)
    try:
        study = analyse(repo, labels)
        text = to_markdown(study, repo)
    finally:
        repo.close()
    args.out.write_text(text, encoding="utf-8")
    counts = Counter(r.arm for r in study.results)
    print(
        f"wrote {args.out}: {counts.get('baseline', 0)} baseline and {counts.get('tool', 0)} "
        f"tool sessions; improvement {_pct(study.improvement())}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
