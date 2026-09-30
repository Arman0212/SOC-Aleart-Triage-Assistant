# Analyst app and decision storage

The analyst works in a Streamlit app that only reads from and writes to a SQLite database. The
heavy lifting happens beforehand: `nullpunkt-prepare-shift` runs the full pipeline, including Phi
briefs for the top 10, and stores the result.

```bash
nullpunkt-prepare-shift --batch data/generated/batch-001    # pipeline + briefs -> SQLite
streamlit run app/streamlit_app.py                          # the analyst app
```

**Database path.** `--db` beats `DB_PATH` (environment or `.env`), which beats `storage.db_path`
in `configs/pipeline.yaml` (default `data/generated/nullpunkt.db`, git-ignored).

**Re-preparing a batch** needs `--replace`. The batch's decisions, study sessions and audit log
are kept, and incident statuses are re-derived from the decisions.

## Storage

`nullpunkt.storage` has a small `Repository` protocol and its `SQLiteRepository` implementation.

**Migrations.** The schema is created by versioned SQL files (`storage/migrations/NNN_*.sql`),
applied in order and recorded in `schema_version`. Opening an older database upgrades it in place;
nobody has to reset it by hand.

| Table | Holds |
|---|---|
| `batches` | one prepared shift: counts, first and last alert, time zone, ATT&CK version, prompt and model, pipeline and briefing seconds, config |
| `alerts` | every alert of the shift (the app never reads batch files) |
| `incidents` | the full `Incident` JSON (techniques, score, brief) and the scoring detail, plus indexed rank, tier, status and risk for the queue |
| `links`, `hubs` | the correlation link reasons ("same user, 12 min apart") and the detected hubs |
| `briefs` | the brief, the context it was written from, and its `BriefingResult` metadata (path, attempts, latency, prompt version, model, cache hit, fallback reason, the model's own confidence, validation errors) |
| `study_sessions` | study runs: session ID, participant code, batch, started_at, ended_at, and (migration 002) arm, purpose, time box and end reason |
| `openings` | when triage of an incident started, per analyst and study session |
| `decisions` | every decision, including re-decisions, with `study_session` (NULL outside a session) |
| `flags` | (migration 002) baseline-arm flags: session, alert, optional note, flagged_at; append-only |
| `audit_log` | append-only: SQL triggers reject UPDATE and DELETE |

**Audit events:**

- `shift_prepared`, `shift_replaced`
- `incident_opened`, `incident_reopened`
- `decision_recorded`, `decision_changed`
- `session_started`, `session_ended`, `session_timed_out`
- `alert_flagged`
- `report_exported`

## Pages

**Queue**

- **Header:** alerts in shift, incidents, reduction ratio, decided so far, and live MTTT.
- **Filters:** tier and status.
- **Table**, sorted by rank:
  - the tier, colour-coded with its label: P1 red, P2 amber, P3 blue, P4 grey
  - risk as a bar relative to the shift's top incident, with the raw score next to it
  - the asset at risk with its criticality
  - the ATT&CK tactic chain as short tags
  - alert count and status
- **Opening an incident:** click a row, or use the "Open incident" picker.
- **Load time:** a warm load of the 65-incident queue takes about 0.03 s. A test holds it under
  1 s.

**Incident**

1. **The verdict:** the brief's two lines, with badges for LLM or template, validated, and
   confidence.
2. **The decision bar:** approve, edit & approve, dismiss as false positive, escalate.
3. **Score breakdown and explanation**, next to "why these alerts are grouped" (the stored link
   reasons).
4. **Evidence timeline** in company time: bursts are grouped, and routine alerts are collapsed to
   one line per rule.
5. **ATT&CK techniques** in kill-chain order.
6. **The full brief**, and the raw alerts in an expander.

**Handover**

- The shift stats, then only approved, edited and escalated incidents in rank order, with their
  final brief text: the analyst's edit where there is one, and the escalation note.
- An unedited brief is printed one field per line, each with a bold label:
  **Verdict:**, **Assets:**, **Techniques:**, **Timeline:** (a list) and **Next action:**. The
  same layout is used in the page, the Markdown and the HTML.
- An edited brief is the analyst's own text, printed with its line breaks kept.
- Downloads: Markdown, and HTML with print CSS. There's no PDF dependency; use the browser's
  Print → Save as PDF.

**Look.** `.streamlit/config.toml` sets a dark SOC theme (navy background, 16 px base font for
projectors). The only accent colours are the tier colours, and a tier is always shown with its
text label as well.

## Decisions

| Action | Required | Status |
|---|---|---|
| approve | nothing | approved |
| edit | the edited brief text (then approved) | approved |
| dismiss | a reason, at least 3 characters | dismissed |
| escalate | a note, at least 3 characters | escalated |

- **An incomplete decision** shows an inline error, and nothing is saved.
- **Re-decisions** are allowed through "Change decision". The latest decision (by `decided_at`,
  then ID) sets the status; every decision is kept and audited.
- **The analyst name** is typed into the sidebar. There's no login (see limitations).

### Capturing `opened_at` reliably

Streamlit re-runs the whole script on every click, and page state is lost on a browser refresh.
So the triage clock lives in the database:

1. The first time an undecided incident's page renders for an analyst (in the current study
   session, or outside one), an `openings` row is inserted with `opened_at = now(UTC)`. The check
   and the insert run in one transaction, so later reruns, refreshes and second tabs find the row
   and insert nothing.
2. The decision click sets `decided_at = now(UTC)`, stores the `Decision` with `triage_seconds`,
   and closes the opening, all in one transaction.
3. Viewing a decided incident never starts a timer. A re-decision starts a new opening only when
   the analyst presses "Change decision".
4. Viewing the queue never starts a timer. Without an analyst name the incident page is
   read-only.

Tests drive all of this with an injectable clock.

## Measures

- **MTTT (mean time to triage):** the mean `triage_seconds` of each incident's first decision.
  That's the time from opening the incident to deciding it. Re-decisions are corrections; they're
  counted separately and never averaged in. The queue header shows MTTT over all first decisions
  in the shift.
- **Brief generation time is separate.** Briefs are generated in the background by
  prepare-shift, before the analyst opens the queue. Their cost (about 3–6 minutes per 10 briefs
  on an M3 laptop) is reported next to MTTT, never folded into it or dropped; see
  [briefing_evaluation.md](briefing_evaluation.md).
- **Study sessions.** Decisions made during a session carry its ID; decisions made outside any
  session have `study_session` NULL and are left out of every study metric (see
  [Study mode](#study-mode)). `nullpunkt.app.metrics.session_metrics(repo, session_id)` returns,
  for one session:
  - the total session duration (up to now if it's still running)
  - the time from session start to the first decision on each incident, which includes
    scanning the queue (needed for comparison with a spreadsheet baseline)
  - the number of decisions, and of re-decisions
  - the first-decision MTTT

## Study mode

The before/after study (Phase 7) runs in the same app. The protocol, the facilitator's script and
the detection definitions are in [study_protocol.md](study_protocol.md).

- **Starting a session.** Use "Start a study session" in the sidebar. It needs:
  - a participant code: upper case, such as `P1`; real names are refused
  - the arm: `baseline` or `tool`
  - the batch
  - the purpose: `study`, `practice` or `dry-run`; only `study` sessions are analysed
  - the time box: its default is `study.time_box_minutes` in `configs/pipeline.yaml` (15)
- **While a session runs**, the sidebar shows only the participant, arm and batch, a countdown
  that updates every second, and "End session". Navigation shows only the arm's pages:
  - baseline: the Alert list
  - tool: Queue, Incident and Handover
- **The time box.** It's enforced in the repository, not the browser. The first read or write
  after the deadline ends the session with `ended_at` set to exactly the deadline,
  `end_reason = timed_out`, and one `session_timed_out` audit event. No flag or decision is
  accepted after that. A session ended with the button gets `end_reason = ended`.
- **The Alert list (baseline arm).**
  - A flat table of the raw alerts, sorted by severity, then time. It shows time, severity,
    source, rule, host, user, IPs, message and alert ID. It has no incidents, grouping, scores,
    tiers, ATT&CK or briefs; a test checks the page for all of these.
  - Search across the text fields; filter by severity, source, host and user.
  - Select a row to flag it, with an optional note. Flags go to the `flags` table with
    `flagged_at = now(UTC)`. They're allowed only in a running baseline session, and they're
    append-only.
  - Baseline sessions can't make decisions.
- **Per-session scope (tool arm).**
  - Each study session sees the queue as if nothing had been decided. Statuses, "Decided", MTTT
    and the handover are computed only from that session's decisions, so one participant's work
    never shows up for the next one.
  - Study decisions never change `incidents.status`; that column reflects only decisions made
    outside sessions.
  - Openings are scoped the same way.
- **Results.** `python -m nullpunkt.evaluation.mttt_study` scores the sessions against the labels
  and writes `docs/mttt_study.md`. This is the only study code that reads labels, and it lives in
  `nullpunkt.evaluation`.

## Known limitations

- **Passcode only, no per-user authentication.** The analyst name is self-declared in the
  sidebar, and anyone with the app can decide as anyone. A hosted demo can set `DEMO_PASSCODE`
  ([deployment.md](deployment.md#5-optional-passcode)) to keep casual visitors out; without it the
  app is unchanged. That's acceptable for a single-laptop demo and study, not for production.
- **SQLite with one writer.** It's fine for one or a few analysts on one machine; a shared
  deployment would need a server database behind the same `Repository` protocol.
- **The elapsed-time label is static.** The timer shown on the incident page updates only on a
  rerun. The stored `opened_at` and `decided_at` are what count.
- **Headless UI tests pin the page.** Streamlit's `AppTest` doesn't keep a page reached through
  `st.switch_page` for later reruns (a browser keeps it in the URL), so the tests pin the incident
  page explicitly after opening it.
