# Before/after MTTT study: protocol

This protocol was fixed before any participant took part. It covers the design, what counts as a
detection, the schedule, the facilitator's script and checklists, and how the results are
produced. The results go in `docs/mttt_study.md`, which is written only by the results command
after the real sessions (see [Results](#results)).

## Question and headline measure

Does nullpunkt (correlated, scored, briefed incidents) let an analyst find the attacks in a
3,000-alert shift faster than a flat alert list?

- **Headline:** restricted mean time to detect (RMST) at τ = 15 minutes, per arm.
  Improvement = 1 − RMST(tool) / RMST(baseline). The target is ≥ 50 %, and the results document
  says plainly whether it was met.
- **Also reported:** detection rate, false positives, time to each detection, the Kaplan–Meier
  median where it exists, and first-decision MTTT for the tool arm.
- **Statistics:** the exact two-sided Wilcoxon signed-rank p on per-participant RMST differences
  is reported as **descriptive only**. With n = 5 the smallest possible p is 0.0625, so no
  significance claim is possible.

## Design

- **Crossover:** each participant does one timed arm with each tool, on a different batch.
- **Arms:**
  - **Baseline:** the "Alert list" page. It's a flat raw-alert table sorted by severity, then
    time, with search and filters. It has no incidents, grouping, scores, tiers, ATT&CK or
    briefs. Participants flag the alerts they think are suspicious, with an optional note.
  - **Tool:** the Queue, Incident and Handover pages, with briefs prepared in advance.
    Participants approve, edit, escalate or dismiss incidents.
- **Time box:** 15 minutes per arm (`study.time_box_minutes` in `configs/pipeline.yaml`; the
  start form defaults to it). The repository ends the session at exactly its deadline, even if
  the tab is closed. After that, no flag or decision is accepted.
- **Participants:** codes only (P1–P5), never real names. The app refuses anything that isn't an
  upper-case code such as `P1`.

### Batches

The two study batches have **disjoint scenario sets**, so nobody sees the same attack type twice.

| Batch ID | Config | Seed | Attacks | Check results |
|---|---|---|---|---|
| `study-A` | `configs/study_a.yaml` | 42 | SCN-01, SCN-03, SCN-05, SCN-07 | 3,000 alerts → 61 incidents; the attack incidents rank 1–4 |
| `study-B` | `configs/study_b.yaml` | 2026 | SCN-02, SCN-04, SCN-06 | 3,000 alerts → 56 incidents; the attack incidents rank 1–3 |
| `practice` | `configs/study_practice.yaml` | 5 | none | 500 alerts, noise only |

**Seed choice for study-B.** It was pre-committed. The candidate order was 2026, 7, 13, 99, 314,
and the first seed that passed every generator, correlation and scoring check would be used.
2026 passed. The other candidates were checked afterwards and also pass, so the choice didn't
depend on which seed looked best. study-A reuses seed 42, the development seed, with only the
study-A scenarios.

**Practice batch.** It has no attacks, so participants can learn both screens without seeing any
scenario. Practice sessions use purpose `practice` and are never analysed.

### What counts as a detection

Time to detect is measured from **session start**, so scanning the list or the queue counts in
both arms.

| | Baseline arm | Tool arm |
|---|---|---|
| **Detection of an attack** | the first flag on **any** alert of that attack (lenient towards the baseline) | the first approve, edit or escalate on an incident containing any alert of that attack |
| **Not a detection** | flags after the time box | dismiss decisions; decisions after the time box |
| **False positive** | each distinct noise alert flagged | each incident approved, edited or escalated that contains no attack alert |

- **Missed attacks:** an attack not detected within the time box is censored at τ = 15 min. RMST
  is the mean of min(t, τ) over the batch's attacks, which equals the area under the
  Kaplan–Meier curve up to τ. It is averaged per participant, then over participants per arm.
- **Ending early:** a participant who ends a session early gets no time back. Anything still
  undetected counts as τ.
- **First-decision MTTT (tool arm only):** the mean time from opening an incident to its first
  decision. The baseline has no incidents, so there is no comparable number. Brief generation
  happens before the sessions and isn't part of any time.

### Counterbalancing schedule

| Participant | First arm | Second arm |
|---|---|---|
| P1 | Baseline · study-A | Tool · study-B |
| P2 | Tool · study-A | Baseline · study-B |
| P3 | Baseline · study-B | Tool · study-A |
| P4 | Tool · study-B | Baseline · study-A |
| P5 | Baseline · study-A | Tool · study-B |

- **P5 imbalance:** with five participants the design can't be fully balanced. P5 repeats P1's
  order and batches, so:
  - baseline runs first three times and tool twice
  - study-A is used for the baseline three times and study-B twice

  The results document states this. `evaluation.mttt_study.SCHEDULE` holds the same table, and
  the results list any session that doesn't match it.
- **Exclusions:**
  - only sessions with purpose `study` are analysed
  - practice and dry-run sessions, sessions still running, and batches without labels are
    excluded
  - repeats: only the first completed session per participant and arm counts
  - every exclusion is listed in the results

## Setup checklist (before the first participant)

1. **Generate the batches.** The output directory name is the batch ID:

   ```bash
   nullpunkt-generate --config configs/study_a.yaml --out data/generated/study-A
   nullpunkt-generate --config configs/study_b.yaml --out data/generated/study-B
   nullpunkt-generate --config configs/study_practice.yaml --out data/generated/practice
   ```

2. **Prepare all three into a separate study database, with briefs.** Ollama must be running for
   this step. Briefs take about 3–6 minutes per batch:

   ```bash
   export DB_PATH=data/generated/study.db
   nullpunkt-prepare-shift --batch data/generated/study-A
   nullpunkt-prepare-shift --batch data/generated/study-B
   nullpunkt-prepare-shift --batch data/generated/practice
   ```

   Each run prints a `briefs:` summary by source. A few `template` briefs are normal: they're
   the fallback when a Phi brief fails validation (see `docs/briefing_evaluation.md`). If every
   brief in a batch is `template`, Ollama wasn't reachable, so start it and re-run that batch
   with `--replace`. Ollama isn't
   needed during the sessions, because every brief is already in the database.
3. **Do a dry run.** Run one full session per arm with purpose `dry-run` and code `P0`. It checks
   the countdown, the auto-end and the flag and decision flow. Dry-run sessions are recorded but
   never analysed.
4. **Prepare the laptop.**
   - Close every other application and silence notifications.
   - Start the app with `DB_PATH` pointing at the study database:
     `DB_PATH=data/generated/study.db streamlit run app/streamlit_app.py`
   - Use a full-screen browser window.
5. **Print the schedule** above and tick each arm off as it's completed.

## Between-participant checklist

Before **every** session:

1. The app shows the sidebar setup screen (no session running). If a session is still running,
   press **End session**. If the notice says "time box reached", the previous session has
   already ended.
2. Open **Start a study session** in the sidebar. Enter the **participant code** and check it
   against the schedule. Never enter a real name.
3. Choose the **arm** and the **batch** from the schedule.
4. Set **Purpose** to `study` (or `practice` for the practice round). Leave **Time box
   (minutes)** at 15.
5. Read aloud the "Check before starting" line under the form (code · arm · batch · purpose).
   Compare it with the printed schedule, and only then press **Start session**.
6. Check that the right pages appear: **Alert list** only for baseline; **Queue**, **Incident**
   and **Handover** for tool.

## Facilitator neutrality

The facilitator built the system and knows where the attacks are, so everything they say is
scripted.

- **Say only the script below.** Read it word for word, identically for every participant.
- **Content questions.** For any question about the alerts, incidents, briefs, or whether
  something is malicious, the only reply is:
  > "I can't help with the content; use your judgement."
- **UI mechanics.** Answer questions such as "how do I filter?" or "where is the flag button?"
  only during the practice round. During a timed arm, UI questions also get the fixed reply.
- **Seating.** During timed arms, sit where you can't see the screen, and give no reaction to
  anything the participant says or does.
- **After a session.** Don't comment on performance or reveal any answers until the participant
  has finished both arms. It's best to wait until all participants are done.

## Participant script

Read word for word.

**Welcome (once, before practice)**

> "Thanks for taking part. You'll be a SOC analyst at the start of a shift. You'll see a shift's
> worth of security alerts twice: once with a plain alert list, and once with our triage tool.
> Each time you have 15 minutes. Your job is to find activity that looks like a real attack, as
> quickly as you can. Not every alert is an attack, and I won't tell you how many attacks there
> are. You'll be identified only by a code, P-number, not by your name. First there's a short
> practice round with data that is not part of the study, so you can learn the screens. During
> practice you can ask me how the screens work. During the timed rounds I can't help with
> anything, and I'll sit where I can't see your screen. Any questions before we start?"

**Practice (about 5 minutes per screen, purpose `practice`, batch `practice`)**

> "This is practice. Nothing here is recorded for the study. Try the search and filters, open
> things, and try recording a flag or a decision. Ask me if something on the screen doesn't work
> the way you expect."

**Before a baseline arm**

> "This round uses the alert list. It shows every alert, most severe first. You can search and
> filter. When you find an alert you think is part of an attack, select it and flag it. A note is
> optional. You have 15 minutes. The timer is in the sidebar, and the session ends by itself when
> it reaches zero. If you believe you've found everything, you may press End session, but you
> won't get the time back. I'll start the timer now."

**Before a tool arm**

> "This round uses the triage tool. Alerts are grouped into incidents, ranked in a queue, with a
> written brief for each. When you think an incident is an attack, approve, edit or escalate it.
> When you think it's benign, dismiss it with a reason. You have 15 minutes. The timer is in the
> sidebar, and the session ends by itself when it reaches zero. If you believe you've found
> everything, you may press End session, but you won't get the time back. I'll start the timer
> now."

**When the time box ends**

> "Time's up. Thank you."

Then, after the second arm only:

> "That's the end of the study. Please don't discuss the content with other participants until
> everyone has taken part."

## Results

After all sessions, run this from the repository root. It reads labels from each batch
directory, and this is the only place labels are used:

```bash
python -m nullpunkt.evaluation.mttt_study --db data/generated/study.db \
    --batch study-A=data/generated/study-A --batch study-B=data/generated/study-B \
    --out docs/mttt_study.md
```

It writes `docs/mttt_study.md`, which contains:

- the headline RMST per arm, the improvement, and whether the ≥ 50 % target was met
- detection rates, false positives and first-decision MTTT
- a per-participant table
- the paired comparison with its descriptive p
- per-attack detection times
- the method, the schedule check and exclusions, and the limitations

The document is committed as generated. It isn't edited by hand.

## Limitations (stated in the results)

- **Small n:** five participants; no significance claim.
- **Synthetic data:** the attacks and noise come from our own generator, and the system was tuned
  on the same generator (other seeds).
- **Unequal batches:** study-A has four attacks and study-B three, and the P5 imbalance above.
- **Learning effects:** the second arm benefits from practice whichever arm it is.
  Counterbalancing spreads this effect but can't remove it with n = 5.
- **Priming:** participants saw the Round 1 deck, which describes the product's goal and may
  prime them to look for low-severity activity on critical assets. This affects both arms
  equally.
- **Facilitator:** the facilitator knows the answers. The script and seating rules above limit
  what they can signal.
- **Lenient baseline detection:** one flagged alert detects a whole attack. This favours the
  baseline, so the measured improvement is conservative.
