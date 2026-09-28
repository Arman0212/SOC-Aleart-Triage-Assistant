# Architecture

Nullpunkt turns a shift's worth of alerts (about 3,000) into about 60 ranked incidents, each with
MITRE ATT&CK techniques, an explainable risk score and a short brief that an analyst approves.
Types are defined in [data_contract.md](data_contract.md).

> **Status: Phase 2.**
>
> - **Built:** the contract, loaders, sample batch and tests, the synthetic data generator
>   ([scenarios.md](scenarios.md)), and stages 1–2 (ingestion and
>   [correlation](#correlation)).
> - **Designed only:** stages 3–5.

## Pipeline

```mermaid
flowchart LR
    subgraph batch["Batch files"]
        A[alerts.jsonl]
        S[assets.csv]
        L[labels.csv]
    end

    A --> I
    S --> I
    I["1 · Ingest<br/><i>ingestion</i><br/>list[Alert], dict[host, Asset]"]
    I --> C["2 · Correlate<br/><i>correlation</i><br/>Incident"]
    C --> M["3 · Map<br/><i>attack</i><br/>+ techniques"]
    M --> R["4 · Rank<br/><i>scoring</i><br/>+ score"]
    R --> B["5 · Brief<br/><i>briefing</i> · Phi via Ollama<br/>+ brief"]
    B --> D[("SQLite<br/><i>storage</i>")]
    D --> U["Analyst review<br/>Streamlit"]
    U -- Decision --> D

    L -.-> E["Evaluation<br/><i>evaluation</i>"]
    D -.-> E

    G["generator"] -.-> batch
```

Solid arrows are the pipeline. Dotted arrows are offline: the generator writes batches, and
evaluation compares pipeline output and analyst decisions against the labels.

## Stages and owners

| # | Stage | Package | Reads | Produces |
|---|---|---|---|---|
| – | Generate | `generator` | `configs/generator.yaml` | `alerts.jsonl`, `assets.csv`, `labels.csv`, `manifest.json` in `data/generated/<batch>/` |
| 1 | Ingest | `ingestion` | batch files | validated `list[Alert]` (sorted by time) and `dict[str, Asset]` |
| 2 | Correlate | `correlation` | alerts, assets | `Incident`s with `alert_ids`, `first_seen`, `last_seen`, `hosts`, `users`, `ips` |
| 3 | Map | `attack` | incident + its alerts | `Incident.techniques` |
| 4 | Rank | `scoring` | incident, assets | `Incident.score` (`ScoreBreakdown`, `risk_score` 0–100) |
| 5 | Brief | `briefing` | scored incident | `Incident.brief` (`Brief`) |
| – | Persist | `storage` | incidents, decisions | SQLite database at `DB_PATH` |
| – | Review | Streamlit app | stored incidents | `Decision`s and an updated `Incident.status` |
| – | Evaluate | `evaluation` | labels, incidents, decisions | detection metrics and MTTT before vs after |

Shared types and constants live in `core`.

Mapping runs before ranking because the score's `stage_multiplier` depends on where the
techniques sit in the kill chain. The deck presents Rank before Map as the narrative order, but
execution maps first because scoring uses tactics.

## Correlation

`nullpunkt.correlation.correlate(alerts, assets, config)` returns incidents with `alert_ids`,
`first_seen`, `last_seen`, `hosts`, `users` and `ips` filled in. `run_correlation` also returns
a `CorrelationResult`:

- **Link reasons:** the links that built each incident, for example "same user jill.rhodes,
  12 min apart".
- **Hubs:** the detected hubs, with their statistics.

Settings live in `configs/pipeline.yaml` under `correlation:`. The tuned values and the reasoning
behind them are in [correlation_tuning.md](correlation_tuning.md).

1. **Entities.** Each alert has a host, a user, and source/destination IPs.
   - IPs that belong to an inventory asset become that host, so "login on FINDB01 from
     10.30.0.7" links to WS-FIN-03.
   - Addresses outside `internal_networks` are external.
2. **Roles.**
   - **Actors:** the user and the source.
   - **Host:** *local* when nobody else acted on it, and a *target* when someone did.
   - **External destinations** (C2, exfiltration) count as active.
3. **Hubs**, detected from the batch. An entity is a hub if it:
   - is in ≥ 6 % of alerts,
   - co-occurs with ≥ 4 distinct users,
   - as an actor, acts on ≥ 4 distinct hosts, or
   - is an inventory asset of a known busy type (domain controller, proxy, vulnerability
     scanner, backup server, software distribution) and appears in ≥ 1 % of alerts.

   Hubs never create links on their own; an alert on a hub joins an incident through its other
   entities.
4. **Linking by per-entity time chaining.** Each alert links to the previous alert sharing a
   non-hub entity within 120 minutes. The alerts are processed in time order, so the pass is
   linear after sorting. Rules:
   - Active occurrences link to each other.
   - A target links only to activity on that host (exploit, then a shell), never to another
     target.
   - Scan rules (ATT&CK T1595\*, T1046) never link through the host they probed.
   - Inbound non-scan alerts do not link through their rotating external source.
   - A host links only if the alert has a non-hub actor, or no actor at all.
5. **Recurrence.** The same rule on the same key entity is linked across the whole shift, as long
   as the group involves at most one user.
   - **Key:** the user or source, or the target host for inbound noise.
   - **Covered cases:** typo bursts, scanner waves, and IDS noise against one server.
   - **Protected cases:** DC01 and shared VPN exit IPs, which serve many users, never merge people.
6. **Hub routines.** With `hub_actor_routine`, all single-user activity of a fan-out hub account
   becomes one routine incident.
7. **Components become incidents.** A union-find computes the connected components, and incidents
   are numbered `INC-0001…` by first alert. Every successful union is kept as a `Link`, so each
   incident carries exactly the spanning set of reasons that built it.

**Known limitation.** A compromised *shared* hub account (for example `adm-it` or a service
account) would be absorbed into that account's routine incident instead of standing out. Our
scenarios deliberately use a personal admin account (SCN-06). Per-account behavioural baselines
are future work; see [correlation_tuning.md](correlation_tuning.md#known-limitation-hub-routines-absorb-a-compromised-hub-account).

```bash
python -m nullpunkt.correlation --batch data/generated/batch-001   # incidents, sizes, hubs
```

## How an Incident is enriched

Each stage adds one field and leaves the rest alone, so any stage can be tested on its own with a
hand-built `Incident`.

| After | `techniques` | `score` | `brief` | `status` |
|---|---|---|---|---|
| Correlate | `[]` | `null` | `null` | `open` |
| Map | `[Technique, …]` | `null` | `null` | `open` |
| Rank | set | `ScoreBreakdown` | `null` | `open` |
| Brief | set | set | `Brief` | `open` |
| Review | set | set | set | `approved` / `dismissed` / `escalated` |

## Ranking

The claim the project rests on: severity alone is a poor triage order. A HIGH alert on a
criticality-1 laptop matters less than a chain of LOW and MEDIUM alerts on a criticality-5
finance database. `ScoreBreakdown` therefore combines:

- `severity_weight`
- `asset_criticality`
- `stage_multiplier`, from the kill-chain stage
- `noise_penalty`, for rules that fire often and are usually benign

It stores each component next to the final `risk_score` so the ranking can be explained. The exact
formula is owned by `scoring` and is not fixed yet (Phase 3).

The sample batch's scenario SCN-01 is built to prove this. Its alerts are all LOW or MEDIUM and
end on FINDB01 (criticality 5), while the loudest alerts in the batch are HIGH or CRITICAL false
positives on laptops. `tests/integration/test_sample_batch.py` asserts that ranking by severity
buries SCN-01 and ranking by severity × criticality puts it at the top.

## Briefs and analyst review

- `briefing` asks Phi (the `OLLAMA_MODEL` served at `OLLAMA_HOST`) for a structured brief.
- If the model is unavailable, or its output fails validation, `briefing` falls back to a
  template brief. `Brief.generated_by` records which path produced it.
- `Brief.validated` is `True` only if every host in `affected_assets` appears in `Incident.hosts` and every ID in `techniques` appears in `Incident.techniques`; otherwise the template fallback is used.
- In the Streamlit app, the analyst approves, edits, dismisses or escalates each incident. Every
  action is stored as a `Decision`, whose `triage_seconds` feeds the MTTT measurement.

## Ground-truth boundary

Only `evaluation` reads labels, and only `generator` (offline tooling) writes them. Stages 1–5,
`storage` and the app see only `Alert` and `Asset`. They never import `GroundTruth`,
`nullpunkt.evaluation` or `nullpunkt.generator`, and never read `labels.csv` or `manifest.json`.

Unit tests enforce this by parsing every module. See
[data_contract.md](data_contract.md#why-labels-live-in-a-separate-file).

The detection rule catalog (`core/detection_rules.py`) is not truth. It maps each rule to the one
technique it detects, which a real SOC knows too, so the `attack` stage may use it.
