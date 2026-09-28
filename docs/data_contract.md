# Data contract

The single source of truth is [`src/nullpunkt/core/schema.py`](../src/nullpunkt/core/schema.py)
(`SCHEMA_VERSION = "1.0"`). This page explains it for humans. If the two disagree, the code wins
and this page is wrong: please fix it.

Changing `schema.py` needs team approval (see [CONTRIBUTING.md](../CONTRIBUTING.md)), because
every package depends on it.

## Ground rules

- **Unknown fields are an error.** Every model inherits `ContractModel`
  (`extra="forbid"`), so a typo like `serverity` fails validation instead of being dropped.
- **Timestamps are UTC.** A naive timestamp such as `2026-10-01T09:00:00` is rejected. A
  timestamp with an explicit offset is converted to UTC, so `2026-10-01T14:30:00+05:30` becomes
  `2026-10-01T09:00:00Z`. Write UTC with a `Z` suffix in files.
- **IP addresses** are checked with `ipaddress.ip_address`, so IPv4 and IPv6 are both accepted.
- **Enums are lowercase strings** (`StrEnum`) in files and JSON.

## Batch files

A batch is a directory with three files. The pipeline reads the first two. Only
`nullpunkt.evaluation` reads the third, and only the generator writes it. Generated batches
also contain `manifest.json` (seed, config, counts and a per-scenario summary). It reveals the
answers too, so it is evaluation-only as well; see [scenarios.md](scenarios.md).

| File | Format | One record is | Loader | Who may read it |
|---|---|---|---|---|
| `alerts.jsonl` | JSON Lines, UTF-8 | `Alert` | `nullpunkt.ingestion.loader.load_alerts` | everyone |
| `assets.csv` | CSV with header | `Asset` | `nullpunkt.ingestion.loader.load_assets` | everyone |
| `labels.csv` | CSV with header | `GroundTruth` | `nullpunkt.evaluation.ground_truth.load_ground_truth` | **evaluation only** |

Loader behaviour:

- Loaders stop at the first bad record and raise `DataFileError` (a `ValueError`) whose message
  starts with `path:line`.
- Duplicate `alert_id`s (in alerts or labels) and duplicate `host`s (in assets) are rejected.
- `load_alerts` skips blank lines and returns alerts sorted by `(timestamp, alert_id)`.
- `write_alerts` writes every field, with `null` for missing values, so every line has the same keys.
- `write_assets` and `write_ground_truth` write CSV with `\n` line endings, so output is
  byte-identical on every OS.
- In CSV files an empty cell means "no value" (`None`). Booleans are written `true` / `false`.

Batches:

- `data/sample/` is a small hand-written fixture that is committed.
- Generated batches go in `data/generated/`, which is git-ignored.

## ID conventions

| ID | Pattern | Example | Used in |
|---|---|---|---|
| Alert | `ALR-` + 6 digits (`^ALR-\d{6}$`) | `ALR-000042` | `Alert.alert_id`, `GroundTruth.alert_id` |
| Incident | `INC-` + 4 digits (`^INC-\d{4}$`) | `INC-0007` | `Incident.incident_id`, `Decision.incident_id` |
| Scenario | `SCN-` + 2 digits (`^SCN-\d{2}$`) | `SCN-01` | `GroundTruth.scenario_id` |
| ATT&CK technique | `T` + 4 digits, optional `.` + 3-digit sub-technique (`^T\d{4}(\.\d{3})?$`) | `T1078`, `T1566.001` | `Technique.technique_id`, `GroundTruth.true_technique` |

Tactic IDs (`TA0001`) are not technique IDs and are rejected. The same patterns are also applied
to each item of `Incident.alert_ids` (alert IDs) and `Brief.techniques` (technique IDs).

## Input models

### Alert: one line of `alerts.jsonl`

One alert as the SOC sees it. It never contains ground truth.

| Field | Type | Required | Rules |
|---|---|---|---|
| `alert_id` | str | yes | `ALR-######` |
| `timestamp` | datetime | yes | timezone-aware |
| `source` | `Source` | yes | `firewall`, `edr`, `ids`, `auth`, `email`, `proxy` |
| `rule_name` | str | yes | non-empty |
| `severity` | `Severity` | yes | `low`, `medium`, `high`, `critical` |
| `host` | str | yes | non-empty; should match an `Asset.host` |
| `user` | str | no | |
| `src_ip` | str | no | valid IP |
| `dst_ip` | str | no | valid IP |
| `message` | str | yes | |

`SEVERITY_WEIGHT` maps severity to an integer: low 1, medium 2, high 3, critical 4.

```json
{"alert_id":"ALR-000010","timestamp":"2026-10-01T09:33:19Z","source":"ids","rule_name":"SMB admin share access","severity":"medium","host":"FINDB01","user":"j.meyer","src_ip":"10.0.3.12","dst_ip":"10.0.1.20","message":"ADMIN$ and C$ shares accessed on FINDB01 from WS-FIN-12"}
```

### Asset: one row of `assets.csv`

| Field | Type | Required | Rules |
|---|---|---|---|
| `host` | str | yes | non-empty, unique |
| `ip` | str | yes | valid IP |
| `asset_type` | `AssetType` | yes | servers: `domain_controller`, `database`, `file_server`, `mail_server`, `vpn_gateway`, `web_server`; infrastructure: `jump_host`, `proxy`, `patch_server`, `software_distribution`, `vuln_scanner`, `backup_server`; endpoints: `workstation`, `laptop` |
| `owner` | str | yes | |
| `criticality` | int | yes | 1 (least) to 5 (crown jewels) |

```csv
host,ip,asset_type,owner,criticality
FINDB01,10.0.1.20,database,finance,5
```

### GroundTruth: one row of `labels.csv` (evaluation only)

| Field | Type | Required | Rules |
|---|---|---|---|
| `alert_id` | str | yes | `ALR-######`, one label per alert |
| `scenario_id` | str | no | `SCN-##`; set for true positives |
| `is_true_positive` | bool | yes | |
| `true_technique` | str | no | ATT&CK technique ID; set for true positives |

```csv
alert_id,scenario_id,is_true_positive,true_technique
ALR-000010,SCN-01,true,T1021.002
ALR-000011,,false,
```

## Output models

The pipeline produces these. An `Incident` starts bare and is enriched stage by stage; see
[architecture.md](architecture.md).

### Incident

| Field | Type | Default | Rules |
|---|---|---|---|
| `incident_id` | str | required | `INC-####` |
| `alert_ids` | list[str] | required | at least one; each `ALR-######` |
| `first_seen` | datetime | required | timezone-aware |
| `last_seen` | datetime | required | timezone-aware; not before `first_seen` |
| `hosts` | list[str] | required | |
| `users` | list[str] | `[]` | |
| `ips` | list[str] | `[]` | |
| `techniques` | list[`Technique`] | `[]` | set by `attack` |
| `score` | `ScoreBreakdown` or null | `null` | set by `scoring` |
| `brief` | `Brief` or null | `null` | set by `briefing` |
| `status` | `IncidentStatus` | `open` | `open`, `approved`, `dismissed`, `escalated` |

### Technique

| Field | Type | Default | Rules |
|---|---|---|---|
| `technique_id` | str | required | `T####` or `T####.###` |
| `name` | str | required | e.g. `PowerShell` |
| `tactic` | str | required | e.g. `execution` |
| `confirmed` | bool | `true` | `false` for a technique that is suspected rather than observed |

### ScoreBreakdown

Every score carries its components so an analyst can see why an incident ranks where it does.

| Field | Type | Default | Rules |
|---|---|---|---|
| `severity_weight` | int | required | 1 to 4 (see `SEVERITY_WEIGHT`) |
| `asset_criticality` | int | required | 1 to 5 |
| `stage_multiplier` | float | required | at least 1.0 |
| `noise_penalty` | float | `1.0` | greater than 0, at most 1.0 (1.0 = no penalty) |
| `risk_score` | float | required | 0 to 100 |
| `explanation` | str | required | plain-language reason for the score |

The schema only checks each field's range. It does not check that `risk_score` is consistent with
the other components. The formula belongs to `nullpunkt.scoring`; see
[scoring_evaluation.md](scoring_evaluation.md).

### Brief

A shift brief for one incident, written by Phi or by a template fallback.

| Field | Type | Rules |
|---|---|---|
| `summary` | str | |
| `affected_assets` | list[str] | host names |
| `techniques` | list[str] | ATT&CK technique IDs, each `T####` or `T####.###` |
| `timeline` | list[str] | one entry per event |
| `next_action` | str | the recommended next step |
| `confidence` | `Confidence` | `low`, `medium`, `high` |
| `generated_by` | `BriefSource` | `llm` or `template` |
| `validated` | bool | `True` only if every host in `affected_assets` appears in `Incident.hosts` and every ID in `techniques` appears in `Incident.techniques`; otherwise the template fallback is used |

All fields are required.

### Decision

One analyst action on one incident. Mean time to triage (MTTT) is computed from these records.

| Field | Type | Default | Rules |
|---|---|---|---|
| `incident_id` | str | required | `INC-####` |
| `action` | `DecisionAction` | required | `approve`, `edit`, `dismiss`, `escalate` |
| `analyst` | str | required | |
| `opened_at` | datetime | required | timezone-aware |
| `decided_at` | datetime | required | timezone-aware; not before `opened_at` |
| `edited_brief` | str or null | `null` | the analyst's version when `action` is `edit` |
| `notes` | str or null | `null` | |

`triage_seconds` is a computed property, `decided_at - opened_at` in seconds. It is not stored,
and it is never negative because the schema rejects `decided_at` earlier than `opened_at`.

## Why labels live in a separate file

The whole point of the project is to measure whether the pipeline finds real attacks. That only
works if the pipeline cannot see the answers.

- **No leakage.** If `is_true_positive` or `true_technique` were on `Alert`, a scorer or prompt
  could use them, even by accident, and every metric would be inflated. `Alert` has no label
  fields, and `extra="forbid"` means an alert line containing one fails to load.
- **Enforced, not just agreed.** `tests/unit/test_ground_truth.py` fails in two cases:
  - A package other than `core`, `evaluation` or `generator` imports `GroundTruth` or
    `nullpunkt.evaluation`, or mentions `labels.csv` or `manifest.json`.
  - A package other than `evaluation` or `generator` imports `nullpunkt.generator`.
- **Realistic input.** A real SOC receives alerts and an asset inventory, never labels. Keeping
  the same shape means the pipeline could run on real data unchanged.
