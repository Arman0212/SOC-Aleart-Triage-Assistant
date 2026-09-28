# Correlation tuning

How the defaults in [`configs/pipeline.yaml`](../configs/pipeline.yaml) (`correlation:`) were
chosen, and the acceptance rules the integration test enforces. The algorithm itself is described
in [architecture.md](architecture.md#correlation).

Reproduce everything below with:

```bash
python -m nullpunkt.evaluation.sweep_correlation --top 15
```

It takes about 4–5 minutes.

## Method

- **Tuning data:** generated shifts with seeds **101–105** (3,000 alerts each, all 7 scenarios).
- **Held-out check:** seed **42**, the demo batch. It was never used for selection and is reported
  only as a check against overfitting.
- **Labels:** used only by `nullpunkt.evaluation`. The correlator never sees them.

**Grid:** 2,016 settings. Every tuned value is an interior point, except the two that are ends of
their range by nature (no gap, routine on).

| Parameter | Values |
|---|---|
| `window_minutes` | 30, 45, 60, 90, 120, 150, 180 |
| `hub_min_share` | 0.04, 0.06, 0.08, 0.10 |
| `hub_min_users` | 3, 4, 6, 8 |
| `hub_min_fanout` | 4, 6, 8 |
| `recurrence_max_gap_minutes` | none, 120, 240 |
| `hub_actor_routine` | on, off |

**Selection order** (lexicographic, worst case over the five tuning seeds):

1. Every scenario is complete: all of its alerts are in one incident.
2. No catch-all incident (see [Size rule](#size-rule-for-large-incidents)).
3. Highest worst-case purity, excluding SCN-05. SCN-05 is impure by design; see
   [scenarios.md](scenarios.md#purity-test-scn-05-shares-its-user-with-the-noise).
4. Incident count inside 50–75 on every seed, if any setting achieves that.
5. **Robustness.** Prefer settings where *every* neighbouring grid point keeps every scenario
   complete on every tuning seed, then settings with the most such neighbours. A neighbour differs
   in one parameter by one grid step.
6. Mean incident count closest to 60, the deck's figure.
7. Smallest largest incident, then grid order.

### Why robustness comes before "closest to 60"

The first version of this sweep ranked "closest to 60" above everything except the hard criteria.
The incident count falls steadily as the window grows (68 → 66 → 65 incidents on seed 42 at 120,
150 and 180 minutes). So that criterion always picked the **longest window in the grid**:

- **First grid:** it picked 120 minutes, the edge.
- **With 150 and 180 added:** it picked 180, the new edge.
- **With robustness as a later tie-breaker:** that changed nothing, because the means were never
  exactly tied.

It also accepted `hub_min_users: 4`, one step away from breaking SCN-03 (see
[WEB02 margins](#web02-margins)). With robustness first, the choice is interior, and no single-step
change of any parameter breaks a scenario.

## Results

Top 15 of 2,016 settings:

| # | window (min) | hub share | hub users | hub fan-out | recurrence gap | routine | min completeness | min purity* | incidents (101-105) | largest | oversized OK | complete neighbours |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 150 | 0.08 | 6 | 6 | none | on | 1.00 | 1.00 | 59-65 | 7.9% | yes | 10/10 |
| 2 | 120 | 0.08 | 6 | 6 | none | on | 1.00 | 1.00 | 60-67 | 7.9% | yes | 10/10 |
| 3 | 90 | 0.08 | 6 | 6 | none | on | 1.00 | 1.00 | 65-70 | 7.9% | yes | 10/10 |
| 4 | 150 | 0.08 | 6 | 6 | 240 | on | 1.00 | 1.00 | 64-72 | 7.9% | yes | 10/10 |
| 5 | 120 | 0.08 | 6 | 6 | 240 | on | 1.00 | 1.00 | 66-74 | 7.9% | yes | 10/10 |
| 6 | 90 | 0.08 | 6 | 6 | 240 | on | 1.00 | 1.00 | 71-75 | 7.9% | yes | 10/10 |
| 7 | 150 | 0.1 | 6 | 6 | none | on | 1.00 | 1.00 | 58-65 | 7.9% | yes | 9/9 |
| 8 | 180 | 0.08 | 6 | 6 | none | on | 1.00 | 1.00 | 59-65 | 7.9% | yes | 9/9 |
| 9 | 150 | 0.08 | 6 | 4 | none | on | 1.00 | 1.00 | 59-65 | 7.9% | yes | 9/9 |
| 10 | 120 | 0.1 | 6 | 6 | none | on | 1.00 | 1.00 | 59-67 | 7.9% | yes | 9/9 |
| 11 | 120 | 0.08 | 6 | 4 | none | on | 1.00 | 1.00 | 60-67 | 7.9% | yes | 9/9 |
| 12 | 90 | 0.1 | 6 | 6 | none | on | 1.00 | 1.00 | 64-70 | 7.9% | yes | 9/9 |
| 13 | 180 | 0.08 | 6 | 6 | 240 | on | 1.00 | 1.00 | 63-70 | 7.9% | yes | 9/9 |
| 14 | 150 | 0.1 | 6 | 6 | 240 | on | 1.00 | 1.00 | 63-71 | 7.9% | yes | 9/9 |
| 15 | 90 | 0.08 | 6 | 4 | none | on | 1.00 | 1.00 | 65-70 | 7.9% | yes | 9/9 |

\* excluding SCN-05.

**Changing one parameter from the chosen setting:**

| Variant | Tuning incidents | Tuning completeness | Tuning purity* | Seed 42 incidents | Seed 42 completeness | Seed 42 purity* |
|---|---|---|---|---|---|---|
| **chosen** | 59–65 | 1.00 | 1.00 | 65 | 1.00 | 1.00 |
| window 120 | 60–67 | 1.00 | 1.00 | 67 | 1.00 | 1.00 |
| window 180 | 59–65 | 1.00 | 1.00 | 64 | 1.00 | 1.00 |
| hub share 0.06 | 59–66 | 1.00 | 1.00 | 66 | 1.00 | 1.00 |
| hub share 0.10 | 58–65 | 1.00 | 1.00 | 65 | 1.00 | 1.00 |
| hub users 4 | 59–65 | 1.00 | 1.00 | 66 | 1.00 | 1.00 |
| hub users 8 | 56–62 | 1.00 | **0.03** | 63 | 1.00 | **0.04** |
| hub fan-out 4 | 59–65 | 1.00 | 1.00 | 65 | 1.00 | 1.00 |
| hub fan-out 8 | 57–63 | 1.00 | **0.02** | 63 | 1.00 | **0.02** |
| recurrence gap 240 min | 64–72 | 1.00 | 1.00 | 66 | 1.00 | 1.00 |
| routine off | 79–84 | 1.00 | 1.00 | 86 | 1.00 | 1.00 |
| *further away:* window 60 | 70–79 | 1.00 | 1.00 | 75 | 1.00 | 1.00 |
| *further away:* recurrence gap 120 min | 73–86 | 1.00 | 1.00 | 82 | 1.00 | 1.00 |
| *further away:* hub users 3 | 62–68 | **0.33** | 1.00 | 69 | **0.62** | 1.00 |
| *previous default* (120 / 0.06 / 4 / 4) | 60–67 | 1.00 | 1.00 | 68 | 1.00 | 1.00 |

Windows of 30 or 45 minutes never kept every scenario complete (0 of 576 settings), because
SCN-04's steps can be up to 60 minutes apart.

## Chosen defaults and why

| Setting | Value | Reason |
|---|---|---|
| `window_minutes` | **150** | Below 60 minutes SCN-04 splits. From 60 up, longer windows only merge each person's bursts. 150 is the longest window whose neighbours (120 and 180) are also safe. |
| `hub_min_share` | **0.08** | At 0.04, WEB02 (4.6–5.7 % of alerts) becomes a hub and SCN-03 splits. 0.08 is two steps from that and one step from both safe neighbours. |
| `hub_min_users` | **6** | WEB02 has 3 distinct users on every seed, so 3 splits SCN-03. 6 is two steps away. 8 is too loose: FS01 (7 users) stops being a hub and SCN-06 is absorbed into file-server noise. |
| `hub_min_fanout` | **6** | Catches the helpdesk workstations, JUMP01, `adm-it`, `svc-sccm`, `svc-backup` (fan-out 6) and the internal scanner. At 8, `svc-backup` stops being a hub and SCN-01 merges with the nightly backup of FINDB01. Scenario actors act on one or two hosts. |
| `hub_min_alerts` | 20 | Keeps small test batches from declaring every entity a hub. It has no effect at 3,000 alerts. |
| `recurrence_max_gap_minutes` | **none** | Gap limits split typo users and scanner waves into several incidents each, without making any scenario purer. |
| `recurrence_max_users` | 1 | Not swept. It is what stops a shared VPN exit IP or DC01 from merging different people. |
| `hub_actor_routine` | **on** | Without it, each hub account's routine splits by rule, adding about 20 incidents. |

**Robustness check.** `test_every_scenario_survives_one_step_perturbation` moves each of the six
parameters one grid step in each direction and asserts that all seven scenarios stay complete on
seed 42.

- **One direction only:** "no recurrence gap" and "routine on" are ends of their range, so they
  are only perturbed one way.
- **Checked:** with the previous default, the test fails on `hub_min_users=3`, which is exactly
  the knife edge it exists to catch.

**Purity is only checked on the high side.** The robustness rule protects completeness, and one
step up in hub users or hub fan-out still keeps every scenario whole. But those steps merge SCN-06
or SCN-01 into large noise incidents, dropping purity to 0.02–0.04. The integration test checks
purity only at the chosen setting. Adding purity to the robustness rule is a candidate next step.

### WEB02 margins

WEB02 carries SCN-03: its web-shell and enumeration alerts share only this host, so if WEB02
becomes a hub, SCN-03 splits. Its distance to each hub threshold under the chosen settings:

| Seed | Alerts | Share (hub at 8 %) | Distinct users (hub at 6) | Fan-out (hub at 6) | Hub? |
|---|---|---|---|---|---|
| 42 | 170 | 5.7 % | 3 | 1 | no |
| 101 | 167 | 5.6 % | 3 | 1 | no |
| 102 | 149 | 5.0 % | 3 | 1 | no |
| 103 | 143 | 4.8 % | 3 | 1 | no |
| 104 | 137 | 4.6 % | 3 | 1 | no |
| 105 | 153 | 5.1 % | 3 | 1 | no |

Previously (0.06 / 4) the margins were 0.3–1.4 percentage points and 1 user. Now they are
2.3–3.4 points and 3 users.

## Held-out check: seed 42

| Scenario | Alerts | Incident | Incident size | Completeness | Purity |
|---|---|---|---|---|---|
| SCN-01 | 5 | INC-0055 | 5 | 1.00 | 1.00 |
| SCN-02 | 16 | INC-0061 | 16 | 1.00 | 1.00 |
| SCN-03 | 8 | INC-0064 | 8 | 1.00 | 1.00 |
| SCN-04 | 7 | INC-0053 | 7 | 1.00 | 1.00 |
| SCN-05 | 6 | INC-0013 | 64 | 1.00 | 0.09 |
| SCN-06 | 4 | INC-0065 | 4 | 1.00 | 1.00 |
| SCN-07 | 4 | INC-0057 | 4 | 1.00 | 1.00 |

- **Volume:** 3,000 alerts become **65 incidents**, 46.2 alerts per incident. The largest has 236
  alerts (7.9 %).
- **Speed:** correlation takes about 0.03 s.

**SCN-05 (purity 0.09).** INC-0013 is the SCN-05 user's whole shift:

| Rule | Alerts | SCN-05 |
|---|---|---|
| Failed login | 46 | |
| Successful login after failures | 10 | |
| Mass file access on share | 3 | yes |
| Account lockout | 2 | |
| Login from new source host | 1 | yes |
| Large archive created | 1 | yes |
| Large outbound transfer | 1 | yes |

The exfiltration chain joins the user's password-typo bursts on DC01 through the shared user
(for example, "same user jeremy.johnson, 11 min apart"). This is the deliberate purity test: the
incident is complete, and the analyst sees the typos next to the exfiltration.

## Acceptance thresholds (integration test)

`tests/integration/test_correlation_batch.py`, on seed 42:

| Check | Threshold | Seed 42 |
|---|---|---|
| Completeness, every scenario | 1.0 | 1.0 |
| Completeness after any one-step parameter change | 1.0 | 1.0 (10 neighbours) |
| Purity, every scenario except SCN-05 | ≥ 0.9 | 1.0 |
| Purity, SCN-05 | ≥ 0.05 | 0.09 |
| Incident count | 50–75 | 65 |
| Largest incident | ≤ 10 % | 7.9 % |
| Incidents above 5 % | each a single recurring activity | 3, all single |
| Correlation time | < 2 s | ~0.03 s |

**Incident count.** The tuned setting reaches the requested 50–75 range on every tuning seed
(59–65) and on seed 42 (65), so the test uses 50–75 directly. The fallback rule (tuned result
± 10 %) was not needed.

## Size rule for large incidents

A shift contains a few legitimately huge, boring activities. Splitting them only adds clicks for
the analyst. So the rule is not "nothing above 5 %"; it is:

- **No incident above 10 %** of the batch.
- **Every incident above 5 % is a single recurring activity:**
  - every alert shares one actor (a user or a source) or one target host, and
  - the incident involves at most one user.
  - `nullpunkt.evaluation.metrics.is_single_activity` checks this.

Seed 42 has three such incidents:

| Incident | Size | Activity | Common entity |
|---|---|---|---|
| INC-0016 | 236 (7.9 %) | internal vulnerability scanner sweeping the network | actor VULNSCAN01, 0 users |
| INC-0018 | 236 (7.9 %) | nightly backup jobs on the databases and file servers | user `svc-backup` |
| INC-0001 | 183 (6.1 %) | spam campaigns blocked at the mail gateway | target MAIL01, 0 users |

## Known limitation: hub routines absorb a compromised hub account

With `hub_actor_routine` on, all single-user activity of a fan-out hub account becomes one
routine incident. If an attacker used such an account, such as the shared `adm-it` or a service
account, their actions would be **absorbed into that routine incident** instead of standing
out.

Our scenarios deliberately use a *personal* admin account. SCN-06 uses `adm-<it user>` from that
admin's own laptop, which acts on one host and is not a hub. So this gap is not exercised by the
generated data.

Future work: per-account behavioural baselines, so that new rules, new targets or unusual hours
for a hub account break out of its routine incident instead of joining it.

## Known gap: hub accounts inflate the user-diversity metric

The "shared by N users" hub criterion counts *every* user that co-occurs with an entity, including
admin and service accounts that are themselves hubs. WEB02's three users on every seed are
`adm-it`, `svc-sccm` and one personal admin account. None of them are people using WEB02, but
they are what puts it within reach of the threshold.

We prototyped counting only non-hub users:

- **Fixed:** WEB02's count drops to 0, and `hub_min_users: 3` no longer splits SCN-03.
- **Broke:** the busy servers (FS01, FS02, FINDB01, HRDB01) also stop being hubs, because most of
  their users are service and admin accounts. Purity collapses to 0.03, and incident counts rise
  to 76–128.

A future redesign should **count only human users** for diversity while **keeping busy servers as
hubs** by some other signal, for example many distinct *actors* of any kind, or an inventory
hint for file servers and databases. Until then, the robustness-first selection keeps the tuned
setting away from this edge.
