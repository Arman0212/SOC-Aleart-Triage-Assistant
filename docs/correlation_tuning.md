# Correlation tuning

How the defaults in [`configs/pipeline.yaml`](../configs/pipeline.yaml) (`correlation:`) were
chosen, and the acceptance rules the integration test enforces. The algorithm itself is described
in [architecture.md](architecture.md#correlation).

Reproduce everything below with:

```bash
python -m nullpunkt.evaluation.sweep_correlation --top 12
```

It takes about 100 seconds.

## Method

- **Tuning data:** generated shifts with seeds **101–105** (3,000 alerts each, all 7 scenarios).
- **Held-out check:** seed **42**, the demo batch. It was never used for selection and is reported
  only as a check against overfitting.
- **Labels:** used only by `nullpunkt.evaluation`. The correlator never sees them.

**Grid:** 810 settings.

| Parameter | Values |
|---|---|
| `window_minutes` | 30, 45, 60, 90, 120 |
| `hub_min_share` | 0.04, 0.06, 0.08 |
| `hub_min_users` | 3, 4, 6 |
| `hub_min_fanout` | 4, 6, 8 |
| `recurrence_max_gap_minutes` | none, 120, 240 |
| `hub_actor_routine` | on, off |

**Selection order** (lexicographic, worst case over the five tuning seeds):

1. Every scenario is complete: all of its alerts are in one incident.
2. No catch-all incident (see [Size rule](#size-rule-for-large-incidents)).
3. Highest worst-case purity, excluding SCN-05. SCN-05 is impure by design; see
   [scenarios.md](scenarios.md#purity-test-scn-05-shares-its-user-with-the-noise).
4. Incident count inside 50–75 on every seed, if any setting achieves that.
5. Mean incident count closest to 60, the deck's figure.
6. Smallest largest incident, then grid order.

## Results

Top 12 of 810 settings:

| # | window (min) | hub share | hub users | hub fan-out | recurrence gap | routine | min completeness | min purity* | incidents (101-105) | largest | oversized OK |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 120 | 0.06 | 4 | 4 | none | on | 1.00 | 1.00 | 60-67 | 7.9% | yes |
| 2 | 120 | 0.06 | 6 | 4 | none | on | 1.00 | 1.00 | 60-67 | 7.9% | yes |
| 3 | 120 | 0.08 | 4 | 4 | none | on | 1.00 | 1.00 | 60-67 | 7.9% | yes |
| 4 | 120 | 0.08 | 4 | 6 | none | on | 1.00 | 1.00 | 60-67 | 7.9% | yes |
| 5 | 120 | 0.08 | 4 | 8 | none | on | 1.00 | 1.00 | 60-67 | 7.9% | yes |
| 6 | 120 | 0.08 | 6 | 4 | none | on | 1.00 | 1.00 | 60-67 | 7.9% | yes |
| 7 | 120 | 0.08 | 6 | 6 | none | on | 1.00 | 1.00 | 60-67 | 7.9% | yes |
| 8 | 120 | 0.06 | 4 | 6 | none | on | 1.00 | 1.00 | 60-68 | 7.9% | yes |
| 9 | 120 | 0.06 | 6 | 6 | none | on | 1.00 | 1.00 | 60-68 | 7.9% | yes |
| 10 | 90 | 0.06 | 4 | 4 | none | on | 1.00 | 1.00 | 65-70 | 7.9% | yes |
| 11 | 90 | 0.06 | 6 | 4 | none | on | 1.00 | 1.00 | 65-70 | 7.9% | yes |
| 12 | 90 | 0.08 | 4 | 4 | none | on | 1.00 | 1.00 | 65-70 | 7.9% | yes |

\* excluding SCN-05.

**Changing one parameter from the chosen setting:**

| Variant | Tuning incidents | Tuning completeness | Seed 42 incidents | Seed 42 completeness |
|---|---|---|---|---|
| chosen | 60–67 | 1.00 | 68 | 1.00 |
| window 90 | 65–70 | 1.00 | 69 | 1.00 |
| window 60 | 70–79 | 1.00 | 76 | 1.00 |
| window 30 or 45 | – | < 1.00 on every hub setting | – | – |
| recurrence gap 240 min | 66–74 | 1.00 | 69 | 1.00 |
| recurrence gap 120 min | 84–100 | 1.00 | 99 | 1.00 |
| routine off | 89–131 | 1.00 | 93 | 1.00 |
| hub share 0.08 | 60–67 | 1.00 | 68 | 1.00 |
| hub share 0.04 | 63–70 | **0.33** | 75 | **0.62** |

## Chosen defaults and why

| Setting | Value | Reason |
|---|---|---|
| `window_minutes` | **120** | Windows below 60 minutes never keep SCN-04 whole: its steps are up to 60 minutes apart. From 60 upwards every scenario stays whole and pure, and a longer window only merges each person's bursts into one incident (76 → 69 → 68 on seed 42). 120 is the edge of the grid; longer windows were not tried. |
| `hub_min_share` | **0.06** | At 0.04, WEB02 (4.6–5.7 % of alerts) becomes a hub, so SCN-03's web-shell alerts, which only share WEB02, fall apart. 0.06 and 0.08 score identically on every seed; 0.06 won on grid order. |
| `hub_min_users` | **4** | At 3, WEB02 (3 distinct users) becomes a hub, with the same SCN-03 failure. 4 and 6 are equivalent. |
| `hub_min_fanout` | **4** | Catches the helpdesk workstations, JUMP01, `adm-it`, `svc-sccm`, the internal scanner and the internet scanners (4 DMZ hosts each). Scenario actors act on one or two hosts. |
| `hub_min_alerts` | 20 | Keeps small test batches from declaring every entity a hub. It has no effect at 3,000 alerts, where the smallest volume hub has 180+ alerts. |
| `recurrence_max_gap_minutes` | **none** | Gap limits split typo users and scanner waves into several incidents each (99 incidents at 120 minutes) without making any scenario purer. |
| `recurrence_max_users` | 1 | Not swept. It is what stops a shared VPN exit IP or DC01 from merging different people. |
| `hub_actor_routine` | **on** | Without it, each hub account's routine splits by rule (for example `adm-it`'s SMB, service-creation and enumeration alerts become three incidents). That adds about 25–65 incidents. |

**Risk: WEB02's margin is thin.** It sits at 4.6–5.7 % of alerts against a 6 % threshold, and has
3 distinct users against a threshold of 4. A busier DMZ could make it a hub and split SCN-03.
`hub_min_share: 0.08` scores identically and leaves more headroom. It is worth switching once more
seeds confirm it, but the selection order picked 0.06 and we did not override it by hand.

## Held-out check: seed 42

| Scenario | Alerts | Incident | Incident size | Completeness | Purity |
|---|---|---|---|---|---|
| SCN-01 | 5 | INC-0056 | 5 | 1.00 | 1.00 |
| SCN-02 | 16 | INC-0062 | 16 | 1.00 | 1.00 |
| SCN-03 | 8 | INC-0066 | 8 | 1.00 | 1.00 |
| SCN-04 | 7 | INC-0054 | 7 | 1.00 | 1.00 |
| SCN-05 | 6 | INC-0013 | 64 | 1.00 | 0.09 |
| SCN-06 | 4 | INC-0068 | 4 | 1.00 | 1.00 |
| SCN-07 | 4 | INC-0058 | 4 | 1.00 | 1.00 |

- **Volume:** 3,000 alerts become **68 incidents**, 44.1 alerts per incident. The largest has 236
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
| Purity, every scenario except SCN-05 | ≥ 0.9 | 1.0 |
| Purity, SCN-05 | ≥ 0.05 | 0.09 |
| Incident count | 50–75 | 68 |
| Largest incident | ≤ 10 % | 7.9 % |
| Incidents above 5 % | each a single recurring activity | 3, all single |
| Correlation time | < 2 s | ~0.03 s |

**Incident count.** The tuned setting reaches the requested 50–75 range on every tuning seed
(60–67) and on seed 42 (68), so the test uses 50–75 directly. The fallback rule (tuned result
± 10 %) was not needed. We did not push further toward 60: longer windows or looser hubs lower the
count, but they start merging unrelated people.

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
