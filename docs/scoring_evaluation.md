# Scoring and evaluation

How incidents are mapped to MITRE ATT&CK, how their risk score is computed, how the scoring
parameters were tuned, and how the ranking compares with what a SIEM queue would show. The
settings live under `scoring:` in [`configs/pipeline.yaml`](../configs/pipeline.yaml).

```bash
python -m nullpunkt.pipeline --batch data/generated/batch-001   # top 10 with scores and tiers
python -m nullpunkt.evaluation.sweep_scoring                     # re-tune (~5 s)
```

## Headline: seed 42 (held out)

The same 65 incidents, ranked three ways. Each cell is the rank of the scenario's incident; lower
is better. This is the demo's key chart.

| Scenario | Our score | Severity-only | Alert count |
|---|---|---|---|
| SCN-01 phishing → finance DB | **1** | 51 | 52 |
| SCN-02 VPN brute force | **6** | 49 | 42 |
| SCN-03 web exploit | **5** | 32 | 47 |
| SCN-04 credential theft → DC | **3** | 33 | 49 |
| SCN-05 staging and exfiltration | **4** | 41 | 17 |
| SCN-06 ransomware precursor | **2** | 37 | 54 |
| SCN-07 infostealer on a laptop | **7** | 36 | 53 |
| **Mean scenario rank** | **4.0** | 39.9 | 44.9 |
| **Scenarios in top 5** | **5** | 0 | 0 |
| **Scenarios in top 10** | **7** | 0 | 0 |
| **Scenarios in top 15** | **7** | 0 | 0 |
| **Precision@10** | **0.7** | 0.0 | 0.0 |

**The baselines:**

- **Severity-only** sorts by the highest alert severity in the incident, then by alert count. It's
  what a SIEM queue does.
- **Alert count** sorts by the number of alerts.

**What the table shows:**

- **Severity-only buries everything real.** Every scenario ranks 32nd or lower, behind incidents
  full of high and critical noise on low-value hosts.
- **SCN-01 goes from 51st to 1st.** It is entirely low and medium severity, but it ends on the
  criticality-5 finance database.
- **Precision@10 of 0.7 is the ceiling here.** There are only 7 scenarios, so at most 7 of the top
  10 can contain one.

## ATT&CK mapping

**Reference data.** The reference data is **Enterprise ATT&CK v19.2**, from MITRE's official
`mitre-attack/attack-stix-data` repository:

- **Pinned source:** `enterprise-attack-19.2.json`.
- **Build script:** `scripts/build_attack_subset.py` extracts the pieces we need into
  `src/nullpunkt/attack/data/attack_subset.json` (6 KB, shipped as package data). The pipeline never
  touches the network.
- **Contents:** the tactics in kill-chain order, every technique the rule catalog uses, and their
  parents.

**v19.2 has 15 tactics, not the 14 of v17 and earlier.** Defense Evasion was replaced by **Stealth**
and **Defense Impairment**:

reconnaissance → resource development → initial access → execution → persistence → privilege
escalation → stealth → defense impairment → credential access → discovery → lateral movement →
collection → command and control → exfiltration → impact

**Tactic per rule.** A detection rule detects its technique in one tactical context, so each rule
names its tactic, and a test checks it is one of the technique's official tactics. The one real
choice is T1078 Valid Accounts, which is official under initial access, persistence, privilege
escalation and stealth:

- "Successful login after failures" and "Impossible travel login" → **initial access**
- "Login from new source host" → **stealth** (a valid account used to blend in)
- "Privileged login from new host" (T1078.002) → **privilege escalation**

The full table is in `core/detection_rules.py`.

**Mapping.** An incident's techniques come from its alerts' rules:

- in order of first appearance
- deduplicated by `(technique, tactic)`, so T1078 for initial access and for stealth stay two entries
- `confirmed=True`

Rules missing from the catalog produce no technique and are reported in `MappingResult.unmapped`.
Phase 5 may suggest a technique for them with `confirmed=False`. On generated data every rule is in
the catalog.

## The risk score

> **risk = 100 × (S × C / 20) × (M / M_max) × N**

In one sentence: *the riskiest single alert-on-asset, scaled by how far along the kill chain the
incident got and how unusual its evidence is.* Each factor is at most 1, so the score is in
(0, 100] by construction, with no clipping.

| Factor | Meaning | Range |
|---|---|---|
| **S × C / 20** | Severity weight (1–4) × criticality (1–5) of the **same alert**: the peak alert-on-asset in the evidence. Ties go to the higher criticality, then the earlier alert. | 0.05–1 |
| **M / M_max** | Stage multiplier `M = 1 + stage_step × (T − 1)`, where T is the number of distinct tactics in the evidence, capped at `tactic_cap`. | (0, 1] |
| **N** | Noise penalty: the informativeness of the incident's most informative evidence rule, × `routine_penalty` if every alert is routine. | (0, 1] |

**Volume cannot raise the score.** The score uses one peak alert, *distinct* tactics and a rarity
factor. Adding alerts can only:

- make a pair routine, which removes it from the evidence, or
- make its rule more common, which lowers N.

`test_duplicating_noise_alerts_never_raises_the_score` checks this.

**Priority tier.** Each incident gets a tier, P1–P4, from **fixed score thresholds**, not from its
rank. A quiet shift therefore has no P1.

| Tier | Minimum score |
|---|---|
| P1 | 23.0 |
| P2 | 6.2 |
| P3 | 3.8 |
| P4 | below 3.8 |

The tier lives in the pipeline output (`RankedIncident.tier`), not in the data contract.

### Asset at risk

Each rule declares whether its alerts threaten the alert's **host** or its **source**.

**A "source" alert resolves to:**

1. the source asset, when the source IP belongs to one; otherwise
2. the endpoint the account owns (inventory `owner`); otherwise
3. the alert's host.

**Relay rule.** Infrastructure doing its normal job for someone else never lends its criticality:

- the DC authenticating a login
- the proxy carrying a web request
- the mail gateway filtering mail
- the VPN concentrator

If a source-side alert on a relay (asset types `relay_asset_types`: domain controller, proxy, mail
server, VPN gateway) can't be resolved, it gets criticality 1.

**Audit of every rule's host field** (seeds 42, 101 and 102):

| Rule | Where the alerts sit | Asset at risk |
|---|---|---|
| Failed login, Successful login after failures, Account lockout | 100 % DC01 or VPN01 (authenticator) | source → the user's endpoint |
| Impossible travel login | 100 % VPN01 | source → the user's laptop |
| Kerberos RC4 service ticket request, LDAP enumeration query | 100 % DC01 | source |
| Connection to newly registered domain, Large outbound transfer | 100 % PROXY01 | source → the client, or FS02 for SCN-05 |
| **Spam campaign blocked** | 100 % MAIL01, no user, external sender | **source** (changed from host). Unresolvable, so criticality 1 instead of MAIL01's 4. |
| **Suspicious attachment delivered** | 0 % MAIL01: the recipient's endpoint | **source** (changed from host). Resolves to the recipient's endpoint through account ownership, and stays correct if a feed puts the alert on the gateway. |
| Internal network scan | the scanned target | source → the scanning host |
| Directory replication request | 100 % DC01 | **host**, kept. A DCSync request attacks the DC's own secrets. The benign DC02 replication is routine, so the noise penalty handles it. |
| Privileged login from new host, Exploit attempt signature, Inbound connection blocked, Port scan detected | partly MAIL01 or VPN01 | **host**, kept. Here the gateway is itself the target being logged into, exploited or probed, not relaying. |
| All other rules | endpoints and servers | host |

The only rules changed from the plan are **Spam campaign blocked** and **Suspicious attachment
delivered**.

### Noise penalty (data-driven, no labels)

- **Rule informativeness:** `(1 + ln(N_alerts / n_rule)) / (1 + ln N_alerts)`. A rule seen once
  scores 1. A rule in every alert scores 1 / (1 + ln N), never 0. The incident uses its most
  informative evidence rule, so one rare, telling alert isn't drowned out by a noisy peak rule
  (SCN-07's peak is the very common "Connection to newly registered domain").
- **Routine activity:** a `(rule, actor)` pair is routine if it fires in at least
  `routine_min_hours` different hours of the batch. The actor is the user, else the source, else
  the host. Examples: a user's typo bursts, `svc-sccm`'s SMB sessions, the vulnerability scanner,
  nightly backups.
  - Routine alerts are left out of the evidence.
  - An incident made **only** of routine alerts is scored on all of them × `routine_penalty`.
  - A brute-force burst (8 failures in 2 minutes, all within one hour) is not routine.

### Worked examples (seed 42, tuned settings)

**SCN-01, INC-0055 (5 alerts, rank 1, P1):**
- All 5 alerts are evidence.
- Peak: *SMB admin share access* on **FINDB01**, medium (2) × criticality 5, giving 10/20 = 0.50.
- 5 tactics: initial access → execution → stealth → lateral movement → collection. With a cap of 4,
  M = 1 + 1.0 × 3 = 4 = M_max, so M / M_max = 1.
- Rarest evidence rule: *Office application spawned PowerShell*, N = 0.662.
- Risk = 100 × 0.50 × 1 × 0.662 = **33.1**.

**SCN-05, INC-0013 (64 alerts: 46 failed logins, 10 successes, 2 lockouts and the 6 SCN-05 alerts; rank 4, P1):**
- 56 of the typo alerts are routine (the user's typos fire in many hours), leaving 8 evidence
  alerts.
- Peak: *Mass file access on share* on **FS02**, medium (2) × criticality 3, giving 0.30.
- 4 tactics: stealth → credential access → collection → exfiltration, so M / M_max = 1.
- N = 0.784. It comes from a stray account lockout that isn't routine.
- Risk = 100 × 0.30 × 1 × 0.784 = **23.5**.
- The score is driven by the file server and the exfiltration. Adding more typos can only make them
  more routine.

**SCN-07, INC-0057 (4 alerts on a criticality-1 laptop, rank 7, P2):**
- Peak: *Connection to newly registered domain*, high (3) × criticality 1 (the laptop), giving 0.15.
- 4 tactics, so M / M_max = 1.
- N = 0.707 (*Unsigned executable launched from Downloads*).
- Risk = **10.6**. That is low in absolute terms but still P2, and 7th of 65: a low-value host is
  not buried.

## Tuning

**Setup:**

- **Data:** seeds **101–105** for tuning. Seed 42 is held out.
- **Incidents:** correlated with the tuned correlation defaults.
- **Grid:** 256 settings.

| Parameter | Values | Chosen |
|---|---|---|
| `stage_step` | 0.5, 0.75, 1.0, 1.5 | **1.0** |
| `tactic_cap` | 3, 4, 5, 6 | **4** |
| `routine_min_hours` | 2, 3, 4, 5 | **3** |
| `routine_penalty` | 0.05, 0.1, 0.25, 0.5 | **0.1** |

**Targets, required on every tuning seed:**

- SCN-01 in the top 5
- at least 6 of 7 scenarios in the top 10, and all 7 in the top 15
- a lower mean scenario rank than both baselines

**Selection order** (robustness first, as for correlation):

1. Meets the targets on every tuning seed.
2. Every neighbouring grid point (one parameter moved one step) also meets them.
3. Tiers are separable: every scenario scores above every routine-only noise incident on every
   seed.
4. The most neighbours meeting the targets.
5. The lowest worst-case mean scenario rank.
6. The widest tier gap, then grid order.

**Top of the sweep:**

| # | stage step | tactic cap | routine hours | routine penalty | targets | neighbours OK | worst mean rank | lowest scenario | highest routine |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1.0 | 4 | 3 | 0.1 | yes | 8/8 | 4.14 | 10.2 | 3.8 |
| 2 | 1.0 | 4 | 4 | 0.1 | yes | 8/8 | 4.14 | 10.2 | 3.8 |
| 3 | 1.0 | 5 | 3 | 0.1 | yes | 8/8 | 4.14 | 8.2 | 3.8 |
| 4 | 1.0 | 5 | 4 | 0.1 | yes | 8/8 | 4.14 | 8.2 | 3.8 |
| 5 | 1.0 | 4 | 3 | 0.25 | yes | 8/8 | 4.14 | 10.2 | 9.4 |
| 6 | 1.0 | 4 | 4 | 0.25 | yes | 8/8 | 4.14 | 10.2 | 9.4 |
| 7 | 0.75 | 4 | 3 | 0.1 | yes | 8/8 | 4.29 | 10.2 | 3.8 |
| 8 | 0.75 | 4 | 4 | 0.1 | yes | 8/8 | 4.29 | 10.2 | 3.8 |

**Changing one parameter from the chosen setting:**

| Variant | Targets on 101–105 | Worst scenario rank | Worst mean rank | Lowest scenario / highest routine score | Seed 42 mean rank | Seed 42 in top 10 | Seed 42 worst |
|---|---|---|---|---|---|---|---|
| **chosen** | yes | 8 | 4.14 | 10.2 / 3.8 | 4.0 | 7 | 7 |
| stage_step 0.75 | yes | 9 | 4.29 | 10.2 / 3.8 | 4.0 | 7 | 7 |
| stage_step 1.5 | yes | 8 | 4.14 | 10.2 / 3.8 | 4.0 | 7 | 7 |
| tactic_cap 3 | yes | 9 | 4.29 | 10.2 / 4.1 | 4.0 | 7 | 7 |
| tactic_cap 5 | yes | 8 | 4.14 | 8.2 / 3.8 | 4.0 | 7 | 7 |
| routine_min_hours 2 | yes | 8 | 4.14 | 10.2 / 4.2 | 4.0 | 7 | 7 |
| routine_min_hours 4 | yes | 8 | 4.14 | 10.2 / 3.8 | 4.0 | 7 | 7 |
| routine_penalty 0.05 | yes | 8 | 4.14 | 10.2 / 1.9 | 4.0 | 7 | 7 |
| routine_penalty 0.25 | yes | 8 | 4.14 | 10.2 / 9.4 | 4.0 | 7 | 7 |
| *further:* tactic_cap 6 | yes | 8 | 4.14 | 6.8 / 3.1 | 4.0 | 7 | 7 |
| *further:* routine_min_hours 5 | yes | 10 | 4.43 | 10.2 / 3.8 | 4.3 | 7 | 9 |
| *further:* routine_penalty 0.5 | yes | 11 | 5.14 | 10.2 / 18.9 | 4.6 | 6 | 11 |

**Reasoning:**

- **The ranking is robust.** Every single-step neighbour keeps all targets on every tuning seed,
  and seed 42 is unchanged.
- **The tiers are what the choice protects.** At `routine_penalty` 0.25 the ranking is identical,
  but routine noise reaches 9.4, just under the lowest scenario (10.2). The tiers would then need
  thresholds squeezed into that sliver. At 0.1 the gap is 10.2 against 3.8.
- **Grid edge effect.** An earlier run of the grid, without 0.05, made 0.1 an edge value with fewer
  neighbours, so it lost on neighbour count alone. Adding 0.05 made it interior. It is the same
  edge effect we fixed for correlation.
- **`tactic_cap` 4** keeps SCN-07's four tactics at full stage weight. A higher cap spreads the
  stage factor thinner, which lowers the lowest scenario score (8.2 at cap 5, 6.8 at cap 6).

### Tier thresholds

The thresholds are derived from the chosen setting's tuning scores, then fixed:

- **P2 = 6.2:** the geometric midpoint between the highest routine-only noise score (3.8) and the
  lowest scenario score (10.2) on seeds 101–105. Every tuning scenario is therefore P1/P2, and
  every routine-only incident is P3/P4.
- **P3 = 3.8:** just above the highest routine-only noise score, so routine incidents are P4.
  Non-routine noise below P2 is P3.
- **P1 = 23.0:** the median scenario score on the tuning seeds, so roughly the upper half of real
  intrusions are P1.

**Tier distribution:**

| Seed | P1 | P2 | P3 | P4 | Scenario tiers |
|---|---|---|---|---|---|
| 101 | 3 | 6 | 7 | 49 | P1 P1 P1 P2 P2 P2 P2 |
| 102 | 4 | 6 | 5 | 47 | P1 P1 P1 P1 P2 P2 P2 |
| 103 | 5 | 4 | 4 | 52 | P1 P1 P1 P1 P1 P2 P2 |
| 104 | 3 | 6 | 5 | 45 | P1 P1 P1 P2 P2 P2 P2 |
| 105 | 5 | 7 | 4 | 46 | P1 P1 P1 P1 P1 P2 P2 |
| **42 (held out)** | **4** | **7** | **9** | **45** | P1 P1 P1 P1 P2 P2 P2 |

**Seed 42 in detail:**

- **P1 (4):** SCN-01, SCN-06, SCN-04 and SCN-05. Every P1 is a real intrusion.
- **P2 (7):** SCN-03, SCN-02 and SCN-07, plus 4 noise incidents: one user bundle that includes a
  phishing attachment, and three incidents with a critical malware-hash detection on a laptop.
- **P3 and P4:** everything routine is P4. The highest routine-only incident scores 3.6.

The thresholds belong to the chosen parameters. Change a scoring parameter and the sweep must
derive them again: at `routine_penalty` 0.25, for example, routine noise would reach P2.

## Acceptance thresholds (integration test)

`tests/integration/test_scoring_batch.py`, on seed 42:

| Check | Target | Seed 42 |
|---|---|---|
| SCN-01 rank, our score | ≤ 5 | 1 |
| SCN-01 rank, severity-only | > 15 | 51 |
| Scenarios in the top 10 / top 15 | ≥ 6 / 7 | 7 / 7 |
| Mean scenario rank vs both baselines | lower | 4.0 vs 39.9 and 44.9 |
| Scenario tiers | P1 or P2 | 4 × P1, 3 × P2 |
| Routine-only noise tiers | P3 or P4 | all P4 |
| Full pipeline (ingest → rank) | < 3 s | about 0.06 s |

## Known limitations

- **"Low and slow" looks routine.** An attacker who repeats the same action from the same account
  across several hours, for example one file-share read per hour, turns that `(rule, actor)` pair
  routine. The alerts drop out of the evidence and, if nothing else remains, the incident is scored
  × 0.1. Our scenarios are all bursts of minutes to an hour or two, so this is not exercised.
  Future work: judge routine against a baseline from *previous* shifts, so a pattern that is new
  this shift is never routine however often it repeats.
- **Scores are low in absolute terms.** A 100 needs a critical alert on a criticality-5 asset, four
  or more tactics, and a rule seen once in the batch. Real incidents here score 10–33. Rank and
  tier are what analysts act on; the raw score is kept for transparency.
- **N can come from a stray alert.** In SCN-05 the most informative evidence rule is a single
  non-routine account lockout from the user's typo noise, not one of the exfiltration alerts. The
  peak asset and the tactics still come from the exfiltration.
- **Hub routines** (see [correlation_tuning.md](correlation_tuning.md#known-limitation-hub-routines-absorb-a-compromised-hub-account))
  also shape scoring: a compromised shared admin account's activity lands in a routine incident and
  is penalised.
