# Synthetic shift and injected scenarios

`nullpunkt.generator` builds one SOC shift: about 80 hosts, 3,000 alerts, 7 injected intrusion
scenarios, and noise that fills the rest. The same seed and config always give byte-identical
files.

```bash
python -m nullpunkt.generator --config configs/generator.yaml --seed 42 --out data/generated/batch-001
# or, once installed:
nullpunkt-generate --out data/generated/batch-001
```

The output directory holds four files:

| File | Contents | Who may read it |
|---|---|---|
| `alerts.jsonl` | the alerts | everyone |
| `assets.csv` | the inventory | everyone |
| `labels.csv` | the answers | evaluation only |
| `manifest.json` | seed, config, counts and a scenario summary | evaluation only |

The manifest names which hosts each scenario touched, so it is truth just like `labels.csv`.

Definitions live in [`scenarios.py`](../src/nullpunkt/generator/scenarios.py) (the steps) and
[`noise.py`](../src/nullpunkt/generator/noise.py) (the background). The rules both use are in
[`core/detection_rules.py`](../src/nullpunkt/core/detection_rules.py).

## The shift

| Setting | Default |
|---|---|
| Company time zone | `Asia/Kolkata` |
| Shift | 09:00–21:00 IST (03:30–15:30 UTC) |
| Business hours | 09:00–18:00 IST |
| Hosts | 80: 16 servers and 64 endpoints |
| Alerts | 3,000 |

All timestamps on disk are UTC. The generator converts from company local time.

**Inventory:**

| Host | Type | Criticality |
|---|---|---|
| DC01, DC02 | `domain_controller` | 5 |
| FINDB01 | `database` | 5 |
| HRDB01 | `database` | 4 |
| FS01 | `file_server` | 4 |
| FS02 | `file_server` | 3 |
| MAIL01 | `mail_server` | 4 |
| VPN01 | `vpn_gateway` | 4 |
| JUMP01 | `jump_host` | 4 |
| WEB01, WEB02 | `web_server` | 3 |
| PROXY01 | `proxy` | 3 |
| SCCM01 | `software_distribution` | 3 |
| BACKUP01 | `backup_server` | 3 |
| WSUS01 | `patch_server` | 2 |
| VULNSCAN01 | `vuln_scanner` | 2 |
| Finance and executive workstations (`WS-FIN-*`, `WS-EXE-*`) | `workstation` | 3 |
| Other workstations (`WS-*`) | `workstation` | 2 |
| Laptops (`LT-*`) | `laptop` | 1 |

- Each named user has one primary endpoint.
- Service accounts: `svc-backup`, `svc-sql`, `svc-deploy`, `svc-legacy` and `svc-sccm`.
- Admin accounts: the shared `adm-it`, plus personal `adm-<user>` accounts for IT staff.

**Hub entities** legitimately appear in many unrelated alerts. Correlation (Phase 2) must not
merge incidents through them:

- **DC01:** every domain authentication alert
- **PROXY01:** every proxy alert; the client is identified by `src_ip` and `user`
- **`adm-it`:** the shared admin account
- **VULNSCAN01:** its address appears in internal scan alerts all shift
- **Commercial VPN exit IPs:** shared by the impossible-travel users

## Rules are shared between noise and attacks

- **Rules fire both ways.** Every rule a scenario uses also fires as noise; a test enforces this.
- **One technique per rule.** Each rule has exactly one ATT&CK technique, and a true positive's
  `true_technique` is always its rule's technique.
- **Messages look the same.** Messages come only from the rule's templates in
  [`messages.py`](../src/nullpunkt/generator/messages.py). The renderer never sees scenario
  information, so noise and attack alerts from the same rule use the same templates and
  vocabulary.
- **No giveaway words.** Messages never contain scenario IDs or words like "attack",
  "malicious" or "simulated".

## Scenarios

Each scenario starts at a random time in the shift. Its steps follow each other with random
delays. The scenario's alerts share at least one host, user or IP, and fall within the
scenario's maximum window.

### SCN-01 · Phishing to the finance database (the demo scenario)

| Step | Rule | Host | Severity | Technique |
|---|---|---|---|---|
| 1 | Suspicious attachment delivered | victim workstation (finance) | medium | T1566.001 |
| 2 | Office application spawned PowerShell | victim workstation | medium | T1059.001 |
| 3 | Login from new source host | FINDB01 | low | T1078 |
| 4 | SMB admin share access | FINDB01 | medium | T1021.002 |
| 5 | Bulk read of database files | FINDB01 | medium | T1005 |

- **Linked by:** the finance user, and the workstation IP as the source on FINDB01.
- **Window:** at most 63 minutes.
- **Why it exists:** it is the core claim of the project. Every alert is LOW or MEDIUM, but the
  chain ends on a criticality-5 database. Severity-only triage buries it under hundreds of HIGH
  false positives; severity × criticality should put it near the top.

### SCN-02 · VPN brute force and discovery

| Step | Rule | Host | Severity | Technique |
|---|---|---|---|---|
| 1 | Failed login ×6–12 | VPN01 | low | T1110.001 |
| 2 | Successful login after failures | VPN01 | medium | T1078 |
| 3 | LDAP enumeration query | DC01 | low | T1087.002 |
| 4 | Internal network scan ×3–6 | FS01 | medium | T1046 |

- **Linked by:** a laptop user and the attacker's external IP (steps 1–2). The attacker's
  VPN-assigned IP (steps 3–4) links the user to the scan.
- **Why it exists:**
  - Failed logins are the most common noise rule, from password typos. The same rule is the
    start of a real brute force here.
  - The discovery step only links through the VPN address, not the user.

### SCN-03 · Web exploit, web shell and discovery

| Step | Rule | Host | Severity | Technique |
|---|---|---|---|---|
| 1 | Exploit attempt signature ×1–3 | WEB02 | high | T1190 |
| 2 | Web server process spawned shell | WEB02 | high | T1505.003 |
| 3 | Account enumeration via net.exe | WEB02 | low | T1087.002 |
| 4 | Internal network scan ×2–5 | HRDB01 | medium | T1046 |

- **Linked by:** WEB02 and its IP.
- **Why it exists:** exploit signatures fire all shift against patched servers and from the
  vulnerability scanner. Only the follow-up activity on the same host distinguishes the one
  that worked.

### SCN-04 · Credential theft reaching the domain controller

| Step | Rule | Host | Severity | Technique |
|---|---|---|---|---|
| 1 | LSASS memory access | victim workstation | high | T1003.001 |
| 2 | Kerberos RC4 service ticket request ×4–8 | DC01 | low | T1558.003 |
| 3 | Privileged login from new host (`svc-sql`) | DC01 | medium | T1078.002 |
| 4 | Directory replication request (`svc-sql`) | DC01 | high | T1003.006 |

- **Linked by:** the victim user, then the workstation IP once the attacker switches to the
  cracked `svc-sql` account.
- **Why it exists:**
  - The chain runs through DC01, the busiest hub in the batch.
  - Every rule has a benign twin in the noise: AV scanning LSASS, a legacy app requesting RC4
    tickets, and DC02 replicating from DC01.

### SCN-05 · Data staging and exfiltration from a file server

| Step | Rule | Host | Severity | Technique |
|---|---|---|---|---|
| 1 | Login from new source host (from a VPN address) | FS02 | low | T1078 |
| 2 | Mass file access on share ×2–4 | FS02 | medium | T1039 |
| 3 | Large archive created | FS02 | low | T1560.001 |
| 4 | Large outbound transfer | PROXY01 | medium | T1567.002 |

- **Linked by:** the user, the VPN address and FS02's IP.
- **Why it exists:**
  - Nightly backups produce the same mass reads, archives and cloud uploads under
    `svc-backup`.
  - It is also the purity test (see below).

### SCN-06 · Ransomware precursor on a file server

| Step | Rule | Host | Severity | Technique |
|---|---|---|---|---|
| 1 | SMB admin share access | FS01 | medium | T1021.002 |
| 2 | Remote service creation | FS01 | medium | T1569.002 |
| 3 | Backup service stopped | FS01 | high | T1489 |
| 4 | Volume shadow copy deletion | FS01 | high | T1490 |

- **Linked by:** a compromised personal admin account (`adm-<it user>`) and that admin's
  workstation IP.
- **Window:** at most 23 minutes.
- **Why it exists:**
  - Approved admin tooling generates the same SMB and service-creation alerts all day.
  - Backup pruning deletes shadow copies on the same file servers.
  - The deciding signal is the sequence, fast, on one host.

### SCN-07 · Infostealer on a laptop

| Step | Rule | Host | Severity | Technique |
|---|---|---|---|---|
| 1 | Unsigned executable launched from Downloads | victim laptop (criticality 1) | low | T1204.002 |
| 2 | Browser credential store access | victim laptop | medium | T1555.003 |
| 3 | Connection to newly registered domain | PROXY01 | high | T1071.001 |
| 4 | Large outbound transfer | PROXY01 | medium | T1567.002 |

- **Linked by:** the user and the laptop's IP.
- **Why it exists:**
  - Asset-aware ranking must not bury low-value hosts entirely. A real compromise of a
    criticality-1 laptop still deserves a brief.
  - Its last step uses the same exfiltration rule as SCN-05.

## Purity test: SCN-05 shares its user with the noise

Scenario victims are kept out of the noise:

- users, and the endpoints they own
- attacker and C2 IPs
- VPN addresses handed to an attacker
- compromised accounts

No noise cluster is keyed on a victim, and no noise alert mentions one.

There is **one deliberate exception**. The SCN-05 user is also one of the ten password-typo users,
so their name appears in harmless failed-login bursts on DC01 throughout the shift. A correlator
that merges on user alone will pull those typos into the exfiltration incident, and one that
drops the user as noise will lose the incident. Phase 2 has to get this right.

Two tests enforce this:

- `test_only_scn05_user_is_shared_with_noise_keys`: the only victim entity used as a noise key
  is the SCN-05 user.
- `test_noise_alerts_never_touch_other_victims`: no noise alert contains any other victim
  entity.

## Noise

Noise comes in episodes: short bursts of related alerts that share a cluster key. Categories
with business-hours weighting place about 90 % of their alerts between 09:00 and 18:00 IST.

| Category | Rules | Share | Cluster key | Clusters |
|---|---|---|---|---|
| Password typos | Failed login, Successful login after failures, Account lockout | 13 % | user (9 + the SCN-05 user) | 10 |
| Internet scans | Inbound connection blocked, Port scan detected | 15 % | scanner IP | 4 |
| Internal vulnerability scanner | Internal network scan, Exploit attempt signature | 8 % | VULNSCAN01 | 1 |
| Approved admin tools | SMB admin share access, Remote service creation, Privileged login from new host, Account enumeration via net.exe, LDAP enumeration query | 10 % | `adm-it`, `svc-sccm`, one personal admin account | 3 |
| PUA detections | Potentially unwanted application, Known malware hash detected | 5 % | laptop | 6 |
| Uncategorised domains | Connection to newly registered domain | 11 % | user | 8 |
| IDS hits on patched servers | Exploit attempt signature | 9 % | WEB01, MAIL01, VPN01 | 3 |
| Off-hours backups (evening weighted) | Bulk read of database files, Mass file access on share, Large archive created, Volume shadow copy deletion, Large outbound transfer | 8 % | backup job | 2 |
| Impossible travel via VPN exits | Impossible travel login | 6 % | user | 8 |
| Mail filtering | Spam campaign blocked, Suspicious attachment delivered | 7 % | sender IP | 3 |
| Benign lookalikes | one twin for each rarer scenario rule (RC4 tickets, web shell by a deploy script, DC replication, patch-time service stop, finance macro, AV scanning LSASS, password manager, downloaded installer, cloud sync) | 5 % | service or user | 9 |
| New-host logins | Login from new source host | 3 % | helpdesk or remote user | 4 |

- **Totals:** about 61 natural noise clusters plus 7 scenarios, so about **68 natural
  incidents**.
- **Exact alert count:** quotas use largest-remainder rounding, so the total is exactly
  `n_alerts`.
- **Every key gets an episode:** every cluster key gets at least one episode before any key gets
  a second. After that, keys are drawn with fixed per-key weights, because some users are
  noisier than others.

## Determinism

- **Seeded randomness:** one `random.Random(seed)` and one `Faker` seeded with the same value
  drive everything, in a fixed order.
- **No clock:** the generator never reads wall-clock time.
- **Sequential IDs:** alerts are sorted by time and then numbered.
- **Faker pin:** Faker's name lists change between major versions, so `pyproject.toml` pins
  Faker to 40.x and `manifest.json` records the exact version used.
- **Exact arithmetic:** quota rounding uses exact fractions rather than float `sum()`. Python 3.12
  changed float summation, and a one-ulp difference would otherwise shift a quota by one alert
  on Python 3.11.
- **Golden test:** `test_output_matches_golden_digest_on_every_python` pins the seed-42 SHA-256
  digests. CI runs it on Python 3.11 and 3.12, so cross-version drift fails the build. It skips
  when Faker is not the recorded version, and the digests are updated only when the generator
  is changed on purpose.
