# nullpunkt

AI-assisted SOC alert triage. Nullpunkt:

- correlates about 3,000 alerts into ranked incidents
- scores them by asset-aware risk and maps them to MITRE ATT&CK
- writes shift briefs with Microsoft Phi for an analyst to approve

Built by Team Nullpunkt for Microsoft Innovate 2026.

## The problem

**Problem 25: "3,000 Alerts, One Analyst."** A single analyst on shift faces thousands of
alerts. Most are noise, and the tools rank them by the severity the detection rule assigned. That
ordering is misleading: a HIGH alert on an intern's laptop floats to the top, while a quiet chain
of LOW and MEDIUM alerts on the finance database, which is the real attack, sits at the bottom.

Nullpunkt:

1. **Correlates** related alerts into incidents, so the analyst reviews about 60 stories instead of
   3,000 lines.
2. **Ranks** incidents 0–100 by risk × asset criticality, with every score broken into its
   components so it can be explained.
3. **Maps** each incident to MITRE ATT&CK techniques and tactics.
4. **Briefs** the analyst with a short summary and next step written by Phi (running locally via
   Ollama), with a template fallback. The analyst approves, edits, dismisses or escalates it.
5. **Measures** mean time to triage (MTTT) before and after.

## Architecture

```
alerts.jsonl ─┐
assets.csv  ──┴─► ingest ─► correlate ─► map ATT&CK ─► rank ─► brief ─► SQLite ─► Streamlit review
                                                                                     │
labels.csv ───────────────────────────► evaluation (offline) ◄──────── decisions ◄───┘
```

- **Stack:** Python, pandas, networkx, Streamlit, SQLite, Microsoft Phi via Ollama.
- **Deployment target:** Azure (details in Phase 8).
- **Package:** each stage is a subpackage of `src/nullpunkt/`.
- **Data contract:** every package shares the Pydantic models in `core/schema.py`.
- **Ground truth:** labels are kept in a separate file that only the evaluation package may read,
  so the pipeline can never see the answers.

More detail:

- [docs/architecture.md](docs/architecture.md): pipeline stages, owners and how an incident is
  enriched
- [docs/data_contract.md](docs/data_contract.md): file formats, models, fields and ID conventions

## Setup

Requires Python 3.11 or newer. Ollama is needed only for the briefing stage.

```bash
git clone https://github.com/Arman0212/nullpunkt.git
cd nullpunkt
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
cp .env.example .env

# for briefs
ollama pull phi4-mini
```

`.env` settings:

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_MODEL` | `phi4-mini` | Phi model used for briefs |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server |
| `DB_PATH` | `data/generated/nullpunkt.db` | SQLite database |

## Commands

```bash
pytest               # run all tests
ruff check .         # lint
ruff format .        # format

# generate a synthetic 3,000-alert shift (deterministic from the seed)
python -m nullpunkt.generator --config configs/generator.yaml --seed 42 --out data/generated/batch-001
```

The generated shift has 80 hosts and 7 injected intrusions hidden in clustered noise. See
[docs/scenarios.md](docs/scenarios.md).

```bash
# correlate the shift into incidents (reads only alerts.jsonl and assets.csv)
python -m nullpunkt.correlation --batch data/generated/batch-001
```

On the seed-42 demo shift, 3,000 alerts become 65 incidents and every injected intrusion lands
whole in a single incident. See [docs/correlation_tuning.md](docs/correlation_tuning.md).

```bash
# the full pipeline: correlate, map to ATT&CK, score and rank (top 10 with P1-P4 tiers)
python -m nullpunkt.pipeline --batch data/generated/batch-001

# ... plus shift briefs for the top 10 from Phi via Ollama (template fallback without it)
python -m nullpunkt.pipeline --batch data/generated/batch-001 --briefs
```

To triage a shift in the analyst app:

```bash
nullpunkt-prepare-shift --batch data/generated/batch-001   # run everything once, store in SQLite
streamlit run app/streamlit_app.py                         # queue, incident pages, handover
```

See [docs/analyst_app.md](docs/analyst_app.md).

The before/after study compares the app with a flat alert list in time-boxed sessions. After the
sessions, one command scores them against the labels and writes `docs/mttt_study.md`. See
[docs/study_protocol.md](docs/study_protocol.md).

| Seed-42 scenario rank | Our score | Severity-only | Alert count |
|---|---|---|---|
| SCN-01 phishing → finance DB (low/medium alerts only) | **1** | 51 | 52 |
| Mean over all 7 scenarios | **4.0** | 39.9 | 44.9 |
| Scenarios in the top 10 | **7** | 0 | 0 |

See [docs/scoring_evaluation.md](docs/scoring_evaluation.md).

Load the sample batch:

```python
from nullpunkt.ingestion.loader import load_alerts, load_assets

alerts = load_alerts("data/sample/alerts.jsonl")  # 14 alerts, sorted by time
assets = load_assets("data/sample/assets.csv")  # 9 hosts keyed by name
```

## Project status

Phases 0–7 are done: foundation, synthetic data generator, correlation, ATT&CK mapping, risk
scoring, AI shift briefs, the analyst app with decision storage, and the before/after study
tooling. The study sessions themselves come next. The later phases are listed in the project
plan.

| Component | Status |
|---|---|
| Data contract, loaders, sample batch, tests, CI, docs | done |
| Synthetic data generator (80 hosts, 3,000 alerts, 7 scenarios) | done |
| Correlation (3,000 alerts → 65 incidents, all scenarios whole) | done |
| ATT&CK mapping (Enterprise ATT&CK v19.2) | done |
| Risk scoring and P1–P4 tiers (all 7 scenarios in the top 10) | done |
| AI shift briefs (Phi via Ollama, validated, template fallback) | done |
| SQLite storage, prepare-shift CLI, Streamlit analyst app, handover report | done |
| Evaluation: correlation and ranking metrics, baselines | done |
| Evaluation: MTTT before vs after (study tooling, protocol) | done |
| Evaluation: MTTT study sessions and results | not started |
| Azure deployment (Phase 8) | not started |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short:

- name branches `feat/<area>` and use Conventional Commits
- PRs need green CI
- changes to `schema.py` need team approval

## License

MIT; see [LICENSE](LICENSE).
