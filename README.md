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

- **Stack:** Python, pandas, networkx, Streamlit, SQLite, Microsoft Phi via Ollama, Azure.
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
```

Load the sample batch:

```python
from nullpunkt.ingestion.loader import load_alerts, load_assets

alerts = load_alerts("data/sample/alerts.jsonl")  # 14 alerts, sorted by time
assets = load_assets("data/sample/assets.csv")  # 9 hosts keyed by name
```

## Project status

| Phase | Scope | Status |
|---|---|---|
| 0 · Foundation | data contract, loaders, sample batch, tests, CI, docs | done |
| 1 · Pipeline | generator, correlation, ATT&CK mapping, scoring | not started |
| 2 · Briefs and review | Phi briefs, SQLite storage, Streamlit app | not started |
| 3 · Evaluation | detection metrics, MTTT before vs after | not started |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short:

- name branches `feat/<area>` and use Conventional Commits
- PRs need green CI
- changes to `schema.py` need team approval

## License

MIT; see [LICENSE](LICENSE).
