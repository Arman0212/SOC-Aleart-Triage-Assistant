# CLAUDE.md

Context for AI coding sessions in this repo. Read this first.

## Project

Nullpunkt is a SOC alert-triage tool built for Microsoft Innovate 2026, Problem 25
("3,000 Alerts, One Analyst"). It:

- ingests about 3,000 synthetic security alerts and correlates them into about 60 incidents
- scores each incident 0–100 by risk × asset criticality and maps it to MITRE ATT&CK
- writes a shift brief for each incident with Microsoft Phi (via Ollama) for an analyst to approve
- measures mean time to triage (MTTT) before and after

**Stack (fixed, do not add to it without asking):** Python, pandas, networkx, Streamlit, SQLite,
Phi via Ollama, Azure (deployment target; details in Phase 8). Runtime and dev dependencies are
listed in `pyproject.toml`; use only those.

**Status:** Phase 0 (foundation) is done: the data contract, loaders, sample batch, tests, CI and
docs. The pipeline packages are still empty.

## Architecture

The package uses a src layout (`src/nullpunkt/`). See `docs/architecture.md` and
`docs/data_contract.md`.

```
ingest → correlate → map (ATT&CK) → rank → brief → analyst review
ingestion  correlation  attack      scoring  briefing  Streamlit + storage
```

- `core/schema.py`: the data contract (Pydantic v2). Every package imports its types from here.
  Input: `Alert`, `Asset`, `GroundTruth`. Output: `Incident`, `Technique`, `ScoreBreakdown`,
  `Brief`, `Decision`.
- `generator`: writes synthetic batches to `data/generated/` (git-ignored).
- `ingestion/loader.py`: `load_alerts`, `load_assets`, `write_alerts`, `read_csv_models`, and
  `DataFileError`, whose messages start with `path:line`.
- `evaluation/ground_truth.py`: `load_ground_truth`, the only place labels are read.
- `correlation`, `attack`, `scoring`, `briefing`, `storage`: pipeline stages, not yet implemented.
- An `Incident` is enriched step by step: `techniques`, then `score`, then `brief`, then `status`.

The batch format is three files:

- `alerts.jsonl`: one `Alert` per line
- `assets.csv`: `Asset` rows
- `labels.csv`: `GroundTruth` rows, for evaluation only

`data/sample/` is a small committed fixture with scenario SCN-01. Its attack uses only low/medium
alerts but reaches the criticality-5 FINDB01, while the noise includes high-severity false
positives on criticality-1 laptops.

## Hard rules

1. **Never run a git command that changes state.** That means no `add`, `commit`, `push`,
   `rebase`, `reset`, `stash`, `checkout` (or `merge`, `pull`, `restore`, `switch`, `tag`, etc.).
   Read-only git (`status`, `diff`, `log`, `show`) is fine. Write code, run the checks, leave the
   changes uncommitted, and propose a commit plan; the user commits.
2. **Do not modify `src/nullpunkt/core/schema.py`.** If it seems to need a change, stop and explain
   why to the user. Schema changes need team approval.
3. **Ground truth never leaves `nullpunkt.evaluation`.** Pipeline code sees only `Alert` and
   `Asset`, and never imports `GroundTruth` or `nullpunkt.evaluation` or reads `labels.csv`.
   `tests/unit/test_ground_truth.py` enforces this.
4. **All timestamps are timezone-aware UTC.** Write them as `...Z`, and use
   `datetime.now(UTC)`, never `datetime.now()` or `utcnow()`. The schema rejects naive datetimes
   and converts aware ones to UTC.
5. **Support Python >= 3.11.** Local development uses 3.14; CI runs 3.11 and 3.12.
6. **Use only the dependencies already in `pyproject.toml`.**

## Commands

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"      # install (editable) with dev tools
pre-commit install           # optional: run ruff on every commit

pytest                       # all tests
pytest tests/unit            # unit tests only
ruff check .                 # lint
ruff format .                # format (CI runs `ruff format --check .`)
```

Configuration comes from `.env` (copy `.env.example`): `OLLAMA_MODEL`, `OLLAMA_HOST`, `DB_PATH`.

## Conventions

- Ruff settings: line length 100, rules E, F, I, B, UP, target py311.
- Conventional Commits (`feat(scoring): ...`, `test(core): ...`, `docs: ...`). Branches are named
  `feat/<area>`. See `CONTRIBUTING.md`.
- Tests live in `tests/unit` and `tests/integration`. The `sample_dir` fixture in
  `tests/conftest.py` points at `data/sample/`.
- Keep `docs/data_contract.md` in sync with `schema.py`.
