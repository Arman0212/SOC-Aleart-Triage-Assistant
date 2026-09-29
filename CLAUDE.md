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

**Status:**

- Phase 0 (foundation) is done: the data contract, loaders, sample batch, tests, CI and docs.
- Phase 1 (synthetic data generator) is done.
- Phase 2 (correlation) is done.
- Phases 3–4 (ATT&CK mapping, risk scoring, the pipeline orchestrator) are done.
- Phase 5 (AI shift briefs with Phi via Ollama, template fallback) is done.
- Phase 6 (SQLite storage, prepare-shift CLI, Streamlit analyst app, handover report) is done.
- Next: Phase 7, the MTTT study.

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
- `core/detection_rules.py`: the rule catalog (rule name, source, severity, one ATT&CK
  technique). The pipeline may use it; it never says whether a given alert is real.
- `generator`: offline tooling that writes a deterministic synthetic shift to
  `data/generated/<batch>/`, which is git-ignored.
  - Modules: `config`, `inventory`, `scenarios` (data-driven steps), `noise` (clustered
    categories), `messages` (templates), `batch`, `cli`.
  - See `docs/scenarios.md`.
- `ingestion/loader.py`:
  - loaders: `load_alerts`, `load_assets`, `read_csv_models`
  - writers: `write_alerts`, `write_assets`, `write_csv_models`
  - `DataFileError`, whose messages start with `path:line`
- `evaluation/ground_truth.py`: `load_ground_truth`, the only place labels are read, and
  `write_ground_truth`, which the generator uses.
- `core/config.py`: `PipelineConfig` for `configs/pipeline.yaml`, with one section per stage.
  Only `correlation` exists so far.
- `correlation`:
  - `correlate()` / `run_correlation()` turn alerts into incidents, using role-based linking,
    data-driven hubs and recurrence.
  - `CorrelationResult` holds the link reasons and the hub stats.
  - See `docs/architecture.md#correlation` and `docs/correlation_tuning.md`.
- `evaluation/metrics.py`: scenario completeness and purity, and incident stats.
- `evaluation/sweep_correlation.py`: the tuning sweep. It tunes on seeds 101–105 and holds out
  seed 42.
- `core/detection_rules.py` also gives each rule its ATT&CK `tactic` and its `asset_at_risk`
  (`host` or `source`).
- `attack`:
  - `reference.py` loads the committed ATT&CK v19.2 subset (15 tactics), package data built by
    `scripts/build_attack_subset.py`.
  - `mapping.py`: `map_incident` / `map_incidents`.
- `scoring/engine.py`: `build_context`, `score_incident`, `asset_at_risk`, `rank` and
  `priority_tier` (P1–P4). See `docs/scoring_evaluation.md`.
- `pipeline.py`: `run(batch_dir)` / `process(alerts, assets)` run ingest → correlate → map →
  score → rank and return a `PipelineResult`.
- `evaluation`:
  - `metrics.py` also has `ranking_metrics`.
  - `baselines.py`: severity-only and alert-count orderings.
  - `sweep_scoring.py`: tuning on seeds 101–105, with seed 42 held out.
- `briefing`: `context.py` (the compact incident JSON), `llm.py` (`LLMClient` protocol,
  `OllamaClient`, `FakeClient` for tests), `prompts/brief_v1.md` (versioned prompt), `validation.py`
  (hallucination guard), `template.py` (fallback), `engine.py` (`generate_brief`, `brief_all`,
  cache, evidence-based confidence). Tests never need Ollama; the one `@pytest.mark.ollama` test
  skips without it. See `docs/briefing_evaluation.md`.
- `storage`:
  - `db.py`: versioned SQL migrations in `storage/migrations/`
  - `repository.py`: the `Repository` protocol and `SQLiteRepository` (shifts, decisions with
    DB-captured `opened_at`, study sessions, append-only audit log)
  - `prepare.py`: the `nullpunkt-prepare-shift` CLI
- `app` (logic, `src/nullpunkt/app/`):
  - `metrics.py`: first-decision MTTT, shift stats, `session_metrics`
  - `report.py`: handover as Markdown and HTML
  - `views.py`: presentation helpers
  - `ui.py`: Streamlit helpers
- `app/` (repo root): the Streamlit pages. Run `streamlit run app/streamlit_app.py`. They are
  covered by the guard tests too. See `docs/analyst_app.md`.
- An `Incident` is enriched step by step: `techniques`, then `score`, then `brief`, then `status`.

The batch format is three files plus a manifest:

- `alerts.jsonl`: one `Alert` per line
- `assets.csv`: `Asset` rows
- `labels.csv`: `GroundTruth` rows, for evaluation only
- `manifest.json` (generated batches only): seed, config, counts and a scenario summary, for
  evaluation only

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
3. **Only `evaluation` reads labels; only `generator` writes them; pipeline code sees neither.**
   - Pipeline and app code (ingestion, correlation, attack, scoring, briefing, storage, app)
     sees only `Alert` and `Asset`.
   - It never imports `GroundTruth`, `nullpunkt.evaluation` or `nullpunkt.generator`, and never
     reads `labels.csv` or `manifest.json`.
   - `tests/unit/test_ground_truth.py` enforces this.
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
python -m nullpunkt.generator --out data/generated/batch-001   # generate a 3,000-alert shift
python -m nullpunkt.correlation --batch data/generated/batch-001   # correlate it into incidents
python -m nullpunkt.pipeline --batch data/generated/batch-001      # full ranking: top 10 + tiers
python -m nullpunkt.evaluation.sweep_scoring                       # re-tune scoring (~5 s)
python -m nullpunkt.pipeline --batch data/generated/batch-001 --briefs   # + Phi briefs (Ollama)
python -m nullpunkt.evaluation.brief_eval --out brief_eval.json    # brief evaluation (~7 min)
nullpunkt-prepare-shift --batch data/generated/batch-001           # pipeline + briefs -> SQLite
streamlit run app/streamlit_app.py                                  # analyst app
python -m nullpunkt.evaluation.sweep_correlation   # re-tune correlation (~4-5 min)
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
