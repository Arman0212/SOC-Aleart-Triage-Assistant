# Contributing

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
cp .env.example .env
```

Python 3.11 or newer is required.

## Branches

Branch off `main` and name the branch after the area you are working on:

```
feat/<area>      new functionality, e.g. feat/correlation, feat/briefing
fix/<area>       bug fixes
docs/<topic>     documentation only
chore/<topic>    tooling, CI, dependencies
```

Areas match the subpackages: `core`, `generator`, `ingestion`, `correlation`, `scoring`,
`attack`, `briefing`, `storage`, `evaluation`, plus `app` for the Streamlit UI.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/), with the area as the scope:

```
feat(scoring): add stage multiplier from ATT&CK tactic
fix(ingestion): report line number for empty CSV cells
test(correlation): cover alerts that share only a user
docs: explain noise penalty
chore: bump ruff
```

Keep commits small and focused. One logical change per commit makes review and reverts easy.

## Pull requests

- Before opening a PR, run `ruff check .`, `ruff format --check .` and `pytest` locally.
- **CI must be green** before merging. It runs ruff and pytest on Python 3.11 and 3.12.
- Add or update tests for any behaviour you change.
- Update `docs/` when you change behaviour described there.

## Schema changes

`src/nullpunkt/core/schema.py` is the contract every package depends on. Changing it **needs team
approval**:

1. Open an issue or post in the team channel explaining the change and why.
2. Once agreed, make the change in its own `feat(core)` PR, and update
   `docs/data_contract.md` and the tests in `tests/unit/test_schema.py` in the same PR.
3. Bump `SCHEMA_VERSION` if the change breaks existing batch files.

## Ground truth

Only `nullpunkt.evaluation` reads `labels.csv` and `manifest.json`, and only
`nullpunkt.generator` writes them. Pipeline and app code must work from `Alert` and `Asset`
alone, and must not import `nullpunkt.evaluation` or `nullpunkt.generator`. Tests enforce this,
so do not work around them.
