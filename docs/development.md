# Development

## Requirements

- Python 3.12+
- Git
- ~8 GB RAM is sufficient for normal development

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Commands

```bash
# Lint
ruff check src tests
ruff format src tests

# Tests
pytest -q
pytest -q tests/unit
pytest -q tests/integration

# Type check (optional)
mypy src/proofmesh

# Run CLI from source
proofmesh version
proofmesh inspect
proofmesh verify
```

## Project layout

See repository root tree. Package code lives under `src/proofmesh/`.

## Adding a check

1. Implement a class with `check_id` and `run(state) -> CheckResult`.
2. Register it in `orchestrator.DEFAULT_CHECKS`.
3. Add tests under `tests/`.
4. Document limitations.

## Releasing

1. Update `CHANGELOG.md` and version in `pyproject.toml` / `__init__.py`.
2. Ensure CI is green.
3. Tag and publish (when packaging is published).
