# Contributing to SAYANOX ProofMesh

Thank you for your interest in contributing.

## Development setup

```bash
git clone https://github.com/sayan9168/sayanox-proofmesh.git
cd sayanox-proofmesh
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Guidelines

1. Prefer small, focused pull requests.
2. Add or update tests for behavior changes.
3. Do not commit secrets, private keys, or real credentials.
4. Keep documentation synchronized with actual behavior.
5. Do not mark skipped checks as passed.
6. Redact any secret-like values in logs and fixtures.
7. Use English for source, commits, and CLI output.

## Code style

- Python 3.12+, type hints on public APIs
- `ruff` for lint / format
- `pytest` for tests

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
