# Implementation Status — 2026-10-20

## Implemented (verified in this workspace)

- Project packaging (`pyproject.toml`, Apache-2.0)
- CLI: init, inspect, verify, report, evidence verify/show, rules, keygen, version
- Repository inspector with dirty/clean, Unicode paths, size limits
- Checks: secrets (redacted), risky_code, file_inventory, dependency_inventory
- Evidence builder with canonical SHA-256 integrity
- Optional Ed25519 sign / verify
- SQLite run history
- Terminal + Markdown reports
- JSON Schema for evidence v1
- Unit tests (gitdiff, rules, evidence, signatures)
- Integration tests (verify flow on dirty/clean repos)
- GitHub Actions CI workflow
- Documentation set required by the master prompt

## Not implemented yet (explicitly out of 0.1 scope)

- Companion PWA UI
- Full OSV vulnerability lookup
- External tool wrappers (Gitleaks, Semgrep) as first-class checks
- Suppression rule engine with audit trail
- Multi-platform packaging installers

## Commands run during development

See CI and local `pytest` / `ruff` invocations recorded in the session.

## Next concrete actions

1. Expand dependency parsers
2. Add schema validation command
3. Begin read-only companion UI for evidence bundles
