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
- Unit and integration tests
- GitHub Actions CI workflow
- Core documentation

## Added in 0.2 slice (2026-10-20)

- Companion PWA (`web/companion/`) — offline evidence browser
- OSV API check (`--with-osv`, network, best-effort)
- External wrappers: Gitleaks / Semgrep (skip if not installed)
- Suppression rules with mandatory justification + audit trail
- `proofmesh schema validate` JSON Schema command
- SARIF 2.1 export (`proofmesh sarif` / `verify --sarif`)

## Still later

- Multi-platform packaging installers
- Team edition / shared policy server
- Authenticated remote agent
