# Changelog

## [0.2.0] — 2026-10-20

### Added

- Severity policy profiles (`verify --policy`)
- Evidence zip export (`proofmesh export`)
- Evidence compare (`proofmesh compare` / companion dual import)
- Expanded dependency inventory (lockfiles: poetry, package-lock, Cargo, go)
- Companion PWA (`web/companion/`)
- OSV vulnerability lookup (`--with-osv`)
- Optional Gitleaks / Semgrep wrappers
- Suppression rules with mandatory justification
- `proofmesh schema validate` and SARIF export
- Example suppressions under `examples/`

## [0.1.0] — 2026-10-20

### Added

- Initial local-first CLI and core checks
- Evidence JSON with SHA-256 integrity and optional Ed25519 signing
- SQLite local run history
- Markdown and terminal reports
- JSON Schema for evidence v1
- Unit and integration tests
- GitHub Actions CI workflow
- Core documentation
