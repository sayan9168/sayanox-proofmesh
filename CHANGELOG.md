# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] — 2026-10-20

### Added

- Initial local-first CLI: `init`, `inspect`, `verify`, `report`, `evidence verify`, `rules`, `keygen`, `version`
- Repository inspector (Git status, change inventory, Unicode paths, size limits)
- Built-in checks: secrets (redacted), risky-code patterns, file inventory, dependency inventory
- Versioned evidence JSON with SHA-256 integrity and optional Ed25519 signing
- SQLite local run history
- Markdown and terminal reports
- JSON Schema for evidence v1
- Unit and integration tests
- GitHub Actions CI workflow
- Core documentation (architecture, threat model, competitive analysis, limitations, roadmap)
