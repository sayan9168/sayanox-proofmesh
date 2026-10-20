# Roadmap

## 0.1 (current)

- [x] Local CLI and core checks
- [x] Evidence JSON + integrity hash
- [x] Optional Ed25519 signing
- [x] SQLite run history
- [x] Unit / integration tests
- [x] CI workflow
- [x] Core documentation

## 0.2

- [x] JSON Schema validation CLI command
- [x] Suppression rules with justification metadata
- [x] Optional integration wrappers for Gitleaks / Semgrep / OSV API
- [ ] Improved dependency inventory (TOML, lockfiles)
- [ ] Evidence import/export package (zip with artifacts)

## 0.3

- [x] Companion PWA (read-only evidence browser)
- [ ] Compare two evidence runs in UI
- [ ] Severity policy profiles
- [x] SARIF export for findings

## Later

- [ ] Team edition concepts (shared policy, retention) — only after real demand
- [ ] Authenticated remote agent (strict allowlist, never open by default)
- [ ] Optional local AI summarization of findings (never as source of truth)

Priorities may change based on user feedback and security review.
