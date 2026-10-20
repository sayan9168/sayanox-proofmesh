# Architecture

## Goals

- Local-first verification with durable, integrity-protected evidence
- Clear separation of inspection, checking, evidence, and reporting
- Safe defaults: no automatic execution of untrusted code, redaction of secrets
- Extensible check interface without requiring cloud services

## Components

### Repository Inspector (`gitdiff.py`)

- Locates Git root via `git rev-parse`
- Collects HEAD, branch, dirty state, and porcelain status
- Hashes changed files under size limits; records errors instead of lying
- Handles Unicode paths, symlinks, and missing files safely

### Verification Orchestrator (`orchestrator.py`)

- Runs explicitly registered checks
- Tracks passed / failed / skipped / errored independently
- Surfaces tool failures as `errored`, not as empty “passed”
- Supports per-check enablement and timeouts from config

### Security Checks (`checks/`)

- **secrets** — pattern match + mandatory redaction
- **risky_code** — heuristic dangerous constructs
- **file_inventory** — change inventory as first-class result
- **dependency_inventory** — manifest parsing (no full vuln DB in 0.1)

### Evidence Engine (`evidence.py`, `integrity.py`)

- Versioned document with schema id
- Canonical JSON → SHA-256 content hash
- Optional Ed25519 signature over body + content hash
- Explicit note that a hash alone is not authenticity

### Storage (`storage.py`)

- SQLite for run metadata and paths to evidence files
- No source code or secret storage

### Reports (`reports.py`)

- Rich terminal summary
- Markdown report
- JSON evidence is the machine-readable source of truth

### CLI (`cli.py`)

- Typer-based stable commands and documented exit codes

## Data flow

```
User / CI
   │
   ▼
CLI (verify)
   │
   ├─► Inspector ──► RepositoryState
   │
   ├─► Orchestrator ──► [CheckResult, ...]
   │
   ├─► Evidence builder ──► evidence JSON (+ optional signature)
   │
   ├─► SQLite history
   │
   └─► Terminal / Markdown report
```

## Extension points

- Register additional `CheckRunner` callables on `Orchestrator`
- Supply extra secret / risky rules via configuration (planned)
- Import evidence into the companion web UI (roadmap)

## Non-goals (current)

- Replacing Semgrep, Gitleaks, or OSV-Scanner
- Full SLSA provenance generation for builds
- Unauthenticated remote command execution
