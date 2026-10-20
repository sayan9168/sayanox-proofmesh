# SAYANOX ProofMesh

**Don't just ship code. Prove what was verified.**

ProofMesh is a **local-first** software verification and evidence engine. It inspects Git repositories, runs deterministic security and quality checks, collects machine-readable evidence with integrity hashes (and optional Ed25519 signatures), and produces reports you can keep, share, or feed into CI.

No cloud account. No paid API. No mandatory AI model. Works offline.

[![CI](https://github.com/sayan9168/sayanox-proofmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/sayan9168/sayanox-proofmesh/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Why ProofMesh?

Most tools either:

- Scan and dump findings (then the scan result is ephemeral), or
- Produce provenance/attestations focused on *builds*, not on *what was verified for a change*.

ProofMesh focuses on **evidence of verification** for a specific repository state:

- What commit / working tree was inspected
- Which checks ran (and which were skipped or errored)
- What findings were produced (secrets redacted)
- Integrity hash of the evidence bundle
- Optional cryptographic signature of who produced it

## Quick start

```bash
# Requires Python 3.12+
pip install -e ".[dev]"

# Initialize config
proofmesh init

# Inspect repository
proofmesh inspect

# Run verification
proofmesh verify

# Verify evidence integrity later
proofmesh evidence verify .proofmesh/evidence/<run-id>.evidence.json
```

## CLI

| Command | Description |
|---------|-------------|
| `proofmesh init` | Write default `proofmesh.json` and `.proofmesh/` |
| `proofmesh inspect` | Show Git state and changed files |
| `proofmesh verify` | Run checks, write evidence, print summary |
| `proofmesh report <evidence.json>` | Re-print summary / write Markdown |
| `proofmesh evidence verify <file>` | Check content-hash integrity (and optional signature) |
| `proofmesh rules --list` | List built-in secret / risky-code rules |
| `proofmesh keygen` | Generate Ed25519 key pair for signing |
| `proofmesh version` | Print version |

Exit codes: `0` passed · `1` failed · `2` errored · `3` other.

## Built-in checks (v0.1)

| Check ID | What it does |
|----------|----------------|
| `file_inventory` | Records change set and repository identity |
| `secrets` | Pattern-based secret detection with **mandatory redaction** |
| `risky_code` | Heuristic risky patterns (`eval`, `shell=True`, …) |
| `dependency_inventory` | Best-effort inventory from common manifests |

Vulnerability *lookup* is intentionally limited in this release — see [docs/limitations.md](docs/limitations.md).

## Evidence

Evidence is a versioned JSON document (`schemas/evidence-v1.schema.json`) containing:

- Run ID, timestamps (UTC), tool version
- Repository identity and change inventory
- Per-check status, findings, durations, limitations
- SHA-256 content hash over a canonical encoding
- Optional Ed25519 signature metadata

A hash is **not** a digital signature. Sign with `proofmesh keygen` + `proofmesh verify --sign-key …` when you need authenticity.

## Architecture (short)

```
Repository Inspector → Verification Orchestrator → Evidence Engine → Reports / SQLite history
         ↑                        ↑
    git status / hash      secrets · risky · inventory
```

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md).

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check src tests
pytest -q
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Status

**Alpha (0.1.0).** Core local CLI, evidence, integrity, and tests are implemented. Companion PWA, full OSV integration, and team features are on the roadmap. Do not treat this as production-hardened without review of [docs/limitations.md](docs/limitations.md).
