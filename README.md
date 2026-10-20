# SAYANOX ProofMesh

**Don't just ship code. Prove what was verified.**

ProofMesh is a **local-first** software verification and evidence engine. It inspects Git repositories, runs deterministic security and quality checks, collects machine-readable evidence with integrity hashes (and optional Ed25519 signatures), and produces reports you can keep, share, or feed into CI.

No cloud account. No paid API. No mandatory AI model. Works offline.

[![CI](https://github.com/sayan9168/sayanox-proofmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/sayan9168/sayanox-proofmesh/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.2.0-green.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Local-first](https://img.shields.io/badge/local--first-yes-brightgreen.svg)](#why-proofmesh)
[![PyPI](https://img.shields.io/badge/PyPI-coming%20soon-lightgrey.svg)](docs/publishing.md)

## Why ProofMesh?

Most tools either scan and dump findings (ephemeral), or produce build provenance. ProofMesh focuses on **evidence of verification** for a specific repository state.

## Quick start

```bash
pip install -e ".[dev]"
proofmesh init
proofmesh inspect
proofmesh verify
proofmesh verify --policy strict
proofmesh verify --with-osv
proofmesh verify --suppressions examples/suppressions.example.json
proofmesh verify --sarif out.sarif --markdown report.md
proofmesh evidence verify .proofmesh/evidence/<run-id>.evidence.json
proofmesh schema validate .proofmesh/evidence/<run-id>.evidence.json
proofmesh export .proofmesh/evidence/<run-id>.evidence.json -o bundle.zip
proofmesh compare evidence-a.json evidence-b.json
```

## CLI (0.2)

| Command | Description |
|---------|-------------|
| `proofmesh init` | Write default config |
| `proofmesh inspect` | Git state and changes |
| `proofmesh verify` | Run checks + evidence |
| `proofmesh report` | Markdown / terminal |
| `proofmesh evidence verify` | Integrity (+ optional signature) |
| `proofmesh schema validate` | JSON Schema check |
| `proofmesh sarif` | SARIF 2.1 export |
| `proofmesh export` | Zip evidence package |
| `proofmesh compare` | Diff two evidence runs |
| `proofmesh policy --list` | Severity profiles |
| `proofmesh rules --list` | Built-in rules |
| `proofmesh keygen` | Ed25519 keys |
| `proofmesh version` | Version |

### verify flags

`--only` · `--with-osv` · `--with-gitleaks` · `--with-semgrep` · `--suppressions` · `--policy` (strict\|standard\|relaxed\|critical-only) · `--sarif` · `--sign-key`

Exit codes: `0` passed · `1` failed · `2` errored · `3` other.

## Companion PWA

```bash
cd web/companion && python -m http.server 8080
# Import A / optional B to compare offline
```

## Checks

`file_inventory` · `secrets` · `risky_code` · `dependency_inventory` (manifests + lockfiles) · opt-in `osv` / `gitleaks` / `semgrep`

## Docs

[architecture](docs/architecture.md) · [threat model](docs/threat-model.md) · [limitations](docs/limitations.md) · [roadmap](docs/roadmap.md) · [publishing](docs/publishing.md)

## License

Apache-2.0
