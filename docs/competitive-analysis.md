# Competitive Analysis

This document compares ProofMesh to publicly documented systems. It does **not** claim ProofMesh is unique, first, or endorsed by any vendor.

## Related systems

| System | Focus | Overlap with ProofMesh |
|--------|--------|-------------------------|
| **Semgrep** | Static analysis / SAST rules | Risky-code style findings; ProofMesh does not replace Semgrep |
| **Gitleaks** | Secret scanning | Secret detection; Gitleaks is more mature for that single job |
| **OSV-Scanner** | Dependency vulnerability lookup | Dependency inventory; full OSV integration is roadmap, not 0.1 |
| **GitHub code scanning / dependency review** | Hosted PR analysis | CI-friendly results; ProofMesh is local-first and portable |
| **Sigstore / cosign** | Signing & transparency for artifacts | Similar *signing* idea applied to evidence documents |
| **in-toto / SLSA** | Supply-chain provenance for builds | Provenance of *builds*; ProofMesh focuses on *verification evidence* for a change |
| **IBM watsonx.governance** | Model/governance risk for AI systems | Different domain (AI governance vs. general software verification evidence) |
| **IBM Research BeeAI** | Agent frameworks / research platform | Not a substitute; different problem space |

## Problem ProofMesh targets

Engineering teams often cannot answer, months later:

> What was actually verified for commit X / PR Y, with what tool versions, and can we detect if that report was altered?

Scanners produce findings; CI logs rot; dashboards require accounts. ProofMesh produces a **portable evidence bundle** with integrity metadata that can live next to the repo or in an archive.

## Differentiation (honest)

1. **Evidence-first, not scan-first** — the primary artifact is a structured, hashable, optionally signed verification record.
2. **Local-first** — useful without cloud, SaaS, or paid APIs.
3. **Status honesty** — skipped ≠ passed; tool failure ≠ clean.
4. **Secret redaction by design** — findings never embed raw secrets.
5. **Does not try to replace** specialized scanners; prefers integration over reimplementation where possible.

## Established vs. new

| Established technology | Used by ProofMesh |
|------------------------|-------------------|
| Git status / rev-parse | Repository identity |
| SHA-256, Ed25519 | Integrity / optional authenticity |
| JSON Schema | Evidence validation |
| Pattern-based secret rules | Baseline detection |
| SQLite | Local history |

| Research / product work still needed | Status |
|--------------------------------------|--------|
| High-quality policy packs & suppression UX | Early |
| Strong OSV / advisory integration | Planned |
| Companion UI for evidence comparison | Planned |
| Cross-org evidence exchange conventions | Future |

## Prefer integration over rebuild

- Use **Gitleaks** or **TruffleHog** when deep secret scanning is required; ProofMesh can record their exit codes and hashes as checks later.
- Use **OSV-Scanner** or **pip-audit** for vulnerability databases.
- Use **Sigstore** when public transparency logs are required; ProofMesh signing is local Ed25519 for evidence authenticity, not a transparency log.

## Claims we do not make

- “World’s first”
- “IBM-approved”
- “Complete vulnerability coverage”
- “Replaces SLSA / in-toto”
