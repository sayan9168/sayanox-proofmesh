# Limitations (honest)

ProofMesh 0.1 is an **alpha** local verification evidence engine. Treat the following as binding constraints, not temporary footnotes.

## Detection coverage

- Secret detection is **pattern-based**, not entropy+context ML, and not a replacement for Gitleaks/TruffleHog in high-assurance settings.
- Risky-code checks are **heuristic** and strongest on Python.
- Dependency inventory does **not** perform full vulnerability database lookups in 0.1.
- Language and ecosystem coverage is incomplete by design until integrations land.

## Integrity vs authenticity vs correctness

- Content hash detects *tampering with the evidence document*, not whether checks were “right”.
- Signature proves *which key* signed a document when the public key is trusted.
- Neither proves the absence of vulnerabilities.

## Execution model

- Checks run in-process. There is no strong sandbox for untrusted code execution (and we deliberately do not execute repository code).
- Timeouts are cooperative; a stuck check can still consume resources until process kill.

## Platform

- Primary target: Linux / Unix-like with Git available.
- Android support is planned via PWA for *viewing* evidence, not for running full native scans in 0.1.
- Windows is expected to work for CLI but is less tested.

## Storage

- SQLite is not encrypted at rest.
- Evidence files may contain paths and finding metadata; protect the `.proofmesh/` directory accordingly.

## CI

- The provided workflow runs tests and a sample verify. It is not a full supply-chain attestation pipeline.

When in doubt, read the evidence `limitations` arrays embedded in every run.
