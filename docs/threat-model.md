# Threat Model

## Assets

- Evidence authenticity and integrity
- Developer secrets that may appear in working trees
- Local SQLite history and evidence files
- Signing private keys (when used)

## Trust boundaries

1. **Repository content** — untrusted. Paths, file contents, and comments are data, not instructions.
2. **Evidence files from others** — untrusted until integrity (and optionally signature) is verified.
3. **Configuration files** — treated as local policy; still validated.
4. **External scanners** (future) — their stdout is untrusted input to parsers.

## Adversaries

- Malicious or compromised repository content trying to:
  - Cause path traversal or symlink following into sensitive files
  - Inject secrets into logs via crafted findings
  - Exhaust CPU/memory with huge files
  - Spoof “passed” status without running checks
- Tampering with evidence JSON after generation
- Theft of signing private keys

## Mitigations (implemented or required)

| Threat | Mitigation |
|--------|------------|
| Path traversal | Resolve under repo root; avoid following untrusted symlinks for content reads |
| Secret leakage | Redact matches; never write raw secrets to evidence or logs |
| Oversized input | File size limits on hashing and scanning |
| Fake pass status | Orchestrator records real statuses; clients must not trust client-supplied status without validation |
| Evidence tampering | SHA-256 over canonical body; optional Ed25519 signature |
| Command injection | No shell=True for Git or checks; argument lists only |
| Untrusted code execution | Checks do not import or exec repository code |

## Out of scope for 0.1

- Multi-tenant cloud control plane
- Guaranteeing completeness of secret or vulnerability detection
- Protecting against a fully compromised developer workstation (keys can be stolen)

## Residual risks

- Pattern-based secret detection has false negatives and positives.
- Unsigned evidence can be modified by anyone with write access to the file.
- SQLite DB on disk is not encrypted at rest by default.
