# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes (alpha) |

## Reporting a vulnerability

Please report security issues privately to the maintainer via GitHub Security Advisories on this repository, or email the address listed in `pyproject.toml`.

Do **not** open a public issue for vulnerabilities that could be exploited before a fix is available.

## Scope notes

- ProofMesh is a verification *evidence* tool. It does not claim complete vulnerability coverage.
- Secret detection is pattern-based; matched values are redacted from logs and reports. Report any case where a raw secret is emitted.
- Optional Ed25519 signing proves who signed a particular evidence document when the public key is trusted; it does not prove correctness of the underlying checks.
- The CLI and library intentionally avoid executing untrusted repository code.

## Hardening expectations

Contributors should:

- Validate external input (paths, JSON evidence, config)
- Avoid shell-string execution of untrusted commands
- Bound file sizes, timeouts, and memory where practical
- Never log or persist raw secret values
