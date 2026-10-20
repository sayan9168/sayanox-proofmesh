# Evidence Format (v1)

## Overview

Evidence is a JSON object. Schema: `schemas/evidence-v1.schema.json`.

Critical fields:

- `schema_version` — currently `"1.0.0"`
- `run_id` — UUID for the run
- `created_at` — UTC ISO-8601
- `tool` — `{ "name", "version" }`
- `repository` — identity + change inventory
- `summary` — overall status and counts
- `checks` — array of check results (status, findings, limitations)
- `limitations` — run-level caveats
- `integrity` — hash and optional signature metadata

## Integrity

1. Build the object **without** the `integrity` field.
2. Canonicalize with sorted keys and compact separators (`json.dumps(..., sort_keys=True, separators=(',', ':'))`).
3. SHA-256 the UTF-8 bytes → `integrity.content_hash`.
4. Optional: Ed25519-sign a payload containing `content_hash` + body; store hex signature.

Verification recomputes the hash and, if signed, checks the signature with a trusted public key.

**A content hash alone does not prove who produced the evidence.**

## Findings

Each finding may include `matched_preview` that is already redacted. Consumers must not expect raw secrets.

## Status semantics

| Status | Meaning |
|--------|---------|
| `passed` | Check completed without findings that fail the policy |
| `failed` | Check completed and reported findings |
| `skipped` | Check not run (disabled, not applicable) |
| `errored` | Check could not complete reliably |

Skipped and errored must never be displayed as passed.
