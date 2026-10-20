"""Evidence schema, generation, and validation."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from proofmesh import __schema_version__, __version__
from proofmesh.checks.base import CheckResult
from proofmesh.gitdiff import RepositoryState


EVIDENCE_SCHEMA_ID = "https://github.com/sayan9168/sayanox-proofmesh/schemas/evidence-v1.schema.json"


def _canonical_json(data: Any) -> bytes:
    """Canonical JSON encoding for hashing/signing (sorted keys, no whitespace variance)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_evidence(
    state: RepositoryState,
    results: list[CheckResult],
    *,
    run_id: str | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Build a versioned evidence document from repository state and check results."""
    run_id = run_id or str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    checks = [r.to_dict() for r in results]
    overall = "passed"
    for r in results:
        if r.status.value == "errored":
            overall = "errored"
            break
        if r.status.value == "failed":
            overall = "failed"
        elif r.status.value == "skipped" and overall == "passed":
            pass

    counts = {"passed": 0, "failed": 0, "skipped": 0, "errored": 0}
    finding_count = 0
    for r in results:
        counts[r.status.value] = counts.get(r.status.value, 0) + 1
        finding_count += len(r.findings)

    body: dict[str, Any] = {
        "schema_version": __schema_version__,
        "schema_id": EVIDENCE_SCHEMA_ID,
        "run_id": run_id,
        "created_at": now,
        "tool": {
            "name": "sayanox-proofmesh",
            "version": __version__,
        },
        "repository": state.to_dict(),
        "summary": {
            "overall_status": overall,
            "check_counts": counts,
            "finding_count": finding_count,
        },
        "checks": checks,
        "limitations": limitations
        or [
            "Deterministic local checks only; no cloud or AI model required.",
            "Secret values are redacted; full secret content is never stored.",
            "Vulnerability lookup coverage is limited; see docs/limitations.md.",
        ],
        "artifacts": [],
    }

    canonical = _canonical_json(body)
    content_hash = sha256_bytes(canonical)
    body["integrity"] = {
        "algorithm": "sha256",
        "content_hash": content_hash,
        "signed": False,
        "signature": None,
        "public_key_hint": None,
        "note": "Hash alone is not a digital signature and does not prove who executed the check.",
    }
    return body


def write_evidence(evidence: dict[str, Any], path: Path) -> str:
    """Write evidence JSON and return its SHA-256."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(evidence, indent=2, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")
    return sha256_bytes(text.encode("utf-8"))


def load_evidence(path: Path) -> dict[str, Any]:
    """Load and parse an evidence file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Evidence root must be a JSON object")
    return data


def verify_evidence_integrity(evidence: dict[str, Any]) -> tuple[bool, str]:
    """Recompute content hash and compare to stored integrity.content_hash."""
    integrity = evidence.get("integrity")
    if not isinstance(integrity, dict):
        return False, "Missing integrity block"
    stored = integrity.get("content_hash")
    if not stored:
        return False, "Missing content_hash"

    body = {k: v for k, v in evidence.items() if k != "integrity"}
    computed = sha256_bytes(_canonical_json(body))
    if computed != stored:
        return False, f"Content hash mismatch: stored={stored[:16]}… computed={computed[:16]}…"
    return True, "Integrity hash matches"
