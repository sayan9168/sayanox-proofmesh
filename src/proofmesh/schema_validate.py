"""JSON Schema validation for evidence documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def default_schema_path() -> Path:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "schemas" / "evidence-v1.schema.json",
        Path.cwd() / "schemas" / "evidence-v1.schema.json",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return candidates[0]


def load_schema(path: Path | None = None) -> dict[str, Any]:
    path = path or default_schema_path()
    if not path.is_file():
        raise FileNotFoundError(f"Evidence schema not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _lightweight_validate(evidence: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = schema.get("required") or []
    for key in required:
        if key not in evidence:
            errors.append(f"(root): '{key}' is a required property")
    if "summary" in evidence and isinstance(evidence["summary"], dict):
        for key in ("overall_status", "check_counts", "finding_count"):
            if key not in evidence["summary"]:
                errors.append(f"summary: '{key}' is a required property")
    if "integrity" in evidence and isinstance(evidence["integrity"], dict):
        for key in ("algorithm", "content_hash"):
            if key not in evidence["integrity"]:
                errors.append(f"integrity: '{key}' is a required property")
    if "checks" in evidence and not isinstance(evidence["checks"], list):
        errors.append("checks: must be an array")
    return errors


def validate_evidence(
    evidence: dict[str, Any],
    schema: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Validate evidence. Uses jsonschema if installed, else required-field check."""
    schema = schema or load_schema()
    try:
        from jsonschema import Draft202012Validator

        validator = Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(evidence), key=lambda e: list(e.path))
        messages = [
            f"{'/'.join(str(p) for p in e.path) or '(root)'}: {e.message}" for e in errors
        ]
        return (len(messages) == 0, messages)
    except ImportError:
        messages = _lightweight_validate(evidence, schema)
        return (len(messages) == 0, messages)
