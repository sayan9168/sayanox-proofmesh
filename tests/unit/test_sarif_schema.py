"""Tests for SARIF export and schema validation."""

from __future__ import annotations

from pathlib import Path

from proofmesh.checks.base import CheckResult, CheckStatus, Finding
from proofmesh.evidence import build_evidence
from proofmesh.gitdiff import inspect_repository
from proofmesh.sarif import evidence_to_sarif
from proofmesh.schema_validate import validate_evidence


def test_sarif_contains_findings(tmp_git_repo: Path) -> None:
    state = inspect_repository(tmp_git_repo)
    results = [
        CheckResult(
            check_id="secrets",
            status=CheckStatus.FAILED,
            findings=[
                Finding(
                    rule_id="secret.aws_access_key",
                    severity="high",
                    path="a.py",
                    message="AWS key",
                    line=3,
                )
            ],
        )
    ]
    evidence = build_evidence(state, results)
    sarif = evidence_to_sarif(evidence)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "secret.aws_access_key"


def test_schema_validation_ok(tmp_git_repo: Path) -> None:
    state = inspect_repository(tmp_git_repo)
    evidence = build_evidence(state, [])
    ok, errors = validate_evidence(evidence)
    assert ok, errors


def test_schema_validation_fails_on_missing_fields() -> None:
    ok, errors = validate_evidence({"run_id": "x"})
    assert not ok
    assert errors
