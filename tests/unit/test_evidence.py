"""Tests for evidence generation and integrity."""

from __future__ import annotations

from pathlib import Path

from proofmesh.checks.base import CheckResult, CheckStatus
from proofmesh.evidence import (
    build_evidence,
    load_evidence,
    verify_evidence_integrity,
    write_evidence,
)
from proofmesh.gitdiff import inspect_repository
from proofmesh.integrity import generate_keypair, sign_evidence, verify_signature


def test_build_and_verify_integrity(tmp_git_repo: Path) -> None:
    state = inspect_repository(tmp_git_repo)
    results = [
        CheckResult(check_id="file_inventory", status=CheckStatus.PASSED, message="ok"),
    ]
    evidence = build_evidence(state, results)
    ok, msg = verify_evidence_integrity(evidence)
    assert ok, msg
    assert evidence["summary"]["overall_status"] == "passed"


def test_tamper_detected(tmp_git_repo: Path) -> None:
    state = inspect_repository(tmp_git_repo)
    evidence = build_evidence(state, [])
    evidence["summary"]["finding_count"] = 999
    ok, msg = verify_evidence_integrity(evidence)
    assert not ok
    assert "mismatch" in msg.lower()


def test_write_load_roundtrip(tmp_git_repo: Path, tmp_path: Path) -> None:
    state = inspect_repository(tmp_git_repo)
    evidence = build_evidence(state, [])
    path = tmp_path / "e.evidence.json"
    write_evidence(evidence, path)
    loaded = load_evidence(path)
    assert loaded["run_id"] == evidence["run_id"]
    ok, _ = verify_evidence_integrity(loaded)
    assert ok


def test_signature_roundtrip(tmp_git_repo: Path) -> None:
    state = inspect_repository(tmp_git_repo)
    evidence = build_evidence(state, [])
    priv, pub = generate_keypair()
    signed = sign_evidence(evidence, priv)
    assert signed["integrity"]["signed"] is True
    ok, msg = verify_signature(signed, pub)
    assert ok, msg
    signed["summary"]["finding_count"] = 42
    ok2, _ = verify_signature(signed, pub)
    assert not ok2
