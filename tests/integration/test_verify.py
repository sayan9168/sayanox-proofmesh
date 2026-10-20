"""Integration tests for the full verify flow."""

from __future__ import annotations

from pathlib import Path

from proofmesh.evidence import load_evidence, verify_evidence_integrity
from proofmesh.orchestrator import Orchestrator


def test_verify_dirty_repo_finds_secrets(dirty_repo: Path) -> None:
    orch = Orchestrator()
    state, results = orch.run(path=dirty_repo)
    assert state.is_dirty
    by_id = {r.check_id: r for r in results}
    assert "secrets" in by_id
    secrets = by_id["secrets"]
    assert secrets.status.value == "failed"
    assert any(f.rule_id == "secret.aws_access_key" for f in secrets.findings)
    for f in secrets.findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in (f.matched_preview or "")
        assert "AKIAIOSFODNN7EXAMPLE" not in f.message


def test_verify_clean_repo_passes(tmp_git_repo: Path) -> None:
    orch = Orchestrator()
    state, results = orch.run(path=tmp_git_repo)
    evidence_status = "passed"
    for r in results:
        if r.status.value == "failed":
            evidence_status = "failed"
        if r.status.value == "errored":
            evidence_status = "errored"
            break
    assert evidence_status in ("passed", "skipped")


def test_evidence_file_integrity(dirty_repo: Path, tmp_path: Path) -> None:
    from proofmesh.evidence import build_evidence, write_evidence

    orch = Orchestrator()
    state, results = orch.run(path=dirty_repo)
    evidence = build_evidence(state, results)
    path = tmp_path / "run.evidence.json"
    write_evidence(evidence, path)
    loaded = load_evidence(path)
    ok, msg = verify_evidence_integrity(loaded)
    assert ok, msg
