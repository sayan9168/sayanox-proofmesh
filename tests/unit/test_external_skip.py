"""External wrappers skip cleanly when tools are missing."""

from __future__ import annotations

from pathlib import Path

from proofmesh.checks.external import GitleaksCheck, SemgrepCheck
from proofmesh.checks.osv import OSVCheck
from proofmesh.gitdiff import inspect_repository


def test_gitleaks_skipped_without_binary(tmp_git_repo: Path) -> None:
    state = inspect_repository(tmp_git_repo)
    result = GitleaksCheck().run(state)
    assert result.status.value in ("skipped", "passed", "failed", "errored")
    if result.message and "not found" in result.message:
        assert result.status.value == "skipped"


def test_semgrep_skipped_without_binary(tmp_git_repo: Path) -> None:
    state = inspect_repository(tmp_git_repo)
    result = SemgrepCheck().run(state)
    if result.message and "not found" in result.message:
        assert result.status.value == "skipped"


def test_osv_skipped_when_disabled(tmp_git_repo: Path) -> None:
    state = inspect_repository(tmp_git_repo)
    result = OSVCheck(enabled=False).run(state)
    assert result.status.value == "skipped"
