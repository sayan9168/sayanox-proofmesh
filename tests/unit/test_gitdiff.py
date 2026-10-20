"""Tests for repository inspection."""

from __future__ import annotations

from pathlib import Path

from proofmesh.gitdiff import inspect_repository


def test_non_git_directory(tmp_path: Path) -> None:
    state = inspect_repository(tmp_path)
    assert state.is_git is False
    assert state.inventory_incomplete is True


def test_clean_repo(tmp_git_repo: Path) -> None:
    state = inspect_repository(tmp_git_repo)
    assert state.is_git is True
    assert state.head_commit is not None
    assert state.is_dirty is False
    assert len(state.changes) == 0


def test_dirty_repo_detects_files(dirty_repo: Path) -> None:
    state = inspect_repository(dirty_repo)
    assert state.is_dirty is True
    paths = {c.path for c in state.changes}
    assert "app.py" in paths
    assert "requirements.txt" in paths


def test_unicode_filename(tmp_git_repo: Path) -> None:
    name = "ফাইল-测试.txt"
    (tmp_git_repo / name).write_text("hello\n", encoding="utf-8")
    state = inspect_repository(tmp_git_repo)
    paths = {c.path for c in state.changes}
    assert name in paths
