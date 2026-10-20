"""Shared pytest fixtures."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """Create a temporary Git repository with an initial commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    (repo / "README.md").write_text("# Test\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    return repo


@pytest.fixture
def dirty_repo(tmp_git_repo: Path) -> Path:
    """Repository with uncommitted changes including a fake secret."""
    (tmp_git_repo / "app.py").write_text(
        "API_KEY = 'AKIAIOSFODNN7EXAMPLE'\neval('1+1')\n",
        encoding="utf-8",
    )
    (tmp_git_repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    return tmp_git_repo
