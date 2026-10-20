"""Git repository inspection and change analysis."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class GitError(Exception):
    """Raised when a Git operation fails."""


@dataclass
class FileChange:
    """Represents a single file change in the working tree or between commits."""

    path: str
    status: str
    old_path: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    is_symlink: bool = False
    is_binary: bool = False
    error: str | None = None


@dataclass
class RepositoryState:
    """Snapshot of repository identity and working-tree state."""

    root: Path
    is_git: bool
    head_commit: str | None = None
    head_commit_short: str | None = None
    branch: str | None = None
    is_dirty: bool = False
    is_detached: bool = False
    remote_url: str | None = None
    changes: list[FileChange] = field(default_factory=list)
    inventory_incomplete: bool = False
    inventory_errors: list[str] = field(default_factory=list)
    inspected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "is_git": self.is_git,
            "head_commit": self.head_commit,
            "head_commit_short": self.head_commit_short,
            "branch": self.branch,
            "is_dirty": self.is_dirty,
            "is_detached": self.is_detached,
            "remote_url": self.remote_url,
            "changes": [
                {
                    "path": c.path,
                    "status": c.status,
                    "old_path": c.old_path,
                    "size_bytes": c.size_bytes,
                    "sha256": c.sha256,
                    "is_symlink": c.is_symlink,
                    "is_binary": c.is_binary,
                    "error": c.error,
                }
                for c in self.changes
            ],
            "inventory_incomplete": self.inventory_incomplete,
            "inventory_errors": self.inventory_errors,
            "inspected_at": self.inspected_at,
        }


def _run_git(args: list[str], cwd: Path, timeout: float = 30.0) -> str:
    """Run a git command safely (no shell)."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git command timed out: git {' '.join(args)}") from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise GitError(f"git {' '.join(args)} failed (exit {result.returncode}): {stderr}")
    return result.stdout


def find_git_root(start: Path | None = None) -> Path | None:
    """Locate the nearest Git repository root."""
    start = (start or Path.cwd()).resolve()
    try:
        out = _run_git(["rev-parse", "--show-toplevel"], cwd=start)
        return Path(out.strip())
    except GitError:
        return None


def _safe_file_hash(path: Path, max_size: int = 5_242_880) -> tuple[str | None, int | None, bool, str | None]:
    """Compute SHA-256 of a file with size limits."""
    try:
        if path.is_symlink():
            return None, None, False, "symlink"
        if not path.is_file():
            return None, None, False, "not a regular file"
        size = path.stat().st_size
        if size > max_size:
            return None, size, False, f"file exceeds size limit ({size} > {max_size})"
        h = hashlib.sha256()
        is_binary = False
        with path.open("rb") as f:
            chunk = f.read(8192)
            if b"\x00" in chunk:
                is_binary = True
            h.update(chunk)
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest(), size, is_binary, None
    except OSError as exc:
        return None, None, False, str(exc)


def inspect_repository(
    path: Path | None = None,
    *,
    max_file_size: int = 5_242_880,
    include_untracked: bool = True,
) -> RepositoryState:
    """Inspect a Git repository and collect changed-file inventory."""
    root = find_git_root(path)
    if root is None:
        return RepositoryState(
            root=(path or Path.cwd()).resolve(),
            is_git=False,
            inventory_incomplete=True,
            inventory_errors=["Not a Git repository"],
        )

    state = RepositoryState(root=root, is_git=True)

    try:
        head = _run_git(["rev-parse", "HEAD"], cwd=root).strip()
        state.head_commit = head
        state.head_commit_short = head[:12]
    except GitError as exc:
        state.inventory_errors.append(str(exc))
        state.inventory_incomplete = True

    try:
        branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=root).strip()
        if branch == "HEAD":
            state.is_detached = True
            state.branch = None
        else:
            state.branch = branch
    except GitError:
        pass

    try:
        remote = _run_git(["config", "--get", "remote.origin.url"], cwd=root).strip()
        state.remote_url = remote or None
    except GitError:
        state.remote_url = None

    try:
        status_args = ["status", "--porcelain=v1", "-z"]
        if not include_untracked:
            status_args.append("-uno")
        raw = _run_git(status_args, cwd=root)
        entries = [e for e in raw.split("\0") if e]
        i = 0
        while i < len(entries):
            entry = entries[i]
            if len(entry) < 4:
                i += 1
                continue
            xy = entry[:2]
            path_part = entry[3:]
            status_char = xy.strip() or xy[0]
            old_path = None
            if status_char in ("R", "C") and i + 1 < len(entries):
                old_path = path_part
                path_part = entries[i + 1]
                i += 2
            else:
                i += 1

            full = root / path_part
            sha, size, is_bin, err = (None, None, False, None)
            is_link = False
            try:
                is_link = full.is_symlink()
            except OSError:
                pass
            if status_char != "D" and not is_link:
                sha, size, is_bin, err = _safe_file_hash(full, max_size=max_file_size)

            state.changes.append(
                FileChange(
                    path=path_part,
                    status=status_char,
                    old_path=old_path,
                    size_bytes=size,
                    sha256=sha,
                    is_symlink=is_link,
                    is_binary=is_bin,
                    error=err,
                )
            )
        state.is_dirty = len(state.changes) > 0
    except GitError as exc:
        state.inventory_errors.append(str(exc))
        state.inventory_incomplete = True

    return state
