"""File and dependency inventory checks."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from proofmesh.checks.base import CheckResult, CheckStatus, Finding, now_iso
from proofmesh.gitdiff import RepositoryState


class FileInventoryCheck:
    """Record the change inventory as a check result (always informational)."""

    check_id = "file_inventory"

    def run(self, state: RepositoryState) -> CheckResult:
        started = now_iso()
        t0 = time.perf_counter()
        limitations = []
        if state.inventory_incomplete:
            limitations.append("Inventory is incomplete; see inventory_errors.")
        for err in state.inventory_errors:
            limitations.append(err)

        status = CheckStatus.ERRORED if state.inventory_incomplete and not state.is_git else CheckStatus.PASSED
        if not state.is_git:
            status = CheckStatus.SKIPPED

        return CheckResult(
            check_id=self.check_id,
            status=status,
            findings=[],
            started_at=started,
            finished_at=now_iso(),
            duration_ms=(time.perf_counter() - t0) * 1000,
            tool_version="proofmesh-builtin-0.1.0",
            exit_code=0 if status != CheckStatus.ERRORED else 2,
            message=f"{len(state.changes)} change(s) recorded; dirty={state.is_dirty}",
            limitations=limitations,
            metadata={
                "change_count": len(state.changes),
                "is_dirty": state.is_dirty,
                "head_commit": state.head_commit,
            },
        )


_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_.\-]+)?",
)


class DependencyInventoryCheck:
    """Collect a best-effort dependency inventory from common manifest files."""

    check_id = "dependency_inventory"

    MANIFESTS = (
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "package.json",
        "Pipfile",
        "poetry.lock",
        "Cargo.toml",
        "go.mod",
    )

    def run(self, state: RepositoryState) -> CheckResult:
        started = now_iso()
        t0 = time.perf_counter()
        findings: list[Finding] = []
        deps: list[dict[str, str]] = []
        limitations = [
            "Inventory only; vulnerability lookup is not performed in this version.",
            "Parser coverage is limited to common Python and Node manifests.",
        ]

        root = state.root
        found_any = False
        for name in self.MANIFESTS:
            path = root / name
            if not path.is_file():
                continue
            found_any = True
            try:
                if name.endswith(".txt"):
                    text = path.read_text(encoding="utf-8", errors="replace")
                    for line in text.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith("-"):
                            continue
                        m = _REQ_LINE.match(line)
                        if m:
                            deps.append({"name": m.group(1), "version": m.group(2) or "", "source": name})
                elif name == "package.json":
                    data = json.loads(path.read_text(encoding="utf-8"))
                    for section in ("dependencies", "devDependencies", "optionalDependencies"):
                        for pkg, ver in (data.get(section) or {}).items():
                            deps.append({"name": pkg, "version": str(ver), "source": f"{name}:{section}"})
                elif name == "pyproject.toml":
                    text = path.read_text(encoding="utf-8", errors="replace")
                    if "dependencies" in text:
                        deps.append({"name": "(see pyproject.toml)", "version": "", "source": name})
            except (OSError, json.JSONDecodeError) as exc:
                findings.append(
                    Finding(
                        rule_id="inventory.parse_error",
                        severity="low",
                        path=name,
                        message=f"Failed to parse manifest: {exc}",
                    )
                )

        status = CheckStatus.PASSED
        if not found_any:
            status = CheckStatus.SKIPPED
            msg = "No supported dependency manifests found."
        else:
            msg = (
                f"Inventoried {len(deps)} dependency reference(s) from "
                f"{sum(1 for n in self.MANIFESTS if (root / n).is_file())} manifest(s)."
            )

        return CheckResult(
            check_id=self.check_id,
            status=status,
            findings=findings,
            started_at=started,
            finished_at=now_iso(),
            duration_ms=(time.perf_counter() - t0) * 1000,
            tool_version="proofmesh-builtin-0.1.0",
            exit_code=0,
            message=msg,
            limitations=limitations,
            metadata={"dependencies": deps[:500]},
        )
