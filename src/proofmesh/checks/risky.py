"""Risky-code pattern detection check."""

from __future__ import annotations

import time
from pathlib import Path

from proofmesh.checks.base import CheckResult, CheckStatus, Finding, now_iso
from proofmesh.gitdiff import RepositoryState
from proofmesh.rules import scan_text


class RiskyCodeCheck:
    """Scan for common risky coding patterns (eval, shell=True, etc.)."""

    check_id = "risky_code"

    def __init__(self, *, max_file_size: int = 1_048_576) -> None:
        self.max_file_size = max_file_size

    def run(self, state: RepositoryState) -> CheckResult:
        started = now_iso()
        t0 = time.perf_counter()
        findings: list[Finding] = []
        limitations = [
            "Heuristic pattern matching only; not a full static analyzer.",
            "Language coverage is currently strongest for Python.",
        ]
        scanned = 0
        skipped = 0

        if not state.is_git:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIPPED,
                started_at=started,
                finished_at=now_iso(),
                duration_ms=(time.perf_counter() - t0) * 1000,
                message="Not a Git repository; risky-code check skipped.",
                limitations=limitations,
            )

        extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash"}
        paths: list[Path] = []
        for change in state.changes:
            if change.status == "D" or change.is_symlink or change.is_binary or change.error:
                skipped += 1
                continue
            p = state.root / change.path
            if p.suffix.lower() in extensions and p.is_file():
                paths.append(p)

        for path in paths:
            try:
                if path.stat().st_size > self.max_file_size:
                    skipped += 1
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                rel = str(path.relative_to(state.root))
                matches = scan_text(text, rel, include_secrets=False, include_risky=True)
                for m in matches:
                    findings.append(
                        Finding(
                            rule_id=m.rule_id,
                            severity=m.severity,
                            path=m.path,
                            message=m.message,
                            remediation=m.remediation,
                            line=m.line,
                            column=m.column,
                            matched_preview=m.matched_preview,
                        )
                    )
                scanned += 1
            except OSError:
                skipped += 1

        status = CheckStatus.FAILED if findings else CheckStatus.PASSED
        return CheckResult(
            check_id=self.check_id,
            status=status,
            findings=findings,
            started_at=started,
            finished_at=now_iso(),
            duration_ms=(time.perf_counter() - t0) * 1000,
            tool_version="proofmesh-builtin-0.1.0",
            exit_code=1 if findings else 0,
            message=f"Scanned {scanned} file(s); {len(findings)} finding(s).",
            limitations=limitations,
            metadata={"files_scanned": scanned, "files_skipped": skipped},
        )
