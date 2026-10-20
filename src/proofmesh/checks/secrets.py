"""Secret detection check with mandatory redaction."""

from __future__ import annotations

import time
from pathlib import Path

from proofmesh.checks.base import CheckResult, CheckStatus, Finding, now_iso
from proofmesh.gitdiff import RepositoryState
from proofmesh.rules import scan_text


class SecretsCheck:
    """Scan changed and tracked text files for secret patterns."""

    check_id = "secrets"

    def __init__(
        self,
        *,
        max_file_size: int = 1_048_576,
        include_untracked: bool = True,
    ) -> None:
        self.max_file_size = max_file_size
        self.include_untracked = include_untracked

    def run(self, state: RepositoryState) -> CheckResult:
        started = now_iso()
        t0 = time.perf_counter()
        findings: list[Finding] = []
        limitations: list[str] = [
            "Pattern-based detection only; not a complete secret scanner.",
            "Binary files and files exceeding size limits are skipped.",
            "Matched secret values are redacted and never written to reports.",
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
                message="Not a Git repository; secrets check skipped.",
                limitations=limitations,
            )

        paths_to_scan: list[Path] = []
        for change in state.changes:
            if change.status == "D" or change.is_symlink or change.is_binary:
                skipped += 1
                continue
            if change.error:
                skipped += 1
                continue
            p = state.root / change.path
            if p.is_file():
                paths_to_scan.append(p)

        if not paths_to_scan:
            for name in (".env", "config.py", "settings.py", "credentials.json"):
                candidate = state.root / name
                if candidate.is_file():
                    paths_to_scan.append(candidate)

        for path in paths_to_scan:
            try:
                size = path.stat().st_size
                if size > self.max_file_size:
                    skipped += 1
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                rel = str(path.relative_to(state.root))
                matches = scan_text(text, rel, include_secrets=True, include_risky=False)
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
            message=f"Scanned {scanned} file(s); {len(findings)} finding(s); {skipped} skipped.",
            limitations=limitations,
            metadata={"files_scanned": scanned, "files_skipped": skipped},
        )
