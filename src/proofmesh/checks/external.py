"""Optional external tool wrappers (Gitleaks, Semgrep) — record evidence, do not reimplement."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from proofmesh.checks.base import CheckResult, CheckStatus, Finding, now_iso
from proofmesh.gitdiff import RepositoryState


def _run_tool(
    args: list[str],
    *,
    cwd: Path,
    timeout: float,
) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except FileNotFoundError:
        return 127, "", "executable not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


class GitleaksCheck:
    """Run gitleaks if installed; otherwise SKIPPED."""

    check_id = "gitleaks"

    def __init__(self, *, timeout: float = 120.0) -> None:
        self.timeout = timeout

    def run(self, state: RepositoryState) -> CheckResult:
        started = now_iso()
        t0 = time.perf_counter()
        limitations = [
            "Requires gitleaks on PATH; skipped if not installed.",
            "ProofMesh wraps the tool; detection quality is Gitleaks' responsibility.",
        ]
        if shutil.which("gitleaks") is None:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIPPED,
                started_at=started,
                finished_at=now_iso(),
                duration_ms=(time.perf_counter() - t0) * 1000,
                message="gitleaks not found on PATH",
                limitations=limitations,
            )

        report_path = state.root / ".proofmesh" / "gitleaks-report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        code, out, err = _run_tool(
            [
                "gitleaks",
                "detect",
                "--source",
                str(state.root),
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--no-banner",
            ],
            cwd=state.root,
            timeout=self.timeout,
        )
        findings: list[Finding] = []
        if report_path.is_file():
            try:
                data = json.loads(report_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data[:200]:
                        findings.append(
                            Finding(
                                rule_id=f"gitleaks.{item.get('RuleID', 'unknown')}",
                                severity="high",
                                path=str(item.get("File") or item.get("file") or ""),
                                message=str(item.get("Description") or item.get("RuleID") or "secret"),
                                remediation="Rotate the credential and remove it from history if needed.",
                                line=item.get("StartLine") or item.get("Line"),
                                matched_preview="[REDACTED by gitleaks wrapper]",
                            )
                        )
            except (json.JSONDecodeError, OSError):
                pass

        if code == 0:
            status = CheckStatus.PASSED
        elif code == 1 or findings:
            status = CheckStatus.FAILED
        elif code == 127:
            status = CheckStatus.SKIPPED
        else:
            status = CheckStatus.ERRORED

        return CheckResult(
            check_id=self.check_id,
            status=status,
            findings=findings,
            started_at=started,
            finished_at=now_iso(),
            duration_ms=(time.perf_counter() - t0) * 1000,
            tool_version="gitleaks",
            exit_code=code,
            message=(err or out or f"gitleaks exit {code}")[:200],
            limitations=limitations,
            metadata={"report_path": str(report_path) if report_path.is_file() else None},
        )


class SemgrepCheck:
    """Run semgrep if installed; otherwise SKIPPED."""

    check_id = "semgrep"

    def __init__(self, *, timeout: float = 180.0, config: str = "auto") -> None:
        self.timeout = timeout
        self.config = config

    def run(self, state: RepositoryState) -> CheckResult:
        started = now_iso()
        t0 = time.perf_counter()
        limitations = [
            "Requires semgrep on PATH; skipped if not installed.",
            "Default config=auto; override via check options when configured.",
            "ProofMesh records results; rule quality is Semgrep's responsibility.",
        ]
        if shutil.which("semgrep") is None:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIPPED,
                started_at=started,
                finished_at=now_iso(),
                duration_ms=(time.perf_counter() - t0) * 1000,
                message="semgrep not found on PATH",
                limitations=limitations,
            )

        code, out, err = _run_tool(
            [
                "semgrep",
                "scan",
                "--config",
                self.config,
                "--json",
                "--quiet",
                str(state.root),
            ],
            cwd=state.root,
            timeout=self.timeout,
        )
        findings: list[Finding] = []
        try:
            data = json.loads(out) if out.strip() else {}
            for r in (data.get("results") or [])[:200]:
                extra = r.get("extra") or {}
                findings.append(
                    Finding(
                        rule_id=f"semgrep.{r.get('check_id', 'unknown')}",
                        severity=str(extra.get("severity") or "medium").lower(),
                        path=str(r.get("path") or ""),
                        message=str(extra.get("message") or r.get("check_id") or ""),
                        remediation="See Semgrep rule documentation for remediation.",
                        line=(r.get("start") or {}).get("line"),
                        column=(r.get("start") or {}).get("col"),
                    )
                )
        except json.JSONDecodeError:
            if code not in (0, 1):
                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.ERRORED,
                    started_at=started,
                    finished_at=now_iso(),
                    duration_ms=(time.perf_counter() - t0) * 1000,
                    exit_code=code,
                    message=(err or "semgrep produced invalid JSON")[:200],
                    limitations=limitations,
                )

        status = CheckStatus.FAILED if findings else (CheckStatus.PASSED if code in (0, 1) else CheckStatus.ERRORED)
        return CheckResult(
            check_id=self.check_id,
            status=status,
            findings=findings,
            started_at=started,
            finished_at=now_iso(),
            duration_ms=(time.perf_counter() - t0) * 1000,
            tool_version="semgrep",
            exit_code=code,
            message=f"semgrep findings={len(findings)} exit={code}",
            limitations=limitations,
        )
