"""Base types for verification checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERRORED = "errored"


@dataclass
class Finding:
    """A single finding produced by a check."""

    rule_id: str
    severity: str
    path: str
    message: str
    remediation: str = ""
    line: int | None = None
    column: int | None = None
    matched_preview: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "message": self.message,
            "remediation": self.remediation,
        }
        if self.line is not None:
            d["line"] = self.line
        if self.column is not None:
            d["column"] = self.column
        if self.matched_preview is not None:
            d["matched_preview"] = self.matched_preview
        if self.extra:
            d["extra"] = self.extra
        return d


@dataclass
class CheckResult:
    """Result of executing one check."""

    check_id: str
    status: CheckStatus
    findings: list[Finding] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    duration_ms: float = 0.0
    tool_version: str | None = None
    exit_code: int | None = None
    message: str = ""
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "tool_version": self.tool_version,
            "exit_code": self.exit_code,
            "message": self.message,
            "limitations": self.limitations,
            "metadata": self.metadata,
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
