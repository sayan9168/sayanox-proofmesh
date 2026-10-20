"""Suppression rules with justification and audit metadata."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Suppression:
    """A single suppression entry."""

    rule_id: str
    path: str | None = None
    line: int | None = None
    justification: str = ""
    created_by: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: str | None = None
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "path": self.path,
            "line": self.line,
            "justification": self.justification,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Suppression:
        return cls(
            id=str(data.get("id") or ""),
            rule_id=str(data["rule_id"]),
            path=data.get("path"),
            line=data.get("line"),
            justification=str(data.get("justification") or ""),
            created_by=str(data.get("created_by") or ""),
            created_at=str(data.get("created_at") or datetime.now(timezone.utc).isoformat()),
            expires_at=data.get("expires_at"),
        )


def _path_matches(pattern: str | None, path: str) -> bool:
    if pattern is None or pattern == "" or pattern == "*":
        return True
    if pattern == path:
        return True
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path.startswith(prefix)
    if pattern.startswith("**/"):
        return path.endswith(pattern[3:]) or pattern[3:] in path
    if "*" in pattern:
        parts = pattern.split("*", 1)
        return path.startswith(parts[0]) and path.endswith(parts[1])
    return path == pattern


def is_expired(sup: Suppression, now: datetime | None = None) -> bool:
    if not sup.expires_at:
        return False
    now = now or datetime.now(timezone.utc)
    try:
        exp = datetime.fromisoformat(sup.expires_at.replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now > exp
    except ValueError:
        return False


def matches_finding(
    sup: Suppression,
    *,
    rule_id: str,
    path: str,
    line: int | None,
) -> bool:
    if is_expired(sup):
        return False
    if sup.rule_id != rule_id and sup.rule_id != "*":
        return False
    if not _path_matches(sup.path, path):
        return False
    if sup.line is not None and line is not None and sup.line != line:
        return False
    return True


class SuppressionSet:
    """Collection of suppressions loaded from JSON."""

    def __init__(self, items: list[Suppression] | None = None) -> None:
        self.items = list(items or [])

    @classmethod
    def load(cls, path: Path) -> SuppressionSet:
        if not path.is_file():
            return cls([])
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "suppressions" in data:
            raw = data["suppressions"]
        elif isinstance(data, list):
            raw = data
        else:
            raise ValueError("Suppressions file must be a list or {suppressions: [...]}")
        items = [Suppression.from_dict(x) for x in raw]
        for i, s in enumerate(items):
            if not s.id:
                s.id = f"sup-{i + 1}"
            if not s.justification.strip():
                raise ValueError(
                    f"Suppression {s.id} for rule {s.rule_id} requires a non-empty justification"
                )
        return cls(items)

    def filter_findings(self, findings: list[Any]) -> tuple[list[Any], list[dict[str, Any]]]:
        active = []
        suppressed: list[dict[str, Any]] = []
        for f in findings:
            if isinstance(f, dict):
                rule_id = f.get("rule_id", "")
                path = f.get("path", "")
                line = f.get("line")
            else:
                rule_id = getattr(f, "rule_id", "")
                path = getattr(f, "path", "")
                line = getattr(f, "line", None)
            matched_sup = None
            for s in self.items:
                if matches_finding(s, rule_id=rule_id, path=path, line=line):
                    matched_sup = s
                    break
            if matched_sup:
                suppressed.append(
                    {
                        "rule_id": rule_id,
                        "path": path,
                        "line": line,
                        "suppression_id": matched_sup.id,
                        "justification": matched_sup.justification,
                        "created_by": matched_sup.created_by,
                    }
                )
            else:
                active.append(f)
        return active, suppressed
