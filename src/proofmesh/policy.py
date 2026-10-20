"""Severity policy profiles — map findings to gate decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "unknown": 2,
}


@dataclass(frozen=True)
class PolicyProfile:
    id: str
    description: str
    fail_on: frozenset[str]
    max_findings: int | None = None


PROFILES: dict[str, PolicyProfile] = {
    "strict": PolicyProfile(
        id="strict",
        description="Fail on any finding (critical through low).",
        fail_on=frozenset({"critical", "high", "medium", "low"}),
    ),
    "standard": PolicyProfile(
        id="standard",
        description="Fail on critical, high, and medium findings.",
        fail_on=frozenset({"critical", "high", "medium"}),
    ),
    "relaxed": PolicyProfile(
        id="relaxed",
        description="Fail only on critical and high findings.",
        fail_on=frozenset({"critical", "high"}),
    ),
    "critical-only": PolicyProfile(
        id="critical-only",
        description="Fail only on critical findings.",
        fail_on=frozenset({"critical"}),
    ),
}


def get_profile(name: str) -> PolicyProfile:
    key = (name or "standard").strip().lower()
    if key not in PROFILES:
        known = ", ".join(sorted(PROFILES))
        raise ValueError(f"Unknown policy profile '{name}'. Known: {known}")
    return PROFILES[key]


def list_profiles() -> list[dict[str, Any]]:
    return [
        {
            "id": p.id,
            "description": p.description,
            "fail_on": sorted(p.fail_on, key=lambda s: -SEVERITY_RANK.get(s, 0)),
        }
        for p in PROFILES.values()
    ]


def apply_policy(
    findings: list[Any],
    profile: PolicyProfile,
) -> tuple[str, list[Any], list[Any]]:
    blocking: list[Any] = []
    informational: list[Any] = []
    for f in findings:
        if isinstance(f, dict):
            sev = str(f.get("severity") or "medium").lower()
        else:
            sev = str(getattr(f, "severity", "medium") or "medium").lower()
        if sev in profile.fail_on:
            blocking.append(f)
        else:
            informational.append(f)
    if profile.max_findings is not None and len(findings) > profile.max_findings:
        return "failed", blocking or findings[:1], informational
    return ("failed" if blocking else "passed"), blocking, informational
