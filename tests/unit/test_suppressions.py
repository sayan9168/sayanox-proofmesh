"""Tests for suppression rules."""

from __future__ import annotations

import json
from pathlib import Path

from proofmesh.checks.base import Finding
from proofmesh.suppressions import Suppression, SuppressionSet, matches_finding


def test_matches_and_requires_justification(tmp_path: Path) -> None:
    path = tmp_path / "sup.json"
    path.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "rule_id": "risky.eval",
                        "path": "tests/**",
                        "justification": "test-only eval",
                        "created_by": "dev",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    sset = SuppressionSet.load(path)
    findings = [
        Finding(rule_id="risky.eval", severity="high", path="tests/x.py", message="eval", line=1),
        Finding(rule_id="risky.eval", severity="high", path="src/app.py", message="eval", line=2),
    ]
    active, audit = sset.filter_findings(findings)
    assert len(active) == 1
    assert active[0].path == "src/app.py"
    assert len(audit) == 1
    assert audit[0]["justification"] == "test-only eval"


def test_missing_justification_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps({"suppressions": [{"rule_id": "x", "justification": ""}]}),
        encoding="utf-8",
    )
    try:
        SuppressionSet.load(path)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_exact_path_match() -> None:
    s = Suppression(rule_id="secret.aws_access_key", path="config.py", justification="rotated")
    assert matches_finding(s, rule_id="secret.aws_access_key", path="config.py", line=None)
    assert not matches_finding(s, rule_id="secret.aws_access_key", path="other.py", line=None)
