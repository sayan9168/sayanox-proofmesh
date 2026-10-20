"""Tests for policy profiles and evidence export."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from proofmesh.checks.base import Finding
from proofmesh.export_pkg import export_evidence_zip
from proofmesh.policy import apply_policy, get_profile, list_profiles


def test_profiles_listed() -> None:
    ids = {p["id"] for p in list_profiles()}
    assert {"strict", "standard", "relaxed", "critical-only"} <= ids


def test_policy_blocking() -> None:
    findings = [
        Finding(rule_id="a", severity="low", path="x", message="m"),
        Finding(rule_id="b", severity="high", path="y", message="m"),
    ]
    status, blocking, info = apply_policy(findings, get_profile("relaxed"))
    assert status == "failed"
    assert len(blocking) == 1
    assert blocking[0].rule_id == "b"
    assert len(info) == 1


def test_export_zip(tmp_path: Path) -> None:
    evidence = {
        "run_id": "run-test",
        "created_at": "2026-10-20T00:00:00+00:00",
        "summary": {"overall_status": "passed", "finding_count": 0},
        "repository": {"head_commit": "abc", "branch": "main"},
        "checks": [],
    }
    ev_path = tmp_path / "x.evidence.json"
    ev_path.write_text(json.dumps(evidence), encoding="utf-8")
    out = tmp_path / "out.zip"
    export_evidence_zip(ev_path, out)
    assert out.is_file()
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "manifest.json" in names
        assert "SUMMARY.json" in names
        assert any(n.startswith("evidence/") for n in names)
