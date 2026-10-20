"""SARIF 2.1.0 export for findings (interop with GitHub code scanning, IDEs)."""

from __future__ import annotations

from typing import Any


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _level(severity: str) -> str:
    s = (severity or "").lower()
    if s in ("critical", "high", "error"):
        return "error"
    if s in ("medium", "warning"):
        return "warning"
    if s in ("low", "note", "info"):
        return "note"
    return "warning"


def evidence_to_sarif(evidence: dict[str, Any]) -> dict[str, Any]:
    """Convert a ProofMesh evidence document to a SARIF 2.1.0 log."""
    tool_name = (evidence.get("tool") or {}).get("name", "sayanox-proofmesh")
    tool_version = (evidence.get("tool") or {}).get("version", "0.1.0")
    rules_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for check in evidence.get("checks") or []:
        for f in check.get("findings") or []:
            rule_id = f.get("rule_id") or "unknown"
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": f.get("message") or rule_id},
                    "fullDescription": {"text": f.get("remediation") or f.get("message") or rule_id},
                    "defaultConfiguration": {"level": _level(f.get("severity", "medium"))},
                }
            loc: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("path") or "unknown"},
                }
            }
            if f.get("line"):
                region: dict[str, Any] = {"startLine": int(f["line"])}
                if f.get("column"):
                    region["startColumn"] = int(f["column"])
                loc["physicalLocation"]["region"] = region
            results.append(
                {
                    "ruleId": rule_id,
                    "level": _level(f.get("severity", "medium")),
                    "message": {"text": f.get("message") or rule_id},
                    "locations": [loc],
                }
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/sayan9168/sayanox-proofmesh",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": "proofmesh verify",
                    }
                ],
            }
        ],
    }
