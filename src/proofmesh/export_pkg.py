"""Evidence package export (zip with evidence + optional reports)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any


def export_evidence_zip(
    evidence_path: Path,
    out_path: Path,
    *,
    include_markdown: Path | None = None,
    include_sarif: Path | None = None,
) -> Path:
    if not evidence_path.is_file():
        raise FileNotFoundError(f"Evidence not found: {evidence_path}")

    data = json.loads(evidence_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "run_id" not in data:
        raise ValueError("File does not look like a ProofMesh evidence document")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(evidence_path, arcname=f"evidence/{evidence_path.name}")
        manifest: dict[str, Any] = {
            "format": "proofmesh-export-v1",
            "run_id": data.get("run_id"),
            "overall_status": (data.get("summary") or {}).get("overall_status"),
            "files": [f"evidence/{evidence_path.name}"],
        }
        if include_markdown and include_markdown.is_file():
            zf.write(include_markdown, arcname=f"reports/{include_markdown.name}")
            manifest["files"].append(f"reports/{include_markdown.name}")
        if include_sarif and include_sarif.is_file():
            zf.write(include_sarif, arcname=f"reports/{include_sarif.name}")
            manifest["files"].append(f"reports/{include_sarif.name}")
        zf.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
        summary = {
            "run_id": data.get("run_id"),
            "created_at": data.get("created_at"),
            "summary": data.get("summary"),
            "repository": {
                "head_commit": (data.get("repository") or {}).get("head_commit"),
                "branch": (data.get("repository") or {}).get("branch"),
            },
        }
        zf.writestr("SUMMARY.json", json.dumps(summary, indent=2) + "\n")
    return out_path
