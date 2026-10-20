"""Configuration loading and defaults for ProofMesh."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class CheckConfig(BaseModel):
    """Configuration for a single verification check."""

    enabled: bool = True
    timeout_seconds: float = 60.0
    options: dict[str, Any] = Field(default_factory=dict)


class RulesConfig(BaseModel):
    """Secret and risky-pattern rules configuration."""

    secret_patterns: list[dict[str, Any]] = Field(default_factory=list)
    risky_patterns: list[dict[str, Any]] = Field(default_factory=list)
    suppressions: list[dict[str, Any]] = Field(default_factory=list)
    max_file_size_bytes: int = 1_048_576  # 1 MiB
    exclude_globs: list[str] = Field(
        default_factory=lambda: [
            "**/.git/**",
            "**/node_modules/**",
            "**/.venv/**",
            "**/venv/**",
            "**/__pycache__/**",
            "**/*.pyc",
            "**/dist/**",
            "**/build/**",
            "**/.proofmesh/**",
        ]
    )


class ProofMeshConfig(BaseModel):
    """Top-level ProofMesh configuration."""

    schema_version: str = "1.0.0"
    project_name: str | None = None
    checks: dict[str, CheckConfig] = Field(default_factory=dict)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    evidence_dir: str = ".proofmesh/evidence"
    retention_days: int = 30

    @field_validator("checks", mode="before")
    @classmethod
    def _ensure_checks(cls, v: Any) -> Any:
        if v is None:
            return {}
        return v


DEFAULT_CONFIG = ProofMeshConfig(
    checks={
        "secrets": CheckConfig(enabled=True, timeout_seconds=30.0),
        "risky_code": CheckConfig(enabled=True, timeout_seconds=30.0),
        "dependency_inventory": CheckConfig(enabled=True, timeout_seconds=45.0),
        "file_inventory": CheckConfig(enabled=True, timeout_seconds=20.0),
    }
)


def load_config(path: Path | None = None) -> ProofMeshConfig:
    """Load configuration from a JSON file or return defaults."""
    if path is None:
        candidates = [
            Path("proofmesh.json"),
            Path(".proofmesh/config.json"),
            Path("proofmesh.config.json"),
        ]
        for candidate in candidates:
            if candidate.is_file():
                path = candidate
                break
    if path is None or not path.is_file():
        return DEFAULT_CONFIG.model_copy(deep=True)

    data = json.loads(path.read_text(encoding="utf-8"))
    return ProofMeshConfig.model_validate(data)


def write_default_config(path: Path) -> None:
    """Write a default configuration file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        DEFAULT_CONFIG.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
