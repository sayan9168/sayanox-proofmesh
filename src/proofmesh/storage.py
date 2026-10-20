"""SQLite storage for run metadata and local history."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    overall_status TEXT NOT NULL,
    head_commit TEXT,
    branch TEXT,
    root_path TEXT,
    finding_count INTEGER NOT NULL DEFAULT 0,
    evidence_path TEXT,
    evidence_hash TEXT,
    summary_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at);
"""


class Storage:
    """Local SQLite store for verification runs."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA_SQL)
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO schema_meta(key, value) VALUES (?, ?)",
                    ("schema_version", str(SCHEMA_VERSION)),
                )
            conn.commit()

    def record_run(
        self,
        run_id: str,
        overall_status: str,
        *,
        head_commit: str | None = None,
        branch: str | None = None,
        root_path: str | None = None,
        finding_count: int = 0,
        evidence_path: str | None = None,
        evidence_hash: str | None = None,
        summary: dict[str, Any] | None = None,
    ) -> None:
        created = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO runs(
                    run_id, created_at, overall_status, head_commit, branch,
                    root_path, finding_count, evidence_path, evidence_hash, summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    created,
                    overall_status,
                    head_commit,
                    branch,
                    root_path,
                    finding_count,
                    evidence_path,
                    evidence_hash,
                    json.dumps(summary or {}),
                ),
            )
            conn.commit()

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            return dict(row) if row else None
