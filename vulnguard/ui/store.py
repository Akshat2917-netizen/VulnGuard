"""SQLite persistence for dashboard scan results."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ScanStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    function_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    pipeline_status TEXT NOT NULL,
                    vulnerability_found INTEGER NOT NULL,
                    judge_verdict TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def save(self, scan_id: str, result: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        payload = {**result, "scan_id": scan_id}
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scans (
                    scan_id, function_id, file_path, pipeline_status,
                    vulnerability_found, judge_verdict, result_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    pipeline_status = excluded.pipeline_status,
                    vulnerability_found = excluded.vulnerability_found,
                    judge_verdict = excluded.judge_verdict,
                    result_json = excluded.result_json,
                    updated_at = excluded.updated_at
                """,
                (
                    scan_id,
                    str(payload.get("function_id", "unknown")),
                    str(payload.get("file_path", "")),
                    str(payload.get("pipeline_status", "UNKNOWN")),
                    int(bool(payload.get("vulnerability_found"))),
                    str(payload.get("judge_verdict", "")),
                    json.dumps(payload, default=str),
                    now,
                    now,
                ),
            )

    def get(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return json.loads(row["result_json"]) if row else None

    def list(self, limit: int = 100) -> dict[str, dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT scan_id, result_json FROM scans ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return {row["scan_id"]: json.loads(row["result_json"]) for row in rows}

    def metrics(self) -> dict[str, int | float]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COALESCE(SUM(vulnerability_found), 0) AS vulnerable,
                    COALESCE(SUM(CASE WHEN judge_verdict = 'PASS' THEN 1 ELSE 0 END), 0) AS patched
                FROM scans
                """
            ).fetchone()
        total = int(row["total"])
        vulnerable = int(row["vulnerable"])
        patched = int(row["patched"])
        return {
            "total_scans": total,
            "vulnerabilities_found": vulnerable,
            "patches_validated": patched,
            "patch_rate": patched / max(vulnerable, 1),
        }
