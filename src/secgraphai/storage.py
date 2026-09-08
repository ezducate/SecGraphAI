"""Minimal transactional SQLite report storage."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from platformdirs import user_data_path

from secgraphai.core import Report
from secgraphai.reporting import to_json


class Storage:
    def __init__(self, path: str | Path | None = None) -> None:
        default = user_data_path("secgraphai") / "secgraph.db"
        self.path = Path(path) if path else default
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS reports (scan_id TEXT PRIMARY KEY, "
                "created_at TEXT NOT NULL, document TEXT NOT NULL)"
            )

    def save(self, report: Report) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO reports VALUES (?, ?, ?)",
                (report.scan_id, report.finished_at.isoformat(), to_json(report)),
            )

    def get(self, scan_id: str) -> Report | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document FROM reports WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return Report.model_validate_json(row[0]) if row else None

    def list(self, *, limit: int = 100, offset: int = 0) -> list[Report]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("invalid pagination")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT document FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [Report.model_validate_json(row[0]) for row in rows]

    def finding(self, finding_id: str):
        for report in self.list(limit=1000):
            for finding in report.findings:
                if finding.id == finding_id:
                    return finding
        return None
