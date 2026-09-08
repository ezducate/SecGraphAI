"""Transactional, migration-versioned SQLite storage for SecGraphAI artifacts."""

from __future__ import annotations

import builtins
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from platformdirs import user_data_path

from secgraphai.core import Report
from secgraphai.reporting import to_json
from secgraphai.security import redact

SCHEMA_VERSION = 1
DOCUMENT_TABLES = frozenset(
    {"targets", "policies", "baselines", "bundles", "plugin_registry", "jobs"}
)


class Storage:
    def __init__(self, path: str | Path | None = None) -> None:
        default = user_data_path("secgraphai") / "secgraph.db"
        self.path = Path(path) if path else default
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS reports (scan_id TEXT PRIMARY KEY, "
                "created_at TEXT NOT NULL, document TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, "
                "created_at TEXT NOT NULL, document TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS findings (scan_id TEXT NOT NULL, id TEXT NOT NULL, "
                "document TEXT NOT NULL, PRIMARY KEY (scan_id, id), "
                "FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "scan_id TEXT NOT NULL, finding_id TEXT NOT NULL, document TEXT NOT NULL, "
                "FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, id) "
                "ON DELETE CASCADE)"
            )
            for table in ("events", "attack_paths", "graph_nodes", "graph_edges"):
                connection.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} "  # noqa: S608 - fixed allow-list
                    "(id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, "
                    "document TEXT NOT NULL, FOREIGN KEY (scan_id) REFERENCES scans(scan_id) "
                    "ON DELETE CASCADE)"
                )
            for table in DOCUMENT_TABLES:
                connection.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} "  # noqa: S608 - fixed allow-list
                    "(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, document TEXT NOT NULL)"
                )
            connection.execute(
                "INSERT OR REPLACE INTO schema_metadata VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    def save(self, report: Report) -> None:
        created_at = report.finished_at.isoformat()
        document = to_json(report)
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO reports VALUES (?, ?, ?)",
                (report.scan_id, created_at, document),
            )
            connection.execute(
                "INSERT OR REPLACE INTO scans VALUES (?, ?, ?)",
                (report.scan_id, created_at, document),
            )
            for table in ("findings", "events", "attack_paths", "graph_nodes", "graph_edges"):
                connection.execute(
                    f"DELETE FROM {table} WHERE scan_id = ?",  # nosec B608  # noqa: S608
                    (report.scan_id,),
                )
            for finding in report.findings:
                finding_document = _json(finding.model_dump(mode="json"))
                connection.execute(
                    "INSERT INTO findings VALUES (?, ?, ?)",
                    (report.scan_id, finding.id, finding_document),
                )
                for evidence in finding.evidence:
                    connection.execute(
                        "INSERT INTO evidence (scan_id, finding_id, document) VALUES (?, ?, ?)",
                        (report.scan_id, finding.id, _json(evidence.model_dump(mode="json"))),
                    )
            for interaction in report.interactions:
                connection.execute(
                    "INSERT INTO events (scan_id, document) VALUES (?, ?)",
                    (report.scan_id, _json(interaction.model_dump(mode="json"))),
                )
            graph = report.graph if isinstance(report.graph, dict) else {}
            for node in graph.get("nodes", []):
                connection.execute(
                    "INSERT INTO graph_nodes (scan_id, document) VALUES (?, ?)",
                    (report.scan_id, _json(node)),
                )
            for edge in graph.get("edges") or graph.get("links") or []:
                connection.execute(
                    "INSERT INTO graph_edges (scan_id, document) VALUES (?, ?)",
                    (report.scan_id, _json(edge)),
                )
            for path in graph.get("risk_paths", []):
                connection.execute(
                    "INSERT INTO attack_paths (scan_id, document) VALUES (?, ?)",
                    (report.scan_id, _json(path)),
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

    def put_document(self, table: str, identifier: str, document: dict[str, Any]) -> None:
        if table not in DOCUMENT_TABLES:
            raise ValueError("unsupported document table")
        if not identifier or len(identifier) > 200:
            raise ValueError("invalid document identifier")
        with self._connect() as connection:
            connection.execute(
                f"INSERT OR REPLACE INTO {table} VALUES (?, ?, ?)",  # noqa: S608
                (identifier, datetime.now(UTC).isoformat(), _json(document)),
            )

    def list_documents(self, table: str, *, limit: int = 100) -> builtins.list[dict[str, Any]]:
        if table not in DOCUMENT_TABLES:
            raise ValueError("unsupported document table")
        if not 1 <= limit <= 1000:
            raise ValueError("invalid pagination")
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT document FROM {table} ORDER BY created_at DESC LIMIT ?",  # nosec B608  # noqa: S608
                (limit,),
            ).fetchall()
        return [json.loads(str(row["document"])) for row in rows]

    def get_document(self, table: str, identifier: str) -> dict[str, Any] | None:
        if table not in DOCUMENT_TABLES:
            raise ValueError("unsupported document table")
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT document FROM {table} WHERE id = ?",  # nosec B608  # noqa: S608
                (identifier,),
            ).fetchone()
        return json.loads(str(row["document"])) if row else None

    def attack_paths(self, scan_id: str | None = None) -> builtins.list[dict[str, Any]]:
        query = "SELECT document FROM attack_paths"
        parameters: tuple[str, ...] = ()
        if scan_id is not None:
            query += " WHERE scan_id = ?"
            parameters = (scan_id,)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [json.loads(str(row["document"])) for row in rows]


def _json(value: Any) -> str:
    return json.dumps(redact(value), sort_keys=True, default=str)
