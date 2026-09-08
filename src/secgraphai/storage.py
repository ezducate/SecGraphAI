"""Transactional, migration-versioned SQLite storage for SecGraphAI artifacts."""

from __future__ import annotations

import builtins
import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from platformdirs import user_data_path

from secgraphai.core import Report
from secgraphai.security import redact

SCHEMA_VERSION = 1
DOCUMENT_TABLES = frozenset(
    {"targets", "policies", "baselines", "bundles", "plugin_registry", "jobs"}
)


class Storage:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        retention_days: int | None = None,
        encryption_key_env: str | None = None,
        mask_pii: bool = False,
    ) -> None:
        if retention_days is not None and retention_days < 1:
            raise ValueError("retention_days must be positive")
        default = user_data_path("secgraphai") / "secgraph.db"
        self.path = Path(path) if path else default
        self._fernet: Any | None = None
        self.mask_pii = mask_pii
        if encryption_key_env:
            key = os.environ.get(encryption_key_env)
            if not key:
                raise ValueError(f"storage encryption key environment variable is unset: {encryption_key_env}")
            try:
                from cryptography.fernet import Fernet
            except ImportError as exc:  # pragma: no cover - exercised without the security extra
                raise RuntimeError("encrypted storage requires the security extra") from exc
            try:
                self._fernet = Fernet(key.encode())
            except (TypeError, ValueError) as exc:
                raise ValueError("storage encryption key is not a valid Fernet key") from exc
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._initialize()
        if retention_days is not None:
            self.prune(before=datetime.now(UTC) - timedelta(days=retention_days))

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
        document = self._encode(report.model_dump(mode="json"))
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
                finding_document = self._encode(finding.model_dump(mode="json"))
                connection.execute(
                    "INSERT INTO findings VALUES (?, ?, ?)",
                    (report.scan_id, finding.id, finding_document),
                )
                for evidence in finding.evidence:
                    connection.execute(
                        "INSERT INTO evidence (scan_id, finding_id, document) VALUES (?, ?, ?)",
                        (
                            report.scan_id,
                            finding.id,
                            self._encode(evidence.model_dump(mode="json")),
                        ),
                    )
            for interaction in report.interactions:
                connection.execute(
                    "INSERT INTO events (scan_id, document) VALUES (?, ?)",
                    (report.scan_id, self._encode(interaction.model_dump(mode="json"))),
                )
            graph = report.graph if isinstance(report.graph, dict) else {}
            for node in graph.get("nodes", []):
                connection.execute(
                    "INSERT INTO graph_nodes (scan_id, document) VALUES (?, ?)",
                    (report.scan_id, self._encode(node)),
                )
            for edge in graph.get("edges") or graph.get("links") or []:
                connection.execute(
                    "INSERT INTO graph_edges (scan_id, document) VALUES (?, ?)",
                    (report.scan_id, self._encode(edge)),
                )
            for path in graph.get("risk_paths", []):
                connection.execute(
                    "INSERT INTO attack_paths (scan_id, document) VALUES (?, ?)",
                    (report.scan_id, self._encode(path)),
                )

    def get(self, scan_id: str) -> Report | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document FROM reports WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return Report.model_validate(self._decode(str(row[0]))) if row else None

    def list(self, *, limit: int = 100, offset: int = 0) -> list[Report]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("invalid pagination")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT document FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [Report.model_validate(self._decode(str(row[0]))) for row in rows]

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
                (identifier, datetime.now(UTC).isoformat(), self._encode(document)),
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
        return [self._decode(str(row["document"])) for row in rows]

    def get_document(self, table: str, identifier: str) -> dict[str, Any] | None:
        if table not in DOCUMENT_TABLES:
            raise ValueError("unsupported document table")
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT document FROM {table} WHERE id = ?",  # nosec B608  # noqa: S608
                (identifier,),
            ).fetchone()
        return self._decode(str(row["document"])) if row else None

    def attack_paths(self, scan_id: str | None = None) -> builtins.list[dict[str, Any]]:
        query = "SELECT document FROM attack_paths"
        parameters: tuple[str, ...] = ()
        if scan_id is not None:
            query += " WHERE scan_id = ?"
            parameters = (scan_id,)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._decode(str(row["document"])) for row in rows]

    def prune(self, *, before: datetime) -> dict[str, int]:
        """Delete scan artifacts and generic documents older than the supplied cutoff."""
        if before.tzinfo is None:
            raise ValueError("retention cutoff must be timezone-aware")
        cutoff = before.astimezone(UTC).isoformat()
        with self._connect() as connection:
            scans = connection.execute(
                "DELETE FROM scans WHERE created_at < ?", (cutoff,)
            ).rowcount
            reports = connection.execute(
                "DELETE FROM reports WHERE created_at < ?", (cutoff,)
            ).rowcount
            documents = 0
            for table in DOCUMENT_TABLES:
                documents += connection.execute(
                    f"DELETE FROM {table} WHERE created_at < ?",  # noqa: S608  # nosec B608
                    (cutoff,),
                ).rowcount
        return {"scans": scans, "reports": reports, "documents": documents}

    def _encode(self, value: Any) -> str:
        document = json.dumps(redact(value, mask_pii=self.mask_pii), sort_keys=True, default=str)
        if self._fernet is None:
            return document
        return "enc:v1:" + self._fernet.encrypt(document.encode()).decode()

    def _decode(self, document: str) -> Any:
        if document.startswith("enc:v1:"):
            if self._fernet is None:
                raise ValueError("encrypted storage requires its configured key")
            try:
                document = self._fernet.decrypt(document.removeprefix("enc:v1:").encode()).decode()
            except Exception as exc:
                raise ValueError("stored document could not be decrypted") from exc
        return json.loads(document)
