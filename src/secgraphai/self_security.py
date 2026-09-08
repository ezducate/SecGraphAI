"""Installation integrity, configuration, dependency, plugin, and pack audits."""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import importlib.metadata
import json
import os
import stat

# Fixed executable, shell disabled, and bounded timeout at the call site.
import subprocess  # nosec B404
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from secgraphai.attacks import AttackPack, PackTrust
from secgraphai.plugins import PluginManifest, audit_plugins
from secgraphai.security import doctor, redact


class AuditStatus(StrEnum):
    # Audit state label, not a credential.
    PASS = "PASS"  # noqa: S105  # nosec B105
    WARN = "WARN"
    FAIL = "FAIL"
    NA = "N/A"


@dataclass(frozen=True)
class AuditCheck:
    name: str
    status: AuditStatus
    detail: str = ""


@dataclass(frozen=True)
class AuditReport:
    checks: tuple[AuditCheck, ...]
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(item.status not in {AuditStatus.FAIL} for item in self.checks)

    def as_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "checks": [item.__dict__ for item in self.checks],
            "metadata": self.metadata,
        }


def package_integrity() -> AuditCheck:
    try:
        distribution = importlib.metadata.distribution("secgraphai")
    except importlib.metadata.PackageNotFoundError:
        return AuditCheck("Package integrity", AuditStatus.WARN, "editable/uninstalled package")
    record = distribution.read_text("RECORD")
    if not record:
        return AuditCheck("Package integrity", AuditStatus.WARN, "distribution has no RECORD")
    mismatches = []
    for relative_path, encoded_hash, _size in csv.reader(record.splitlines()):
        if not encoded_hash or not encoded_hash.startswith("sha256="):
            continue
        installed = Path(str(distribution.locate_file(relative_path)))
        if not installed.is_file():
            mismatches.append(relative_path)
            continue
        expected = encoded_hash.removeprefix("sha256=")
        actual = base64.urlsafe_b64encode(_sha256_file(installed)).decode().rstrip("=")
        if not hmac.compare_digest(actual, expected):
            mismatches.append(relative_path)
    if mismatches:
        return AuditCheck(
            "Package integrity",
            AuditStatus.FAIL,
            f"{len(mismatches)} installed file hashes do not match RECORD",
        )
    return AuditCheck("Package integrity", AuditStatus.PASS, "installed RECORD hashes verified")


def dependency_audit(deep: bool = False) -> AuditCheck:
    if not deep:
        return AuditCheck(
            "Dependency vulnerabilities", AuditStatus.WARN, "run with --deep to invoke pip-audit"
        )
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            shell=False,
        )  # nosec B603
    except (OSError, subprocess.TimeoutExpired):
        return AuditCheck("Dependency vulnerabilities", AuditStatus.WARN, "pip-audit unavailable")
    if result.returncode == 0:
        return AuditCheck("Dependency vulnerabilities", AuditStatus.PASS)
    return AuditCheck("Dependency vulnerabilities", AuditStatus.FAIL, "pip-audit found issues")


def permissions_check(path: str | Path | None, name: str) -> AuditCheck:
    if path is None or not Path(path).exists():
        return AuditCheck(name, AuditStatus.NA)
    mode = Path(path).stat().st_mode
    if os.name != "nt" and mode & (stat.S_IWGRP | stat.S_IWOTH):
        return AuditCheck(name, AuditStatus.FAIL, "path is group/world writable")
    return AuditCheck(name, AuditStatus.PASS)


def run_self_audit(
    *,
    config: dict[str, object] | None = None,
    config_path: str | Path | None = None,
    database: str | Path | None = None,
    plugins: Iterable[PluginManifest] = (),
    packs: Iterable[AttackPack] = (),
    deep: bool = False,
) -> AuditReport:
    plugin_values = tuple(plugins)
    pack_values = tuple(packs)
    plugin_problems = audit_plugins(plugin_values)
    unverified = [pack.id for pack in pack_values if pack.trust == PackTrust.UNVERIFIED_COMMUNITY]
    config_problems = doctor(dict(config or {})) if config is not None else []
    dashboard_raw = config.get("dashboard") if config is not None else None
    dashboard = dict(dashboard_raw) if isinstance(dashboard_raw, dict) else {}
    dashboard_host = str(dashboard.get("host", "127.0.0.1"))
    dashboard_local = dashboard_host in {"127.0.0.1", "localhost", "::1"}
    secret_probe = {"api_key": "SG-SECRET"}
    checks = [
        package_integrity(),
        dependency_audit(deep),
        AuditCheck(
            "Unexpected plugins",
            AuditStatus.FAIL if plugin_problems else AuditStatus.PASS,
            "; ".join(plugin_problems),
        ),
        AuditCheck(
            "Plugin signatures",
            AuditStatus.FAIL
            if any(
                item.trust.value in {"trusted", "organization"} and not item.artifact_sha256
                for item in plugin_values
            )
            else AuditStatus.PASS,
        ),
        AuditCheck(
            "Attack pack signatures",
            AuditStatus.FAIL if unverified else AuditStatus.PASS,
            ", ".join(unverified),
        ),
        AuditCheck(
            "Configuration safety",
            AuditStatus.FAIL
            if config_problems
            else (AuditStatus.NA if config is None else AuditStatus.PASS),
            "; ".join(config_problems),
        ),
        permissions_check(config_path, "Config permissions"),
        permissions_check(database, "Database permissions"),
        AuditCheck(
            "Dashboard bind",
            AuditStatus.PASS if dashboard_local else AuditStatus.FAIL,
            dashboard_host,
        ),
        AuditCheck(
            "TLS configuration",
            AuditStatus.NA
            if dashboard_local
            else (AuditStatus.PASS if dashboard.get("tls") else AuditStatus.FAIL),
        ),
        AuditCheck(
            "Secret exposure",
            AuditStatus.PASS
            if redact(secret_probe)["api_key"] == "[REDACTED]"
            else AuditStatus.FAIL,
        ),
        AuditCheck(
            "Unsafe environment vars",
            AuditStatus.WARN
            if any(
                key.upper().endswith(("_KEY", "_TOKEN", "_SECRET")) and value
                for key, value in os.environ.items()
            )
            else AuditStatus.PASS,
            "secret-like environment variables are present",
        ),
        AuditCheck(
            "Version freshness",
            AuditStatus.WARN,
            "offline audit does not query a package index",
        ),
    ]
    digest = hashlib.sha256(
        json.dumps([item.__dict__ for item in checks], sort_keys=True, default=str).encode()
    ).hexdigest()
    return AuditReport(tuple(checks), {"audit_sha256": digest})


def _sha256_file(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()
