"""Permission manifests and isolated external-tool execution."""

from __future__ import annotations

import json
import os
import shutil

# Allow-listed executable, shell disabled, and isolated working directory at the call site.
import subprocess  # nosec B404
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class PluginMode(StrEnum):
    IN_PROCESS = "in_process"
    SUBPROCESS = "subprocess"
    CONTAINER = "container"


class PluginTrust(StrEnum):
    TRUSTED = "trusted"
    ORGANIZATION = "organization"
    COMMUNITY = "community"
    LOCAL = "local"


@dataclass(frozen=True)
class PluginManifest:
    name: str
    command: tuple[str, ...]
    permissions: frozenset[str] = frozenset()
    trusted: bool = False
    version: str = "0"
    mode: PluginMode = PluginMode.SUBPROCESS
    trust: PluginTrust = PluginTrust.LOCAL
    output_schema: dict[str, Any] | None = None
    max_output_bytes: int = 2_000_000


def run_plugin(
    manifest: PluginManifest,
    payload: dict[str, object],
    *,
    allowed_permissions: Iterable[str] = (),
    timeout: float = 30,
) -> dict[str, object]:
    if manifest.mode != PluginMode.SUBPROCESS:
        raise PermissionError("only subprocess plugins are supported by this runner")
    if not manifest.command or Path(manifest.command[0]).name != manifest.command[0]:
        raise PermissionError("plugin command must be an allow-listed executable name")
    if not manifest.permissions <= frozenset(allowed_permissions):
        raise PermissionError("plugin requests unapproved permissions")
    executable = shutil.which(manifest.command[0])
    if not executable:
        raise FileNotFoundError("plugin executable is not installed")
    safe_payload = json.dumps(payload, separators=(",", ":"))
    if len(safe_payload.encode()) > 2_000_000:
        raise ValueError("plugin input exceeds size limit")
    environment = {
        "PATH": os.path.dirname(executable),
        "PYTHONIOENCODING": "utf-8",
        "SECGRAPH_PLUGIN": manifest.name,
    }
    with tempfile.TemporaryDirectory(prefix="secgraph-plugin-") as workdir:
        result = subprocess.run(  # noqa: S603
            (executable, *manifest.command[1:]),
            input=safe_payload,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            cwd=workdir,
            shell=False,
            env=environment,
        )  # nosec B603
    if result.returncode or len(result.stdout.encode()) > manifest.max_output_bytes:
        raise RuntimeError("plugin failed or exceeded output limit")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("plugin output must be a JSON object")
    if manifest.output_schema:
        required = manifest.output_schema.get("required", [])
        if not all(key in value for key in required):
            raise ValueError("plugin output does not match its schema")
    return value


def load_manifest(path: str | Path) -> PluginManifest:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("command"), list):
        raise ValueError("invalid plugin manifest")
    return PluginManifest(
        name=str(raw["name"]),
        command=tuple(map(str, raw["command"])),
        permissions=frozenset(map(str, raw.get("permissions", []))),
        trusted=bool(raw.get("trusted", False)),
        version=str(raw.get("version", "0")),
        mode=PluginMode(raw.get("mode", "subprocess")),
        trust=PluginTrust(raw.get("trust", "local")),
        output_schema=raw.get("output_schema"),
        max_output_bytes=int(raw.get("max_output_bytes", 2_000_000)),
    )


def audit_plugins(manifests: Iterable[PluginManifest]) -> list[str]:
    problems = []
    names: set[str] = set()
    for manifest in manifests:
        if manifest.name in names:
            problems.append(f"duplicate plugin: {manifest.name}")
        names.add(manifest.name)
        if manifest.mode == PluginMode.IN_PROCESS and not manifest.trusted:
            problems.append(f"untrusted plugin requests in-process execution: {manifest.name}")
        if "credentials.raw" in manifest.permissions:
            problems.append(f"plugin requests raw credentials: {manifest.name}")
        if not manifest.output_schema:
            problems.append(f"plugin has no output schema: {manifest.name}")
    return problems
