"""Permission manifests and isolated external-tool execution."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
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
    artifact_sha256: str | None = None


def run_plugin(
    manifest: PluginManifest,
    payload: dict[str, object],
    *,
    allowed_permissions: Iterable[str] = (),
    timeout: float = 30,
) -> dict[str, object]:
    if manifest.mode == PluginMode.IN_PROCESS:
        raise PermissionError("in-process plugin execution is not supported by the safe runner")
    if not manifest.command:
        raise PermissionError("plugin command is required")
    if not manifest.permissions <= frozenset(allowed_permissions):
        raise PermissionError("plugin requests unapproved permissions")
    if manifest.mode == PluginMode.CONTAINER:
        executable, command = _container_command(manifest)
    else:
        if Path(manifest.command[0]).name != manifest.command[0]:
            raise PermissionError("plugin command must be an allow-listed executable name")
        found = shutil.which(manifest.command[0])
        if not found:
            raise FileNotFoundError("plugin executable is not installed")
        executable = found
        command = (executable, *manifest.command[1:])
        if manifest.trust in {PluginTrust.TRUSTED, PluginTrust.ORGANIZATION}:
            if not manifest.artifact_sha256:
                raise PermissionError("trusted plugin requires an artifact SHA-256")
            digest = _file_sha256(Path(executable))
            if not hmac.compare_digest(digest, manifest.artifact_sha256):
                raise PermissionError("plugin artifact SHA-256 mismatch")
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
            command,
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


def _container_command(manifest: PluginManifest) -> tuple[str, tuple[str, ...]]:
    image = manifest.command[0]
    if not re.fullmatch(r"[A-Za-z0-9._/-]+@sha256:[a-fA-F0-9]{64}", image):
        raise PermissionError("container plugins require an image pinned by SHA-256 digest")
    runtime = shutil.which("docker") or shutil.which("podman")
    if not runtime:
        raise FileNotFoundError("Docker or Podman is required for container plugins")
    temporary_mount = "/" + "tmp:rw,noexec,nosuid,size=16m"
    command = (
        runtime,
        "run",
        "--rm",
        "--interactive",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "256m",
        "--cpus",
        "1",
        "--tmpfs",
        temporary_mount,
        "--env",
        f"SECGRAPH_PLUGIN={manifest.name}",
        image,
        *manifest.command[1:],
    )
    return runtime, command


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        artifact_sha256=str(raw["artifact_sha256"]) if raw.get("artifact_sha256") else None,
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
        if manifest.mode == PluginMode.CONTAINER and not re.fullmatch(
            r"[A-Za-z0-9._/-]+@sha256:[a-fA-F0-9]{64}",
            manifest.command[0] if manifest.command else "",
        ):
            problems.append(f"container plugin image is not digest-pinned: {manifest.name}")
        if not manifest.output_schema:
            problems.append(f"plugin has no output schema: {manifest.name}")
        if (
            manifest.trust in {PluginTrust.TRUSTED, PluginTrust.ORGANIZATION}
            and not manifest.artifact_sha256
        ):
            problems.append(f"trusted plugin has no artifact SHA-256: {manifest.name}")
    return problems
