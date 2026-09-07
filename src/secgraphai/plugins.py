"""Permission manifests and isolated external-tool execution."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class PluginManifest:
    name: str
    command: tuple[str, ...]
    permissions: frozenset[str] = frozenset()
    trusted: bool = False


def run_plugin(manifest: PluginManifest, payload: dict[str, object], *,
               allowed_permissions: Iterable[str] = (), timeout: float = 30) -> dict[str, object]:
    if not manifest.command or Path(manifest.command[0]).name != manifest.command[0]:
        raise PermissionError("plugin command must be an allow-listed executable name")
    if not manifest.permissions <= frozenset(allowed_permissions):
        raise PermissionError("plugin requests unapproved permissions")
    result = subprocess.run(manifest.command, input=json.dumps(payload), text=True,
                            capture_output=True, timeout=timeout, check=False,
                            shell=False, env={"PATH": "/usr/bin:/bin"})
    if result.returncode or len(result.stdout) > 2_000_000:
        raise RuntimeError("plugin failed or exceeded output limit")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("plugin output must be a JSON object")
    return value
