"""Non-executing model artifact and deployment supply-chain inspection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

UNSAFE_SUFFIXES = frozenset({".pkl", ".pickle", ".joblib", ".dill", ".pt", ".pth"})
KNOWN_MODEL_SUFFIXES = frozenset({".onnx", ".safetensors", ".gguf", ".bin", *UNSAFE_SUFFIXES})


@dataclass(frozen=True)
class ArtifactInspection:
    path: str
    size: int
    sha256: str
    format: str
    unsafe_serialization: bool
    external_files: tuple[str, ...] = ()
    metadata: dict[str, Any] | None = None


def inspect_artifact(path: str | Path, *, max_bytes: int = 10_000_000_000) -> ArtifactInspection:
    target = Path(path)
    if not target.is_file() or target.stat().st_size > max_bytes:
        raise ValueError("model artifact is missing or exceeds size limit")
    digest = hashlib.sha256()
    with target.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    suffix = target.suffix.casefold()
    metadata: dict[str, Any] = {}
    sidecar = target.with_suffix(target.suffix + ".json")
    if sidecar.is_file() and sidecar.stat().st_size <= 2_000_000:
        value = json.loads(sidecar.read_text(encoding="utf-8"))
        metadata = value if isinstance(value, dict) else {}
    external = tuple(
        sorted(
            str(item.name)
            for item in target.parent.iterdir()
            if item.is_file() and item != target and item != sidecar
        )
    )
    return ArtifactInspection(
        str(target),
        target.stat().st_size,
        digest.hexdigest(),
        suffix.removeprefix(".") or "unknown",
        suffix in UNSAFE_SUFFIXES,
        external,
        metadata,
    )


def inspect_model_directory(path: str | Path) -> list[ArtifactInspection]:
    root = Path(path)
    return [
        inspect_artifact(item)
        for item in sorted(root.rglob("*"))
        if item.is_file() and item.suffix.casefold() in KNOWN_MODEL_SUFFIXES
    ]
