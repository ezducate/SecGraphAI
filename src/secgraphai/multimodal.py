"""Bounded multimodal artifact normalization using the common evidence model."""

from __future__ import annotations

import hashlib
import mimetypes
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MediaArtifact:
    path: str
    media_type: str
    size: int
    sha256: str
    extracted_text: str = ""


def inspect_media(path: str | Path, *, max_bytes: int = 50_000_000) -> MediaArtifact:
    target = Path(path)
    if not target.is_file() or target.stat().st_size > max_bytes:
        raise ValueError("media artifact is missing or exceeds size limit")
    content = target.read_bytes()
    media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    text = ""
    if media_type.startswith("text/") or target.suffix.casefold() in {".md", ".json", ".xml"}:
        text = content.decode("utf-8", "replace")
    elif media_type == "application/pdf":
        try:
            from pypdf import PdfReader
        except ImportError:
            text = ""
        else:
            text = "\n".join(page.extract_text() or "" for page in PdfReader(target))
    return MediaArtifact(
        str(target), media_type, len(content), hashlib.sha256(content).hexdigest(), text
    )
