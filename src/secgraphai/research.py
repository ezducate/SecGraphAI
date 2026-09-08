"""Local research importer that emits disabled, human-review-required draft packs."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from secgraphai.attacks import Attack, AttackPack, PackTrust


def extract_text(path: str | Path, *, max_bytes: int = 20_000_000) -> str:
    target = Path(path)
    if target.stat().st_size > max_bytes:
        raise ValueError("research document exceeds size limit")
    if target.suffix.casefold() == ".pdf":
        try:
            from pypdf import PdfReader  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("PDF research import requires the research extra") from exc
        reader = PdfReader(target)
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    return target.read_text(encoding="utf-8", errors="replace")


def draft_attack_pack(path: str | Path) -> tuple[AttackPack, dict[str, Any]]:
    text = extract_text(path)
    digest = hashlib.sha256(text.encode()).hexdigest()[:12]
    sentences = [
        item.strip()
        for item in re.split(r"(?<=[.!?])\s+", text)
        if any(word in item.casefold() for word in ("attack", "inject", "bypass", "exploit"))
    ]
    attacks = tuple(
        Attack(
            f"research-{index}",
            "research-draft",
            sentence[:1000],
            tags=frozenset({"human-review-required"}),
        )
        for index, sentence in enumerate(sentences[:50], 1)
    )
    pack = AttackPack(
        f"local.research.{digest}",
        "0.0.0-draft",
        "local-import",
        "1.0.0rc1",
        attacks,
        PackTrust.LOCAL,
    )
    review = {
        "human_review_required": True,
        "activated": False,
        "source_sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        "limitations": [
            "Automated extraction may misinterpret research claims.",
            "Draft attacks must be reviewed before execution.",
        ],
    }
    return pack, review
