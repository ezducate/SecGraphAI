"""Deterministic verification and optional judge-ensemble fallback."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable

from secgraphai.core import Evidence, Verdict


@dataclass(frozen=True)
class Validation:
    verdict: Verdict
    confidence: float
    evidence: tuple[Evidence, ...] = ()


class Validators:
    """Side-effect-free validators. A positive match is reproducible evidence."""

    @staticmethod
    def contains(output: str, marker: str) -> Validation:
        found = marker in output
        return Validation(Verdict.VERIFIED_VIOLATION if found else Verdict.PASS, 1.0,
                          (Evidence(kind="marker", description="Marker search", observed=marker),))

    @staticmethod
    def regex(output: str, pattern: str) -> Validation:
        found = re.search(pattern, output, re.MULTILINE) is not None
        return Validation(Verdict.VERIFIED_VIOLATION if found else Verdict.PASS, 1.0)

    @staticmethod
    def json_path(output: str, path: str, expected: object) -> Validation:
        try:
            value: object = json.loads(output)
            for part in path.strip("$.").split("."):
                value = value[int(part)] if isinstance(value, list) else value[part]  # type: ignore[index]
        except (ValueError, KeyError, IndexError, TypeError):
            return Validation(Verdict.INCONCLUSIVE, 0.0)
        return Validation(Verdict.VERIFIED_VIOLATION if value == expected else Verdict.PASS, 1.0)


Judge = Callable[[str, str], Awaitable[tuple[bool, float]]]


async def judge_ensemble(prompt: str, output: str, judges: Iterable[Judge]) -> Validation:
    """Majority vote; ties and unavailable judges never become a pass."""
    votes = [await judge(prompt, output) for judge in judges]
    if not votes:
        return Validation(Verdict.INCONCLUSIVE, 0.0)
    yes = sum(decision for decision, _ in votes)
    confidence = sum(score for _, score in votes) / len(votes)
    if yes * 2 == len(votes):
        return Validation(Verdict.INCONCLUSIVE, confidence)
    return Validation(Verdict.LIKELY_VIOLATION if yes * 2 > len(votes) else Verdict.PASS, confidence)
