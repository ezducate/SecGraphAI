"""Declarative invariant models and deterministic flow evaluation."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from secgraphai.core import Evidence, Verdict


class Invariant(BaseModel):
    id: str
    description: str = ""
    source: dict[str, Any] = Field(default_factory=dict)
    destination: dict[str, Any] = Field(default_factory=dict)
    principal: dict[str, Any] = Field(default_factory=dict)
    tool: str | None = None
    when: dict[str, Any] = Field(default_factory=dict)
    requires: list[str] = Field(default_factory=list)
    expected: str = "deny"


def invariant(identifier: str, **values: Any) -> Invariant:
    return Invariant(id=identifier, **values)


class Evaluation(BaseModel):
    invariant_id: str
    verdict: Verdict
    reason: str
    evidence: list[Evidence] = Field(default_factory=list)


class InvariantEngine:
    def __init__(self, invariants: Iterable[Invariant] = ()) -> None:
        self.invariants = list(invariants)

    @classmethod
    def from_yaml(cls, path: str | Path) -> InvariantEngine:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict) or not isinstance(raw.get("invariants", []), list):
            raise ValueError("configuration must contain an invariants list")
        return cls(Invariant.model_validate(item) for item in raw.get("invariants", []))

    def evaluate_flow(
        self, source: dict[str, Any], destination: dict[str, Any]
    ) -> list[Evaluation]:
        results = []
        for rule in self.invariants:
            if _matches(rule.source, source) and _matches(rule.destination, destination):
                denied = rule.expected.lower() == "deny"
                verdict = Verdict.VERIFIED_VIOLATION if denied else Verdict.PASS
                reason = (
                    "observed flow violates deny invariant" if denied else "observed allowed flow"
                )
                results.append(
                    Evaluation(
                        invariant_id=rule.id,
                        verdict=verdict,
                        reason=reason,
                        evidence=[
                            Evidence(
                                kind="flow",
                                description=reason,
                                metadata={"source": source, "destination": destination},
                            )
                        ],
                    )
                )
        return results


def _matches(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())
