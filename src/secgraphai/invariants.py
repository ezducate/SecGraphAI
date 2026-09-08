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
        if (
            not isinstance(raw, dict)
            or "invariants" not in raw
            or not isinstance(raw.get("invariants"), list)
        ):
            raise ValueError("configuration must contain an invariants list")
        return cls(Invariant.model_validate(item) for item in raw.get("invariants", []))

    def evaluate_flow(
        self,
        source: dict[str, Any],
        destination: dict[str, Any],
        *,
        principal: dict[str, Any] | None = None,
        tool: str | None = None,
        context: dict[str, Any] | None = None,
        controls: Iterable[str] = (),
    ) -> list[Evaluation]:
        """Evaluate a fully observed flow against applicable invariant clauses."""
        principal = dict(principal or {})
        context = dict(context or {})
        observed_controls = frozenset({controls} if isinstance(controls, str) else map(str, controls))
        results = []
        for rule in self.invariants:
            if not _applies(rule, source, destination, principal, tool, context):
                continue
            expected = rule.expected.casefold()
            missing = sorted(set(rule.requires) - observed_controls)
            unequal = _principal_mismatches(rule.principal, principal, destination)
            if expected == "deny":
                verdict = Verdict.VERIFIED_VIOLATION
                reason = "observed flow violates deny invariant"
            elif expected == "equal":
                verdict = Verdict.VERIFIED_VIOLATION if unequal else Verdict.PASS
                reason = (
                    "principal and resource attributes differ"
                    if unequal
                    else "principal and resource attributes are equal"
                )
            elif rule.requires:
                verdict = Verdict.VERIFIED_VIOLATION if missing else Verdict.PASS
                reason = (
                    f"required controls are missing: {', '.join(missing)}"
                    if missing
                    else "all required controls were observed"
                )
            else:
                verdict = Verdict.PASS
                reason = "observed flow satisfies invariant"
            results.append(
                Evaluation(
                    invariant_id=rule.id,
                    verdict=verdict,
                    reason=reason,
                    evidence=[
                        Evidence(
                            kind="flow",
                            description=reason,
                            metadata={
                                "source": source,
                                "destination": destination,
                                "principal": principal,
                                "tool": tool,
                                "context": context,
                                "controls": sorted(observed_controls),
                                "missing_controls": missing,
                                "unequal": unequal,
                            },
                        )
                    ],
                )
            )
        return results


def _matches(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def _applies(
    rule: Invariant,
    source: dict[str, Any],
    destination: dict[str, Any],
    principal: dict[str, Any],
    tool: str | None,
    context: dict[str, Any],
) -> bool:
    principal_literals = {
        key: value
        for key, value in rule.principal.items()
        if not (isinstance(value, str) and value.startswith("$resource."))
    }
    return (
        _matches(rule.source, source)
        and _matches(rule.destination, destination)
        and _matches(principal_literals, principal)
        and (rule.tool is None or rule.tool == tool)
        and _matches_conditions(rule.when, context)
    )


def _matches_conditions(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    operators = {
        "_gte": lambda left, right: left >= right,
        "_lte": lambda left, right: left <= right,
        "_gt": lambda left, right: left > right,
        "_lt": lambda left, right: left < right,
        "_eq": lambda left, right: left == right,
    }
    for key, value in expected.items():
        operator = next((suffix for suffix in operators if key.endswith(suffix)), None)
        field = key[: -len(operator)] if operator else key
        observed = actual.get(field)
        if observed is None:
            return False
        try:
            matched = operators[operator](observed, value) if operator else observed == value
        except TypeError:
            return False
        if not matched:
            return False
    return True


def _principal_mismatches(
    expected: dict[str, Any], principal: dict[str, Any], resource: dict[str, Any]
) -> list[str]:
    mismatches = []
    for key, value in expected.items():
        if isinstance(value, str) and value.startswith("$resource."):
            resource_key = value.removeprefix("$resource.")
            if principal.get(key) != resource.get(resource_key):
                mismatches.append(key)
        elif principal.get(key) != value:
            mismatches.append(key)
    return mismatches
