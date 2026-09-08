"""Runtime policy evaluation, explanation, simulation, and shadow mode."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"
    RATE_LIMIT = "rate_limit"
    SANDBOX = "sandbox"
    LOG = "log"
    TRANSFORM = "transform"


@dataclass(frozen=True)
class Rule:
    id: str
    effect: Effect
    match: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    priority: int = 0
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    effect: Effect
    rule_id: str
    reason: str
    enforced: bool
    explanation: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SimulationSummary:
    total: int
    would_block: int
    would_require_approval: int
    allowed: int
    decisions: tuple[Decision, ...]


class PolicyEngine:
    def __init__(
        self, rules: Iterable[Rule], *, shadow: bool = False, default: Effect = Effect.DENY
    ) -> None:
        self.rules = sorted(rules, key=lambda rule: (-rule.priority, rule.id))
        self.shadow, self.default = shadow, default

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict) or not isinstance(raw.get("rules", []), list):
            raise ValueError("policy document must contain a rules list")
        rules = []
        for item in raw["rules"]:
            if not isinstance(item, dict):
                raise ValueError("policy rule must be an object")
            rules.append(
                Rule(
                    id=str(item["id"]),
                    effect=Effect(item["effect"]),
                    match=dict(item.get("match", {})),
                    reason=str(item.get("reason", "")),
                    priority=int(item.get("priority", 0)),
                    options=dict(item.get("options", {})),
                )
            )
        mode = str(raw.get("mode", "enforce")).lower()
        if mode not in {"enforce", "shadow"}:
            raise ValueError("policy mode must be enforce or shadow")
        return cls(rules, shadow=mode == "shadow", default=Effect(raw.get("default", "deny")))

    def evaluate(self, event: dict[str, Any]) -> Decision:
        for rule in self.rules:
            if all(_condition(event, key, value) for key, value in rule.match.items()):
                explanation = tuple(f"{key} matched {value!r}" for key, value in rule.match.items())
                return Decision(
                    rule.effect,
                    rule.id,
                    rule.reason or "matched policy rule",
                    not self.shadow,
                    explanation,
                    dict(rule.options),
                )
        return Decision(
            self.default,
            "default",
            "no policy rule matched",
            not self.shadow,
            ("default policy applied",),
        )

    def simulate(self, events: Iterable[dict[str, Any]]) -> list[Decision]:
        return [self.evaluate(event) for event in events]

    def summarize(self, events: Iterable[dict[str, Any]]) -> SimulationSummary:
        decisions = tuple(self.simulate(events))
        blocked = sum(item.effect == Effect.DENY for item in decisions)
        approvals = sum(item.effect == Effect.REQUIRE_APPROVAL for item in decisions)
        return SimulationSummary(
            len(decisions), blocked, approvals, len(decisions) - blocked - approvals, decisions
        )


def _lookup(event: dict[str, Any], key: str) -> Any:
    value: Any = event
    for part in key.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _condition(event: dict[str, Any], expression: str, expected: Any) -> bool:
    operators = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "contains"}
    key, separator, candidate = expression.rpartition("__")
    operator = candidate if separator and candidate in operators else "eq"
    key = key if operator != "eq" or separator else expression
    actual = _lookup(event, key)
    try:
        return {
            "eq": lambda: actual == expected,
            "ne": lambda: actual != expected,
            "gt": lambda: actual > expected,
            "gte": lambda: actual >= expected,
            "lt": lambda: actual < expected,
            "lte": lambda: actual <= expected,
            "in": lambda: actual in expected,
            "contains": lambda: expected in actual,
        }[operator]()
    except (TypeError, KeyError):
        return False
