"""Runtime policy evaluation, explanation, simulation, and shadow mode."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Rule:
    id: str
    effect: Effect
    match: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass(frozen=True)
class Decision:
    effect: Effect
    rule_id: str
    reason: str
    enforced: bool


class PolicyEngine:
    def __init__(self, rules: Iterable[Rule], *, shadow: bool = False,
                 default: Effect = Effect.DENY) -> None:
        self.rules, self.shadow, self.default = list(rules), shadow, default

    def evaluate(self, event: dict[str, Any]) -> Decision:
        for rule in self.rules:
            if all(event.get(k) == v for k, v in rule.match.items()):
                return Decision(rule.effect, rule.id, rule.reason or "matched policy rule",
                                not self.shadow)
        return Decision(self.default, "default", "no policy rule matched", not self.shadow)

    def simulate(self, events: Iterable[dict[str, Any]]) -> list[Decision]:
        return [self.evaluate(event) for event in events]
