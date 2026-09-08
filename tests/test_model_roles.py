from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from secgraphai import ModelRole, ModelRoles
from secgraphai.attacks import Attack, AttackPlanner
from secgraphai.core import Verdict
from secgraphai.scanner import ScanBudget, SecGraph
from secgraphai.validators import Validation, ValidationContext


@dataclass
class StubModel:
    response: str
    base_url: str
    model: str
    calls: list[list[dict[str, str]]] = field(default_factory=list)

    async def complete(self, messages, **parameters):
        self.calls.append(list(messages))
        return self.response


@pytest.mark.asyncio
async def test_four_model_roles_are_logically_independent_and_integrated():
    target = StubModel("safe output", "https://target.test", "target")
    attack = StubModel("mutated probe", "https://attack.test", "attack")
    judge = StubModel(
        '{"violation": true, "confidence": 0.9}', "https://judge.test", "judge"
    )
    remediation = StubModel("Enforce authorization before tool execution.", "https://fix.test", "fix")
    roles = ModelRoles(
        target=target,  # type: ignore[arg-type]
        attack=attack,  # type: ignore[arg-type]
        judges=(judge,),  # type: ignore[arg-type]
        remediation=remediation,  # type: ignore[arg-type]
    )
    scanner = SecGraph(roles=roles, budget=ScanBudget(max_requests=10))
    report = await scanner.scan(prompts=["probe"])
    assert len(report.findings) == 1
    assert report.findings[0].verdict == Verdict.LIKELY_VIOLATION
    assert report.findings[0].remediation == [
        "Enforce authorization before tool execution."
    ]
    assert target.calls and judge.calls and remediation.calls
    assert attack.calls == []
    assert roles.manifest()["target"] == {
        "base_url": "https://target.test",
        "model": "target",
    }
    assert {role.value for role in ModelRole} == {"target", "attack", "judge", "remediation"}


class ViolationValidator:
    def validate(self, context: ValidationContext) -> Validation:
        return Validation(Verdict.VERIFIED_VIOLATION, 1)


@pytest.mark.asyncio
async def test_attack_role_drives_adaptive_mutation_separately():
    attack_model = StubModel("a distinct generated probe", "https://attack.test", "attack")
    roles = ModelRoles(attack=attack_model)  # type: ignore[arg-type]
    attack = Attack("seed", "agent", "seed probe", tags=frozenset({"agent"}))
    scanner = SecGraph(
        roles=roles,
        planner=AttackPlanner([attack]),
        validators=[ViolationValidator()],
        budget=ScanBudget(max_requests=10),
    )
    seen: list[str] = []
    await scanner.scan_attacks(
        lambda prompt: seen.append(prompt) or "safe",
        features=["agent"],
        attack_budget=2,
    )
    assert seen == ["seed probe", "a distinct generated probe"]
    assert attack_model.calls


@pytest.mark.asyncio
async def test_invalid_judge_decision_becomes_test_error_not_pass():
    judge = StubModel("not-json", "https://judge.test", "judge")
    roles = ModelRoles(judges=(judge,))  # type: ignore[arg-type]
    report = await SecGraph(roles=roles).scan(lambda prompt: "safe", prompts=["probe"])
    assert report.summary()["TEST_ERROR"] == 1
