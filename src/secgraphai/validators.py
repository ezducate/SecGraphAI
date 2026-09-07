"""Deterministic verification and optional judge-ensemble fallback."""

from __future__ import annotations

import json
import re
import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable, Protocol

from secgraphai.core import Evidence, Verdict


@dataclass(frozen=True)
class Validation:
    verdict: Verdict
    confidence: float
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ValidationContext:
    output: str = ""
    status_code: int | None = None
    expected_status: frozenset[int] = frozenset()
    before: Any = None
    after: Any = None
    metadata: dict[str, Any] | None = None
    cost_usd: float = 0
    latency_ms: float = 0


class Validator(Protocol):
    def validate(self, context: ValidationContext) -> Validation: ...


def _evidence(kind: str, description: str, observed: str | None = None,
              **metadata: Any) -> Evidence:
    payload = json.dumps({"kind": kind, "description": description, "observed": observed,
                          "metadata": metadata}, sort_keys=True, default=str).encode()
    return Evidence(kind=kind, description=description, observed=observed, metadata=metadata,
                    sha256=hashlib.sha256(payload).hexdigest())


class Validators:
    """Side-effect-free validators. A positive match is reproducible evidence."""

    @staticmethod
    def contains(output: str, marker: str) -> Validation:
        found = marker in output
        return Validation(Verdict.VERIFIED_VIOLATION if found else Verdict.PASS, 1.0,
                          (_evidence("marker", "Marker search", marker),))

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


@dataclass(frozen=True)
class CanaryValidator:
    marker: str

    def validate(self, context: ValidationContext) -> Validation:
        return Validators.contains(context.output, self.marker)


@dataclass(frozen=True)
class AuthorizationValidator:
    forbidden_markers: tuple[str, ...] = ()

    def validate(self, context: ValidationContext) -> Validation:
        status_failed = bool(context.expected_status and context.status_code not in context.expected_status)
        marker_failed = any(marker in context.output for marker in self.forbidden_markers)
        failed = status_failed or marker_failed
        return Validation(Verdict.VERIFIED_VIOLATION if failed else Verdict.PASS, 1.0,
                          (_evidence("authorization", "Authorization expectation",
                                     str(context.status_code), expected=sorted(context.expected_status)),))


@dataclass(frozen=True)
class StateValidator:
    kind: str = "state"

    def validate(self, context: ValidationContext) -> Validation:
        changed = context.before != context.after
        return Validation(Verdict.VERIFIED_VIOLATION if changed else Verdict.PASS, 1.0,
                          (_evidence(self.kind, "Protected state comparison", repr(context.after)),))


class DatabaseStateValidator(StateValidator):
    kind: str = "database-state"


class FileStateValidator(StateValidator):
    kind: str = "file-state"

    @classmethod
    def snapshot(cls, path: str | Path) -> str | None:
        target = Path(path)
        return hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None


@dataclass(frozen=True)
class ToolInvocationValidator:
    allowed_tools: frozenset[str]

    def validate(self, context: ValidationContext) -> Validation:
        tools = set((context.metadata or {}).get("tools", []))
        unexpected = tools - self.allowed_tools
        return Validation(Verdict.VERIFIED_VIOLATION if unexpected else Verdict.PASS, 1.0,
                          (_evidence("tool", "Observed tool invocations", ",".join(sorted(tools)),
                                     unexpected=sorted(unexpected)),))


@dataclass(frozen=True)
class HTTPCallbackValidator:
    expected_token: str

    def validate(self, context: ValidationContext) -> Validation:
        callbacks = (context.metadata or {}).get("callbacks", [])
        found = self.expected_token in callbacks
        return Validation(Verdict.VERIFIED_VIOLATION if found else Verdict.PASS, 1.0,
                          (_evidence("http-callback", "Controlled callback observation",
                                     self.expected_token),))


@dataclass(frozen=True)
class JSONSchemaValidator:
    schema: dict[str, Any]

    def validate(self, context: ValidationContext) -> Validation:
        try:
            value = json.loads(context.output)
        except ValueError:
            return Validation(Verdict.VERIFIED_VIOLATION, 1.0,
                              (_evidence("json-schema", "Response is not JSON"),))
        required = self.schema.get("required", [])
        valid = isinstance(value, dict) and all(key in value for key in required)
        return Validation(Verdict.PASS if valid else Verdict.VERIFIED_VIOLATION, 1.0)


@dataclass(frozen=True)
class CrossTenantValidator:
    requesting_tenant: str
    forbidden_tenants: frozenset[str]

    def validate(self, context: ValidationContext) -> Validation:
        observed = str((context.metadata or {}).get("tenant", ""))
        failed = observed in self.forbidden_tenants or (
            bool(observed) and observed != self.requesting_tenant)
        return Validation(Verdict.VERIFIED_VIOLATION if failed else Verdict.PASS, 1.0,
                          (_evidence("tenant", "Observed tenant", observed),))


@dataclass(frozen=True)
class SecretLeakValidator:
    patterns: tuple[str, ...]

    def validate(self, context: ValidationContext) -> Validation:
        matched = next((pattern for pattern in self.patterns if re.search(pattern, context.output)), None)
        return Validation(Verdict.VERIFIED_VIOLATION if matched else Verdict.PASS, 1.0,
                          (_evidence("secret", "Secret pattern scan", matched),))


@dataclass(frozen=True)
class PolicyDecisionValidator:
    allowed_effects: frozenset[str]

    def validate(self, context: ValidationContext) -> Validation:
        effect = str((context.metadata or {}).get("effect", ""))
        return Validation(Verdict.PASS if effect in self.allowed_effects else Verdict.VERIFIED_VIOLATION,
                          1.0, (_evidence("policy", "Policy effect", effect),))


@dataclass(frozen=True)
class CostValidator:
    maximum_usd: float

    def validate(self, context: ValidationContext) -> Validation:
        return Validation(Verdict.VERIFIED_VIOLATION if context.cost_usd > self.maximum_usd
                          else Verdict.PASS, 1.0)


@dataclass(frozen=True)
class LatencyValidator:
    maximum_ms: float

    def validate(self, context: ValidationContext) -> Validation:
        return Validation(Verdict.VERIFIED_VIOLATION if context.latency_ms > self.maximum_ms
                          else Verdict.PASS, 1.0)


@dataclass(frozen=True)
class ResponseCodeValidator:
    expected: frozenset[int]

    def validate(self, context: ValidationContext) -> Validation:
        return Validation(Verdict.PASS if context.status_code in self.expected
                          else Verdict.VERIFIED_VIOLATION, 1.0)


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
