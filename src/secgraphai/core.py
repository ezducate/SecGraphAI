"""Stable finding and evidence schemas."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Verdict(StrEnum):
    PASS = "PASS"
    VERIFIED_VIOLATION = "VERIFIED_VIOLATION"
    LIKELY_VIOLATION = "LIKELY_VIOLATION"
    BLOCKED_BY_CONTROL = "BLOCKED_BY_CONTROL"
    INCONCLUSIVE = "INCONCLUSIVE"
    TEST_ERROR = "TEST_ERROR"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"

    @property
    def passed(self) -> bool:
        return self is Verdict.PASS


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: str
    description: str
    observed: str | None = None
    deterministic: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    title: str
    severity: Severity
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    actor: str | None = None
    asset: str | None = None
    invariant: str | None = None
    attack_path: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    mappings: dict[str, list[str]] = Field(default_factory=dict)


class Report(BaseModel):
    model_config = ConfigDict(frozen=True)
    scan_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def summary(self) -> dict[str, int]:
        result = {verdict.value: 0 for verdict in Verdict}
        for finding in self.findings:
            result[finding.verdict.value] += 1
        # Errors may also have a corresponding finding; count each failed test once.
        result[Verdict.TEST_ERROR.value] = max(result[Verdict.TEST_ERROR.value], len(self.errors))
        return result
