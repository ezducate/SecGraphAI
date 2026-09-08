"""Stable finding and evidence schemas."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Verdict(StrEnum):
    # Public verdict label, not a credential.
    PASS = "PASS"  # noqa: S105  # nosec B105
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
    sha256: str | None = None


class Interaction(BaseModel):
    """Sanitized request/response trace captured during a security test."""

    model_config = ConfigDict(frozen=True)
    test_id: str
    request: dict[str, Any] = Field(default_factory=dict)
    response: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    model_calls: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)


class ScanManifest(BaseModel):
    """Inputs required to explain and reproduce a scan."""

    model_config = ConfigDict(frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    package_version: str = "1.0.0rc1"
    target_hash: str | None = None
    config_hash: str | None = None
    policy_hash: str | None = None
    pack_versions: dict[str, str] = Field(default_factory=dict)
    engine_versions: dict[str, str] = Field(default_factory=dict)
    seed: int | None = None
    artifact_hashes: dict[str, str] = Field(default_factory=dict)


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
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    component_ids: list[str] = Field(default_factory=list)
    known_exploited: bool | None = None
    fingerprint: str | None = None


class Report(BaseModel):
    model_config = ConfigDict(frozen=True)
    scan_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    interactions: list[Interaction] = Field(default_factory=list)
    manifest: ScanManifest = Field(default_factory=ScanManifest)
    graph: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)

    def summary(self) -> dict[str, int]:
        result = {verdict.value: 0 for verdict in Verdict}
        for finding in self.findings:
            result[finding.verdict.value] += 1
        # Errors may also have a corresponding finding; count each failed test once.
        result[Verdict.TEST_ERROR.value] = max(result[Verdict.TEST_ERROR.value], len(self.errors))
        return result

    def save(self, path: str | Path, format: str | None = None) -> None:
        """Save using the safe report renderer selected by the file extension."""
        from secgraphai.reporting import save

        save(self, path, format)
