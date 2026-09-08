"""Validated configuration with safe defaults."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Mode(StrEnum):
    PASSIVE = "PASSIVE"
    SAFE = "SAFE"
    LAB = "LAB"
    CUSTOM = "CUSTOM"


class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost"])
    allowed_ports: list[int] = Field(default_factory=lambda: [8000])
    max_total_requests: int = Field(default=100, ge=1, le=1_000_000)
    max_requests_per_second: float = Field(default=5, gt=0, le=10_000)
    max_duration_seconds: float = Field(default=120, gt=0, le=86_400)
    prohibit: list[str] = Field(default_factory=lambda: ["destructive_write", "account_deletion"])
    blocked_networks: list[str] = Field(
        default_factory=lambda: [
            "0.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "::1/128",
            "fe80::/10",
        ]
    )


class BudgetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_requests: int = Field(default=100, ge=1)
    max_duration_seconds: float = Field(default=120, gt=0)
    max_cost_usd: float | None = Field(default=None, ge=0)
    max_input_tokens: int | None = Field(default=None, ge=0)
    max_output_tokens: int | None = Field(default=None, ge=0)


class ActorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token_env: str | None = None
    tenant: str | None = None
    role: str | None = None
    permissions: list[str] = Field(default_factory=list)

    @field_validator("token_env")
    @classmethod
    def token_is_reference(cls, value: str | None) -> str | None:
        if value is not None and not value.replace("_", "").isalnum():
            raise ValueError("token_env must be an environment variable name")
        return value


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Mode = Mode.SAFE
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    invariants: list[dict[str, object]] = Field(default_factory=list)
    dashboard: dict[str, object] = Field(default_factory=dict)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    actors: dict[str, ActorConfig] = Field(default_factory=dict)
    policies: list[dict[str, object]] = Field(default_factory=list)
    attack_packs: list[str] = Field(default_factory=list)
    seed: int = 0

    @classmethod
    def load(cls, path: str | Path) -> Config:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(raw or {})
