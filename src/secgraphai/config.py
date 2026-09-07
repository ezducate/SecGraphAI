"""Validated configuration with safe defaults."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


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


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Mode = Mode.SAFE
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    invariants: list[dict[str, object]] = Field(default_factory=list)
    dashboard: dict[str, object] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(raw or {})
