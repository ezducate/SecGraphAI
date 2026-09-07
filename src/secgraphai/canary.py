"""Synthetic deterministic evidence canaries."""

from __future__ import annotations

import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class Canary:
    value: str
    kind: str
    tenant: str | None = None

    def observed_in(self, content: str | bytes) -> bool:
        text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
        return self.value in text


class CanaryFactory:
    def _make(self, kind: str, tenant: str | None = None) -> Canary:
        token = secrets.token_hex(6).upper()
        return Canary(f"SG-CANARY-{kind.upper()}-{token}", kind, tenant)

    def secret(self) -> Canary:
        return self._make("secret")

    def record(self, *, tenant: str) -> Canary:
        return self._make("record", tenant)

