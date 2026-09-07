"""Provenance and taint propagation for values crossing trust boundaries."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Generic, TypeVar

T = TypeVar("T")


class Trust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    MIXED = "mixed"


@dataclass(frozen=True)
class Provenance:
    sources: frozenset[str]
    trust: Trust = Trust.UNTRUSTED
    tenant: str | None = None
    sensitivity: frozenset[str] = frozenset()
    transformations: tuple[str, ...] = ()

    def transformed(self, operation: str) -> "Provenance":
        return replace(self, transformations=(*self.transformations, operation))

    def merge(self, other: "Provenance") -> "Provenance":
        trust = self.trust if self.trust == other.trust else Trust.MIXED
        tenant = self.tenant if self.tenant == other.tenant else None
        return Provenance(self.sources | other.sources, trust, tenant,
                          self.sensitivity | other.sensitivity,
                          self.transformations + other.transformations)


@dataclass(frozen=True)
class Tainted(Generic[T]):
    value: T
    provenance: Provenance
