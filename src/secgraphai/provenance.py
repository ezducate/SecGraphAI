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


class Label(StrEnum):
    SYSTEM = "SYSTEM"
    USER = "USER"
    UNTRUSTED = "UNTRUSTED"
    EXTERNAL = "EXTERNAL"
    TOOL_DATA = "TOOL_DATA"
    RAG = "RAG"
    MEMORY = "MEMORY"
    # Provenance label, not a credential.
    SECRET = "SECRET"  # noqa: S105  # nosec B105
    PII = "PII"
    CONFIDENTIAL = "CONFIDENTIAL"
    MODEL_GENERATED = "MODEL_GENERATED"


class Confidence(StrEnum):
    EXACT = "exact"
    DERIVED = "derived"
    PROBABILISTIC = "probabilistic"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Provenance:
    sources: frozenset[str]
    trust: Trust = Trust.UNTRUSTED
    tenant: str | None = None
    sensitivity: frozenset[str] = frozenset()
    transformations: tuple[str, ...] = ()
    labels: frozenset[Label] = frozenset()
    confidence: Confidence = Confidence.EXACT

    def transformed(self, operation: str) -> Provenance:
        return replace(self, transformations=(*self.transformations, operation))

    def merge(self, other: Provenance) -> Provenance:
        trust = self.trust if self.trust == other.trust else Trust.MIXED
        tenant = self.tenant if self.tenant == other.tenant else None
        return Provenance(
            self.sources | other.sources,
            trust,
            tenant,
            self.sensitivity | other.sensitivity,
            self.transformations + other.transformations,
            self.labels | other.labels,
            self.confidence if self.confidence == other.confidence else Confidence.DERIVED,
        )


@dataclass(frozen=True)
class Tainted(Generic[T]):
    value: T
    provenance: Provenance

    def map(self, operation: str, function):
        return Tainted(function(self.value), self.provenance.transformed(operation))
