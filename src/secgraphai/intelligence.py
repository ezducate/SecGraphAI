"""Offline-first OWASP, CVE, CVSS, SSVC, SBOM, and security-gate primitives."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    purl: str | None = None


@dataclass(frozen=True)
class Vulnerability:
    id: str
    component: str
    severity: float
    known_exploited: bool = False
    reachable: bool | None = None
    aliases: frozenset[str] = frozenset()

    @property
    def priority(self) -> float:
        reachability = 1.0 if self.reachable else (0.7 if self.reachable is None else 0.25)
        return round(min(10.0, self.severity * reachability + (2 if self.known_exploited else 0)), 2)


def parse_cyclonedx(document: dict[str, Any]) -> list[Component]:
    return [Component(str(c.get("name", "")), str(c.get("version", "")), c.get("purl"))
            for c in document.get("components", []) if isinstance(c, dict) and c.get("name")]


class VulnerabilityCache:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def save(self, vulnerabilities: Iterable[Vulnerability]) -> None:
        self.path.write_text(json.dumps([{"id": v.id, "component": v.component,
            "severity": v.severity, "known_exploited": v.known_exploited,
            "reachable": v.reachable, "aliases": sorted(v.aliases)} for v in vulnerabilities]),
            encoding="utf-8")

    def search(self, query: str) -> list[Vulnerability]:
        if not self.path.exists():
            return []
        records = [Vulnerability(**{**item, "aliases": frozenset(item.get("aliases", []))})
                   for item in json.loads(self.path.read_text(encoding="utf-8"))]
        needle = query.casefold()
        return [v for v in records if needle in v.id.casefold() or needle in v.component.casefold()
                or any(needle in alias.casefold() for alias in v.aliases)]


def security_gate(vulnerabilities: Iterable[Vulnerability], *, max_priority: float = 8,
                  deny_known_exploited: bool = True) -> tuple[bool, list[str]]:
    reasons = [v.id for v in vulnerabilities
               if v.priority >= max_priority or (deny_known_exploited and v.known_exploited)]
    return not reasons, reasons


OWASP_PROFILES = {
    "llm-2026": frozenset(f"LLM{i:02d}" for i in range(1, 11)),
    "api-2023": frozenset(f"API{i}" for i in range(1, 11)),
    "web-2025": frozenset(f"A{i:02d}" for i in range(1, 11)),
    "agentic-2026": frozenset(f"ASI{i:02d}" for i in range(1, 11)),
}


def coverage(profile: str, observed: Iterable[str]) -> dict[str, object]:
    required, covered = OWASP_PROFILES[profile], frozenset(observed) & OWASP_PROFILES[profile]
    return {"profile": profile, "covered": sorted(covered), "missing": sorted(required - covered),
            "percent": round(100 * len(covered) / len(required), 1)}
