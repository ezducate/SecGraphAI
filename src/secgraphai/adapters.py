"""Permission-gated adapters for external security engines."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from secgraphai.core import Evidence, Finding, Severity, Verdict
from secgraphai.plugins import PluginManifest, run_plugin

SUPPORTED_ENGINES = frozenset(
    {
        "pyrit",
        "garak",
        "promptfoo",
        "deepteam",
        "schemathesis",
        "llmguard",
        "presidio",
        "semgrep",
        "codeql",
        "zap",
        "nuclei",
        "detect-secrets",
        "pip-audit",
        "osv",
        "modelscan",
    }
)


@dataclass(frozen=True)
class Adapter:
    name: str
    manifest: PluginManifest

    def __post_init__(self) -> None:
        if self.name.casefold() not in SUPPORTED_ENGINES:
            raise ValueError(f"unsupported security engine: {self.name}")

    def run(
        self, target: dict[str, Any], *, allowed_permissions: Iterable[str] = ()
    ) -> list[Finding]:
        output = run_plugin(
            self.manifest, {"target": target}, allowed_permissions=allowed_permissions
        )
        records = output.get("findings", [])
        if not isinstance(records, list):
            raise ValueError("adapter findings must be a list")
        findings = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            findings.append(
                Finding(
                    id=str(record.get("id", f"{self.name}-{index}")),
                    title=str(record.get("title", "External engine finding")),
                    severity=Severity(str(record.get("severity", "MEDIUM")).upper()),
                    verdict=Verdict(str(record.get("verdict", "LIKELY_VIOLATION")).upper()),
                    confidence=float(record.get("confidence", 0.5)),
                    evidence=[
                        Evidence(
                            kind=f"adapter:{self.name}",
                            description="Normalized external security-engine result",
                            metadata={"engine": self.name, "raw_id": record.get("id")},
                        )
                    ],
                    mappings=dict(record.get("mappings", {})),
                )
            )
        return findings
