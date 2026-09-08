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

ENGINE_CAPABILITIES = {
    "pyrit": "prompt-injection",
    "garak": "model-probes",
    "promptfoo": "prompt-evaluation",
    "deepteam": "red-team",
    "schemathesis": "api-property-testing",
    "llmguard": "content-filtering",
    "presidio": "pii-detection",
    "semgrep": "static-analysis",
    "codeql": "static-analysis",
    "zap": "dynamic-api-testing",
    "nuclei": "template-scanning",
    "detect-secrets": "secret-detection",
    "pip-audit": "dependency-vulnerabilities",
    "osv": "dependency-vulnerabilities",
    "modelscan": "model-supply-chain",
}


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
        records = normalize_engine_output(self.name, output)
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


def normalize_engine_output(name: str, output: dict[str, object]) -> list[dict[str, Any]]:
    """Normalize native JSON from supported engines without executing or fetching references."""
    direct = output.get("findings")
    if isinstance(direct, list):
        return [item for item in direct if isinstance(item, dict)]
    normalized = name.casefold()
    if normalized == "semgrep":
        return [
            {
                "id": item.get("check_id"),
                "title": item.get("extra", {}).get("message", "Semgrep finding"),
                "severity": _severity(item.get("extra", {}).get("severity")),
                "mappings": {"CWE": item.get("extra", {}).get("metadata", {}).get("cwe", [])},
            }
            for item in _records(output.get("results"))
            if isinstance(item, dict) and isinstance(item.get("extra"), dict)
        ]
    if normalized in {"codeql", "zap"}:
        sarif = _sarif_records(output)
        if sarif:
            return sarif
    if normalized == "zap":
        return [
            {
                "id": alert.get("pluginid"),
                "title": alert.get("alert", "ZAP finding"),
                "severity": {"3": "HIGH", "2": "MEDIUM", "1": "LOW"}.get(
                    str(alert.get("riskcode")), "INFO"
                ),
            }
            for site in _records(output.get("site"))
            for alert in _records(site.get("alerts"))
        ]
    if normalized == "nuclei":
        values = output.get("results", output.get("templates", []))
        return [
            {
                "id": item.get("template-id"),
                "title": item.get("info", {}).get("name", "Nuclei finding"),
                "severity": _severity(item.get("info", {}).get("severity")),
            }
            for item in _records(values)
            if isinstance(item.get("info"), dict)
        ]
    if normalized == "pip-audit":
        dependencies = output.get("dependencies", [])
        return [
            {
                "id": vulnerability.get("id"),
                "title": f"{dependency.get('name')} {dependency.get('version')} is vulnerable",
                "severity": "HIGH",
                "mappings": {"aliases": vulnerability.get("aliases", [])},
            }
            for dependency in _records(dependencies)
            for vulnerability in _records(dependency.get("vulns"))
        ]
    return []


def _sarif_records(output: dict[str, object]) -> list[dict[str, Any]]:
    records = []
    for run in _records(output.get("runs")):
        for item in _records(run.get("results")):
            message = item.get("message", {})
            records.append(
                {
                    "id": item.get("ruleId"),
                    "title": message.get("text", "SARIF finding")
                    if isinstance(message, dict)
                    else str(message),
                    "severity": _severity(item.get("level")),
                }
            )
    return records


def _records(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _severity(value: object) -> str:
    return {
        "critical": "CRITICAL",
        "error": "HIGH",
        "high": "HIGH",
        "warning": "MEDIUM",
        "medium": "MEDIUM",
        "low": "LOW",
        "note": "LOW",
        "info": "INFO",
    }.get(str(value).casefold(), "MEDIUM")
