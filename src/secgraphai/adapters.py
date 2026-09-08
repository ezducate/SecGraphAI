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
            mappings = record.get("mappings", {})
            safe_mappings = (
                {
                    str(key): [str(item) for item in value]
                    for key, value in mappings.items()
                    if isinstance(value, list)
                }
                if isinstance(mappings, dict)
                else {}
            )
            findings.append(
                Finding(
                    id=str(record.get("id", f"{self.name}-{index}"))[:200],
                    title=str(record.get("title", "External engine finding"))[:4_000],
                    severity=Severity(_severity(record.get("severity"))),
                    verdict=_verdict(record.get("verdict")),
                    confidence=_confidence(record.get("confidence")),
                    evidence=[
                        Evidence(
                            kind=f"adapter:{self.name}",
                            description="Normalized external security-engine result",
                            metadata={"engine": self.name, "raw_id": record.get("id")},
                        )
                    ],
                    mappings=safe_mappings,
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
    if normalized == "detect-secrets":
        results = output.get("results", {})
        return [
            {
                "id": f"{path}:{item.get('line_number', index)}",
                "title": str(item.get("type", "Potential secret")),
                "severity": "HIGH",
            }
            for path, values in (results.items() if isinstance(results, dict) else ())
            if isinstance(path, str)
            for index, item in enumerate(_records(values), 1)
        ]
    if normalized == "osv":
        vulnerabilities = _records(output.get("vulns"))
        for result in _records(output.get("results")):
            vulnerabilities.extend(_records(result.get("vulnerabilities")))
            for package in _records(result.get("packages")):
                vulnerabilities.extend(_records(package.get("vulnerabilities")))
        return [
            {
                "id": item.get("id"),
                "title": item.get("summary") or item.get("details") or "OSV vulnerability",
                "severity": _severity(item.get("severity", "high")),
                "mappings": {"aliases": item.get("aliases", [])},
            }
            for item in vulnerabilities
        ]
    if normalized == "presidio":
        return [
            {
                "id": f"{item.get('entity_type', 'PII')}:{item.get('start', index)}",
                "title": f"Detected {item.get('entity_type', 'sensitive data')}",
                "severity": "HIGH",
                "confidence": item.get("score", 0.5),
            }
            for index, item in enumerate(_records(output.get("results")), 1)
        ]
    if normalized == "llmguard" and output.get("is_valid") is False:
        return [
            {
                "id": output.get("scanner", "llmguard"),
                "title": output.get("reason", "LLM Guard rejected content"),
                "severity": "HIGH",
                "confidence": output.get("risk_score", 0.8),
            }
        ]
    if normalized == "modelscan":
        values = output.get("issues", output.get("results", []))
        return [
            _common_record(item, normalized, index)
            for index, item in enumerate(_records(values), 1)
        ]
    for key in ("results", "vulnerabilities", "issues", "failures", "probes", "tests"):
        records = _records(output.get(key))
        if records:
            return [_common_record(item, normalized, index) for index, item in enumerate(records, 1)]
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


def _common_record(item: dict[str, Any], engine: str, index: int) -> dict[str, Any]:
    identifier = next(
        (item[key] for key in ("id", "test_id", "test", "name", "type") if item.get(key)),
        f"{engine}-{index}",
    )
    title = next(
        (
            item[key]
            for key in ("title", "message", "description", "reason", "name")
            if item.get(key)
        ),
        f"{engine} finding",
    )
    status = str(item.get("status", item.get("verdict", ""))).casefold()
    verdict = "PASS" if status in {"pass", "passed", "safe"} else "LIKELY_VIOLATION"
    return {
        "id": str(identifier),
        "title": str(title),
        "severity": _severity(item.get("severity", item.get("level", item.get("risk")))),
        "verdict": verdict,
        "confidence": item.get("confidence", item.get("score", 0.5)),
        "mappings": item.get("mappings", {}),
    }


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


def _verdict(value: object) -> Verdict:
    try:
        return Verdict(str(value or "LIKELY_VIOLATION").upper())
    except ValueError:
        return Verdict.INCONCLUSIVE


def _confidence(value: object) -> float:
    candidate = value if value is not None else 0.5
    if not isinstance(candidate, (str, int, float)):
        return 0.0
    try:
        return min(1.0, max(0.0, float(candidate)))
    except ValueError:
        return 0.0
