"""Offline-first OWASP, CVE, CVSS, SSVC, SBOM, and security-gate primitives."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from importlib import metadata
from pathlib import Path
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version

from secgraphai.core import Finding


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    purl: str | None = None
    ecosystem: str = "pypi"
    cpe: str | None = None


@dataclass(frozen=True)
class CVSSMetric:
    version: str
    vector: str
    base_score: float
    threat_score: float | None = None
    environmental_score: float | None = None


@dataclass(frozen=True)
class SSVCDecision:
    decision: str
    exploitation: str | None = None
    automatable: bool | None = None
    technical_impact: str | None = None


class Reachability(StrEnum):
    PRESENT = "PRESENT"
    AFFECTED = "AFFECTED"
    POTENTIALLY_REACHABLE = "POTENTIALLY_REACHABLE"
    REACHABLE = "REACHABLE"
    EXPLOITABILITY_UNVERIFIED = "EXPLOITABILITY_UNVERIFIED"
    VERIFIED_IN_LAB = "VERIFIED_IN_LAB"
    MITIGATED = "MITIGATED"
    NOT_AFFECTED = "NOT_AFFECTED"


@dataclass(frozen=True)
class Vulnerability:
    id: str
    component: str
    severity: float
    known_exploited: bool = False
    reachable: bool | None = None
    aliases: frozenset[str] = frozenset()
    description: str = ""
    cwe_ids: frozenset[str] = frozenset()
    cvss: tuple[CVSSMetric, ...] = ()
    ssvc: tuple[SSVCDecision, ...] = ()
    status: Reachability = Reachability.PRESENT
    affected_versions: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    @property
    def priority(self) -> float:
        reachability = 1.0 if self.reachable else (0.7 if self.reachable is None else 0.25)
        return round(
            min(10.0, self.severity * reachability + (2 if self.known_exploited else 0)), 2
        )


def parse_cyclonedx(document: dict[str, Any]) -> list[Component]:
    return [
        Component(
            str(c.get("name", "")),
            str(c.get("version", "")),
            c.get("purl"),
            str(c.get("properties", [{}])[0].get("value", "pypi"))
            if c.get("properties")
            else "pypi",
            c.get("cpe"),
        )
        for c in document.get("components", [])
        if isinstance(c, dict) and c.get("name")
    ]


def generate_cyclonedx(components: Iterable[Component]) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": [{"vendor": "SecGraphAI", "name": "secgraphai"}],
        },
        "components": [
            {
                key: value
                for key, value in {
                    "type": "library",
                    "name": item.name,
                    "version": item.version,
                    "purl": item.purl,
                    "cpe": item.cpe,
                }.items()
                if value is not None
            }
            for item in components
        ],
    }


def parse_spdx(document: dict[str, Any]) -> list[Component]:
    """Parse package identity from an SPDX 2.x JSON document without fetching references."""
    result = []
    for package in document.get("packages", []):
        if not isinstance(package, dict) or not package.get("name"):
            continue
        references = package.get("externalRefs", [])
        purl = next(
            (
                item.get("referenceLocator")
                for item in references
                if isinstance(item, dict)
                and str(item.get("referenceType", "")).casefold() == "purl"
            ),
            None,
        )
        cpe = next(
            (
                item.get("referenceLocator")
                for item in references
                if isinstance(item, dict) and "cpe" in str(item.get("referenceType", "")).casefold()
            ),
            None,
        )
        result.append(
            Component(
                str(package["name"]),
                str(package.get("versionInfo", "")),
                str(purl) if purl else None,
                cpe=str(cpe) if cpe else None,
            )
        )
    return result


def generate_spdx(components: Iterable[Component]) -> dict[str, Any]:
    """Generate a compact SPDX 2.3 JSON software bill of materials."""
    packages = []
    for index, item in enumerate(components, 1):
        references = []
        if item.purl:
            references.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": item.purl,
                }
            )
        if item.cpe:
            references.append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": item.cpe,
                }
            )
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{index}",
                "name": item.name,
                "versionInfo": item.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": references,
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "SecGraphAI SBOM",
        "documentNamespace": "https://secgraphai.dev/spdx/local",
        "creationInfo": {
            "created": datetime.now(UTC).isoformat(),
            "creators": ["Tool: SecGraphAI"],
        },
        "packages": packages,
    }


def enrich_known_exploited(
    vulnerabilities: Iterable[Vulnerability], document: dict[str, Any]
) -> list[Vulnerability]:
    """Apply CISA KEV-style catalog flags from already-downloaded JSON data."""
    exploited = {
        str(item.get("cveID"))
        for item in document.get("vulnerabilities", [])
        if isinstance(item, dict) and item.get("cveID")
    }
    return [
        replace(item, known_exploited=item.known_exploited or item.id in exploited)
        for item in vulnerabilities
    ]


def installed_components() -> list[Component]:
    result = []
    for distribution in metadata.distributions():
        try:
            name = distribution.metadata["Name"]
        except KeyError:
            name = None
        if name:
            result.append(
                Component(
                    name,
                    distribution.version,
                    f"pkg:pypi/{name.lower().replace('_', '-')}@{distribution.version}",
                )
            )
    return sorted(result, key=lambda item: item.name.casefold())


class VulnerabilityCache:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def save(self, vulnerabilities: Iterable[Vulnerability]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = [
            {
                "id": v.id,
                "component": v.component,
                "severity": v.severity,
                "known_exploited": v.known_exploited,
                "reachable": v.reachable,
                "aliases": sorted(v.aliases),
                "description": v.description,
                "cwe_ids": sorted(v.cwe_ids),
                "cvss": [item.__dict__ for item in v.cvss],
                "ssvc": [item.__dict__ for item in v.ssvc],
                "status": v.status.value,
                "affected_versions": list(v.affected_versions),
                "references": list(v.references),
            }
            for v in vulnerabilities
        ]
        handle, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".cve-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(document, stream, sort_keys=True)
            Path(temporary).replace(self.path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def search(self, query: str) -> list[Vulnerability]:
        if not self.path.exists():
            return []
        records = [
            _vulnerability_from_dict(item)
            for item in json.loads(self.path.read_text(encoding="utf-8"))
        ]
        needle = query.casefold()
        return [
            v
            for v in records
            if needle in v.id.casefold()
            or needle in v.component.casefold()
            or any(needle in alias.casefold() for alias in v.aliases)
        ]


def security_gate(
    vulnerabilities: Iterable[Vulnerability],
    *,
    max_priority: float = 8,
    deny_known_exploited: bool = True,
) -> tuple[bool, list[str]]:
    reasons = [
        v.id
        for v in vulnerabilities
        if v.priority >= max_priority or (deny_known_exploited and v.known_exploited)
    ]
    return not reasons, reasons


def affected(component: Component, vulnerability: Vulnerability) -> bool | None:
    if component.name.casefold() != vulnerability.component.casefold():
        return False
    if not vulnerability.affected_versions:
        return None
    try:
        installed = Version(component.version)
    except InvalidVersion:
        return None
    for expression in vulnerability.affected_versions:
        operator = next(
            (item for item in (">=", "<=", "!=", "==", ">", "<") if expression.startswith(item)),
            "==",
        )
        try:
            expected = Version(expression.removeprefix(operator).strip())
        except InvalidVersion:
            continue
        if {
            "==": installed == expected,
            "!=": installed != expected,
            ">=": installed >= expected,
            "<=": installed <= expected,
            ">": installed > expected,
            "<": installed < expected,
        }[operator]:
            return True
    return False


def correlate_finding(finding: Finding, vulnerabilities: Iterable[Vulnerability]) -> Finding:
    matches = [
        item
        for item in vulnerabilities
        if item.id in finding.cve_ids or item.component in finding.component_ids
    ]
    return finding.model_copy(
        update={
            "cve_ids": sorted(set(finding.cve_ids) | {item.id for item in matches}),
            "cwe_ids": sorted(
                set(finding.cwe_ids) | {cwe for item in matches for cwe in item.cwe_ids}
            ),
            "known_exploited": any(item.known_exploited for item in matches) if matches else None,
        }
    )


def parse_nvd(document: dict[str, Any]) -> list[Vulnerability]:
    results = []
    for entry in document.get("vulnerabilities", []):
        cve = entry.get("cve", {}) if isinstance(entry, dict) else {}
        descriptions = cve.get("descriptions", [])
        description = next(
            (item.get("value", "") for item in descriptions if item.get("lang") == "en"), ""
        )
        metrics = []
        for name, values in cve.get("metrics", {}).items():
            for value in values if isinstance(values, list) else []:
                data = value.get("cvssData", {})
                if data.get("baseScore") is not None:
                    metrics.append(
                        CVSSMetric(
                            str(data.get("version", name)),
                            str(data.get("vectorString", "")),
                            float(data["baseScore"]),
                            data.get("threatScore"),
                            data.get("environmentalScore"),
                        )
                    )
        weaknesses = frozenset(
            item.get("value")
            for group in cve.get("weaknesses", [])
            for item in group.get("description", [])
            if str(item.get("value", "")).startswith("CWE-")
        )
        references = tuple(
            str(item.get("url")) for item in cve.get("references", []) if item.get("url")
        )
        severity = max((item.base_score for item in metrics), default=0)
        results.append(
            Vulnerability(
                str(cve.get("id", "")),
                "unknown",
                severity,
                aliases=frozenset(),
                description=description,
                cwe_ids=weaknesses,
                cvss=tuple(metrics),
                references=references,
            )
        )
    return [item for item in results if item.id]


class NVDClient:
    endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        *,
        api_key_env: str = "NVD_API_KEY",
        timeout: float = 30,
        max_response_bytes: int = 20_000_000,
    ) -> None:
        self.api_key_env, self.timeout, self.max_response_bytes = (
            api_key_env,
            timeout,
            max_response_bytes,
        )

    async def search(self, query: str) -> list[Vulnerability]:
        headers = (
            {"apiKey": os.environ[self.api_key_env]} if os.environ.get(self.api_key_env) else {}
        )
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            response = await client.get(
                self.endpoint,
                params={"keywordSearch": query, "resultsPerPage": 2000},
                headers=headers,
            )
            response.raise_for_status()
            if len(response.content) > self.max_response_bytes:
                raise ValueError("NVD response exceeds configured limit")
        return parse_nvd(response.json())


def _vulnerability_from_dict(item: dict[str, Any]) -> Vulnerability:
    return Vulnerability(
        **{
            **item,
            "aliases": frozenset(item.get("aliases", [])),
            "cwe_ids": frozenset(item.get("cwe_ids", [])),
            "cvss": tuple(CVSSMetric(**value) for value in item.get("cvss", [])),
            "ssvc": tuple(SSVCDecision(**value) for value in item.get("ssvc", [])),
            "status": Reachability(item.get("status", "PRESENT")),
            "affected_versions": tuple(item.get("affected_versions", [])),
            "references": tuple(item.get("references", [])),
        }
    )


OWASP_PROFILES = {
    "llm-2026": frozenset(f"LLM{i:02d}" for i in range(1, 11)),
    "api-2023": frozenset(f"API{i}" for i in range(1, 11)),
    "web-2025": frozenset(f"A{i:02d}" for i in range(1, 11)),
    "agentic-2026": frozenset(f"ASI{i:02d}" for i in range(1, 11)),
}


def coverage(profile: str, observed: Iterable[str]) -> dict[str, object]:
    required, covered = OWASP_PROFILES[profile], frozenset(observed) & OWASP_PROFILES[profile]
    return {
        "profile": profile,
        "covered": sorted(covered),
        "missing": sorted(required - covered),
        "percent": round(100 * len(covered) / len(required), 1),
    }
