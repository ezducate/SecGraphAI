"""Reproducible scan artifacts, baselines, regressions, and CI report formats."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

# XML is generated only; no untrusted XML is parsed by this module.
from xml.etree.ElementTree import Element, SubElement, tostring  # nosec B405

from secgraphai.core import Finding, Report, Severity, Verdict
from secgraphai.security import redact


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def artifact_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(redact(value))).hexdigest()


def finalize_report(
    report: Report, *, configuration: Any = None, policies: Any = None, test_definitions: Any = None
) -> Report:
    findings = []
    for item in report.findings:
        evidence = [
            value
            if value.sha256
            else value.model_copy(
                update={"sha256": artifact_hash(value.model_dump(mode="json", exclude={"sha256"}))}
            )
            for value in item.evidence
        ]
        findings.append(
            item.model_copy(
                update={
                    "evidence": evidence,
                    "fingerprint": item.fingerprint or fingerprint(item),
                }
            )
        )
    artifacts = {
        "configuration": configuration or {},
        "policies": policies or [],
        "tests": test_definitions or [],
        "evidence": [
            evidence.model_dump(mode="json") for item in findings for evidence in item.evidence
        ],
        "findings": [item.model_dump(mode="json") for item in findings],
        "interactions": [item.model_dump(mode="json") for item in report.interactions],
        "graph": report.graph,
        "limitations": report.limitations,
    }
    hashes = {name: artifact_hash(value) for name, value in artifacts.items()}
    manifest = report.manifest.model_copy(
        update={
            "artifact_hashes": hashes,
            "config_hash": hashes["configuration"],
            "policy_hash": hashes["policies"],
            "environment": {
                "python": platform.python_version(),
                "implementation": platform.python_implementation(),
                "platform": sys.platform,
            },
        }
    )
    return report.model_copy(update={"findings": findings, "manifest": manifest})


def fingerprint(finding: Finding) -> str:
    stable = [finding.title, finding.asset or "", finding.invariant or "", *finding.attack_path]
    return hashlib.sha256("\0".join(stable).encode()).hexdigest()[:24]


def diff_reports(baseline: Report, current: Report) -> dict[str, list[Finding]]:
    old = {fingerprint(item): item for item in baseline.findings}
    new = {fingerprint(item): item for item in current.findings}
    return {
        "new": [new[key] for key in new.keys() - old],
        "resolved": [old[key] for key in old.keys() - new],
        "unchanged": [new[key] for key in new.keys() & old],
    }


def save_replay(
    report: Report,
    path: str | Path,
    inputs: dict[str, object],
    *,
    configuration: dict[str, object] | None = None,
    policies: list[dict[str, object]] | None = None,
    tests: list[dict[str, object]] | None = None,
) -> None:
    """Create a safe, non-executable replay bundle."""
    safe_report = finalize_report(
        report, configuration=configuration, policies=policies, test_definitions=tests
    )
    content = {
        "report.json": safe_report.model_dump_json(),
        "inputs.json": json.dumps(redact(inputs), sort_keys=True),
        "configuration.json": json.dumps(redact(configuration or {}), sort_keys=True),
        "policies.json": json.dumps(redact(policies or []), sort_keys=True),
        "tests.json": json.dumps(redact(tests or []), sort_keys=True),
    }
    manifest = {
        "schema": 2,
        "executable": False,
        "hashes": {
            name: hashlib.sha256(value.encode()).hexdigest() for name, value in content.items()
        },
    }
    content["manifest.json"] = json.dumps(manifest, sort_keys=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in content.items():
            archive.writestr(name, value)


def load_replay(path: str | Path, max_bytes: int = 10_000_000) -> tuple[Report, dict[str, object]]:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        required = {"report.json", "inputs.json", "manifest.json"}
        if not required <= names or not names <= required | {
            "configuration.json",
            "policies.json",
            "tests.json",
        }:
            raise ValueError("unexpected replay content")
        if sum(info.file_size for info in archive.infolist()) > max_bytes:
            raise ValueError("replay archive exceeds expanded size limit")
        if any(
            info.file_size > max_bytes
            or ".." in Path(info.filename).parts
            or Path(info.filename).is_absolute()
            for info in archive.infolist()
        ):
            raise ValueError("unsafe replay archive")
        manifest = json.loads(archive.read("manifest.json"))
        for name, expected in manifest.get("hashes", {}).items():
            if name not in names or hashlib.sha256(archive.read(name)).hexdigest() != expected:
                raise ValueError("replay artifact hash mismatch")
        return (
            Report.model_validate_json(archive.read("report.json")),
            json.loads(archive.read("inputs.json")),
        )


def pytest_regression(finding: Finding) -> str:
    marker = next((e.observed for e in finding.evidence if e.observed), "forbidden marker")
    return (
        "def test_secgraph_regression(target):\n"
        f"    output = target({json.dumps(finding.title)})\n"
        f"    assert {json.dumps(marker)} not in output\n"
    )


def regression_bundle(finding: Finding) -> dict[str, str]:
    return {
        "pytest": pytest_regression(finding),
        "yaml": json.dumps(
            {"id": finding.id, "fingerprint": fingerprint(finding), "expected": "PASS"}, indent=2
        ),
        "ci": f"secgraph replay {finding.id} --fail-on-violation",
    }


class BaselineStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name):
            raise ValueError("invalid baseline name")
        return self.root / f"{name}.json"

    def save(self, name: str, report: Report) -> Path:
        target = self._path(name)
        target.write_text(finalize_report(report).model_dump_json(indent=2), encoding="utf-8")
        return target

    def load(self, name: str) -> Report:
        return Report.model_validate_json(self._path(name).read_text(encoding="utf-8"))


def to_sarif(report: Report) -> dict[str, object]:
    levels = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    results = [
        {
            "ruleId": f.id,
            "level": levels[f.severity],
            "message": {"text": f.title},
            "partialFingerprints": {"secgraphFingerprint": f.fingerprint or fingerprint(f)},
            "properties": {
                "verdict": f.verdict.value,
                "confidence": f.confidence,
                "mappings": f.mappings,
            },
        }
        for f in report.findings
    ]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "SecGraphAI"}}, "results": results}],
    }


def to_junit(report: Report) -> str:
    suite = Element(
        "testsuite",
        tests=str(len(report.findings)),
        failures=str(sum(f.verdict != Verdict.PASS for f in report.findings)),
    )
    for finding in report.findings:
        case = SubElement(suite, "testcase", name=finding.id, classname="secgraphai")
        if finding.verdict != Verdict.PASS:
            SubElement(case, "failure", message=finding.title).text = finding.verdict.value
    return tostring(suite, encoding="unicode")
