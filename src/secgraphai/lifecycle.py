"""Reproducible scan artifacts, baselines, regressions, and CI report formats."""

from __future__ import annotations

import hashlib
import inspect
import json
import platform
import re
import sys
import zipfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

# XML is generated only; no untrusted XML is parsed by this module.
from xml.etree.ElementTree import Element, SubElement, tostring  # nosec B405

from pydantic import BaseModel, ConfigDict, Field

from secgraphai.core import Finding, Report, Severity, Verdict
from secgraphai.security import redact


class ReplayAttempt(BaseModel):
    """One safely re-executed request from a replay bundle."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    finding_id: str | None = None
    prompt: str
    verdict: Verdict
    matched_markers: list[str] = Field(default_factory=list)
    output: str | None = None
    error: str | None = None


class ReplayResult(BaseModel):
    """Aggregate result of executing the data-only cases in a replay bundle."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    attempts: list[ReplayAttempt] = Field(default_factory=list)

    def summary(self) -> dict[str, int]:
        result = {verdict.value: 0 for verdict in Verdict}
        for attempt in self.attempts:
            result[attempt.verdict.value] += 1
        return result


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
    """Create a safe bundle containing data-only cases that can be re-executed."""
    safe_report = finalize_report(
        report, configuration=configuration, policies=policies, test_definitions=tests
    )
    replay_inputs = dict(inputs)
    if "cases" not in replay_inputs:
        replay_inputs["cases"] = _replay_cases(safe_report)
    content = {
        "report.json": safe_report.model_dump_json(),
        "inputs.json": json.dumps(redact(replay_inputs), sort_keys=True),
        "configuration.json": json.dumps(redact(configuration or {}), sort_keys=True),
        "policies.json": json.dumps(redact(policies or []), sort_keys=True),
        "tests.json": json.dumps(redact(tests or []), sort_keys=True),
    }
    manifest = {
        "schema": 3,
        "executable": False,
        "replayable": True,
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
        listed_names = archive.namelist()
        names = set(listed_names)
        if len(listed_names) != len(names):
            raise ValueError("replay artifact hash mismatch: duplicate content")
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
        try:
            manifest = json.loads(archive.read("manifest.json"))
        except json.JSONDecodeError as exc:
            raise ValueError("replay manifest is invalid") from exc
        artifact_names = names - {"manifest.json"}
        hashes = manifest.get("hashes") if isinstance(manifest, dict) else None
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema") not in {2, 3}
            or manifest.get("executable") is not False
            or not isinstance(hashes, dict)
            or set(hashes) != artifact_names
            or not all(isinstance(value, str) for value in hashes.values())
        ):
            raise ValueError("replay manifest is invalid")
        for name, expected in hashes.items():
            if name not in names or hashlib.sha256(archive.read(name)).hexdigest() != expected:
                raise ValueError("replay artifact hash mismatch")
        return (
            Report.model_validate_json(archive.read("report.json")),
            json.loads(archive.read("inputs.json")),
        )


async def execute_replay(
    report: Report,
    inputs: dict[str, object],
    callback: Callable[[str], str | Awaitable[str]],
) -> ReplayResult:
    """Re-run a bundle's inert prompts against an explicitly supplied callback."""
    raw_cases = inputs.get("cases")
    cases = raw_cases if isinstance(raw_cases, list) else _replay_cases(report)
    attempts: list[ReplayAttempt] = []
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            attempts.append(
                ReplayAttempt(
                    prompt="",
                    verdict=Verdict.TEST_ERROR,
                    error="invalid replay case",
                )
            )
            continue
        prompt_value = raw_case.get("prompt")
        if not isinstance(prompt_value, str):
            attempts.append(
                ReplayAttempt(
                    prompt="",
                    verdict=Verdict.TEST_ERROR,
                    error="invalid replay case",
                )
            )
            continue
        prompt = prompt_value
        finding_id = raw_case.get("finding_id")
        markers = raw_case.get("forbidden_markers", [])
        safe_markers = (
            [value for value in markers if isinstance(value, str) and value]
            if isinstance(markers, list)
            else []
        )
        try:
            value = callback(prompt)
            output = await value if inspect.isawaitable(value) else value
            rendered = str(output)
            matched = [marker for marker in safe_markers if marker in rendered]
            verdict = Verdict.VERIFIED_VIOLATION if matched else Verdict.PASS
            attempts.append(
                ReplayAttempt(
                    finding_id=finding_id if isinstance(finding_id, str) else None,
                    prompt=prompt,
                    verdict=verdict,
                    matched_markers=matched,
                    output=str(redact(rendered)),
                )
            )
        except Exception as exc:  # target failures are replay results, not runner failures
            attempts.append(
                ReplayAttempt(
                    finding_id=finding_id if isinstance(finding_id, str) else None,
                    prompt=prompt,
                    verdict=Verdict.TEST_ERROR,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
    return ReplayResult(attempts=attempts)


def _replay_cases(report: Report) -> list[dict[str, object]]:
    interactions = {item.test_id: item for item in report.interactions}
    cases: list[dict[str, object]] = []
    for finding in report.findings:
        prompt = finding.reproduction.get("prompt")
        if not isinstance(prompt, str):
            test_id = finding.reproduction.get("test_id")
            interaction = interactions.get(test_id) if isinstance(test_id, str) else None
            prompt = interaction.request.get("prompt") if interaction else None
        if not isinstance(prompt, str):
            continue
        markers = [
            evidence.observed
            for evidence in finding.evidence
            if evidence.deterministic and isinstance(evidence.observed, str) and evidence.observed
        ]
        cases.append(
            {
                "finding_id": finding.id,
                "prompt": prompt,
                "forbidden_markers": list(dict.fromkeys(markers)),
            }
        )
    return cases


def pytest_regression(finding: Finding) -> str:
    marker = next((e.observed for e in finding.evidence if e.observed), "forbidden marker")
    prompt = finding.reproduction.get("prompt", finding.title)
    if not isinstance(prompt, str):
        prompt = finding.title
    return (
        "import pytest\n\n"
        "@pytest.mark.secgraph\n"
        f"def test_secgraph_regression_{_python_name(finding.id)}(target):\n"
        f"    output = target({json.dumps(prompt)})\n"
        f"    assert {json.dumps(marker)} not in output\n"
    )


def regression_bundle(finding: Finding) -> dict[str, str]:
    yaml_case = {
        "schema": "secgraph-regression/1.0",
        "id": finding.id,
        "fingerprint": fingerprint(finding),
        "invariant": finding.invariant,
        "expected": "PASS",
        "forbidden_verdicts": ["VERIFIED_VIOLATION", "LIKELY_VIOLATION", "TEST_ERROR"],
    }
    junit = Element("testsuite", name="secgraph-regression", tests="1")
    SubElement(junit, "testcase", classname="secgraphai.generated", name=finding.id)
    return {
        "pytest": pytest_regression(finding),
        "yaml": json.dumps(yaml_case, indent=2),
        "junit": tostring(junit, encoding="unicode"),
        "policy": json.dumps(
            {
                "fail_on_new": ["CRITICAL", "HIGH"],
                "fail_on_test_error": True,
                "required_fingerprints": [fingerprint(finding)],
            },
            indent=2,
        ),
        "ci": (
            "secgraph replay \"$SECGRAPH_REPLAY_BUNDLE\" "
            "--callback \"$SECGRAPH_TARGET_CALLBACK\" --fail-on-violation"
        ),
    }


def _python_name(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_]", "_", value).lower()
    return result if not result[:1].isdigit() else f"finding_{result}"


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
