"""Reproducible scan artifacts, baselines, regressions, and CI report formats."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from secgraphai.core import Finding, Report, Verdict


def fingerprint(finding: Finding) -> str:
    stable = [finding.title, finding.asset or "", finding.invariant or "", *finding.attack_path]
    return hashlib.sha256("\0".join(stable).encode()).hexdigest()[:24]


def diff_reports(baseline: Report, current: Report) -> dict[str, list[Finding]]:
    old = {fingerprint(item): item for item in baseline.findings}
    new = {fingerprint(item): item for item in current.findings}
    return {"new": [new[key] for key in new.keys() - old],
            "resolved": [old[key] for key in old.keys() - new],
            "unchanged": [new[key] for key in new.keys() & old]}


def save_replay(report: Report, path: str | Path, inputs: dict[str, object]) -> None:
    """Create a safe, non-executable replay bundle."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.json", report.model_dump_json())
        archive.writestr("inputs.json", json.dumps(inputs, sort_keys=True))
        archive.writestr("manifest.json", json.dumps({"schema": 1, "executable": False}))


def load_replay(path: str | Path, max_bytes: int = 10_000_000) -> tuple[Report, dict[str, object]]:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        if names != {"report.json", "inputs.json", "manifest.json"}:
            raise ValueError("unexpected replay content")
        if any(info.file_size > max_bytes or ".." in info.filename for info in archive.infolist()):
            raise ValueError("unsafe replay archive")
        return (Report.model_validate_json(archive.read("report.json")),
                json.loads(archive.read("inputs.json")))


def pytest_regression(finding: Finding) -> str:
    marker = next((e.observed for e in finding.evidence if e.observed), "forbidden marker")
    return ("def test_secgraph_regression(target):\n"
            f"    output = target({json.dumps(finding.title)})\n"
            f"    assert {json.dumps(marker)} not in output\n")


def to_sarif(report: Report) -> dict[str, object]:
    results = [{"ruleId": f.id, "level": f.severity.value.lower(),
                "message": {"text": f.title}} for f in report.findings]
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "SecGraphAI"}}, "results": results}]}


def to_junit(report: Report) -> str:
    suite = Element("testsuite", tests=str(len(report.findings)),
                    failures=str(sum(f.verdict != Verdict.PASS for f in report.findings)))
    for finding in report.findings:
        case = SubElement(suite, "testcase", name=finding.id, classname="secgraphai")
        if finding.verdict != Verdict.PASS:
            SubElement(case, "failure", message=finding.title).text = finding.verdict.value
    return tostring(suite, encoding="unicode")
