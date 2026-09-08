from __future__ import annotations

import json

import yaml
from typer.testing import CliRunner

from secgraphai.cli import app
from secgraphai.core import Evidence, Finding, Report, Severity, Verdict
from secgraphai.intelligence import Vulnerability, VulnerabilityCache

runner = CliRunner()


def callback(prompt: str) -> str:
    return "safe"


def files(tmp_path):
    report = Report(
        scan_id="cli",
        findings=[
            Finding(
                id="F-1",
                title="issue",
                severity=Severity.HIGH,
                verdict=Verdict.VERIFIED_VIOLATION,
                confidence=1,
                evidence=[Evidence(kind="marker", description="x", observed="MARK")],
                mappings={"OWASP_LLM_2026": ["LLM01"]},
            )
        ],
    )
    report_path = tmp_path / "report.json"
    report_path.write_text(report.model_dump_json())
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        yaml.safe_dump(
            {
                "default": "allow",
                "rules": [{"id": "d", "effect": "deny", "match": {"tool": "shell"}}],
            }
        )
    )
    events = tmp_path / "events.json"
    events.write_text(json.dumps([{"tool": "shell"}, {"tool": "read"}]))
    cache = tmp_path / "cve.json"
    VulnerabilityCache(cache).save(
        [Vulnerability("CVE-1", "demo", 9, reachable=True, affected_versions=("<2",))]
    )
    return report, report_path, policy, events, cache


def invoke(args, expected=0):
    result = runner.invoke(app, [str(item) for item in args])
    assert result.exit_code == expected, result.output
    return result


def test_cli_lifecycle_policy_report_and_baseline(tmp_path):
    report, report_path, policy, events, _ = files(tmp_path)
    invoke(["diff", report_path, report_path])
    invoke(["compare", report_path, report_path])
    invoke(["generate-test", report_path, "F-1", "--output", tmp_path / "regression.py"])
    invoke(["report", "render", report_path, tmp_path / "report.md"])
    invoke(["policy", "test", policy, "--event", '{"tool":"shell"}'])
    invoke(["policy", "simulate", policy, events])
    invoke(["baseline", "create", "release", report_path, "--root", tmp_path / "baselines"])
    invoke(["baseline", "compare", "release", report_path, "--root", tmp_path / "baselines"])
    bundle = tmp_path / "scan.secgraph"
    invoke(["bundle", "create", report_path, bundle])
    invoke(["bundle", "replay", bundle])
    invoke(["replay", bundle])
    invoke(["owasp", "coverage", report_path])
    invoke(["owasp", "gate", report_path, "--minimum-percent", "10"])


def test_cli_cve_sbom_pack_plugin_engines_and_openapi(tmp_path):
    _, _, _, _, cache = files(tmp_path)
    invoke(["cve", "search", "demo", "--cache", cache])
    invoke(["cve", "show", "CVE-1", "--cache", cache])
    invoke(["cve", "affected", "demo", "1.0", "--cache", cache])
    invoke(["cve", "reachable", "--cache", cache])
    invoke(["cve", "status", "--cache", cache])
    bom = tmp_path / "bom.json"
    invoke(["sbom", "generate", "--output", bom])
    spdx = tmp_path / "bom.spdx.json"
    invoke(["sbom", "generate", "--output", spdx, "--format", "spdx"])
    empty_cache = tmp_path / "empty.json"
    VulnerabilityCache(empty_cache).save([])
    invoke(["sbom", "scan", bom, "--cache", empty_cache])
    invoke(["sbom", "scan", spdx, "--cache", empty_cache])
    pack = tmp_path / "pack.yaml"
    pack.write_text(
        yaml.safe_dump(
            {
                "id": "local",
                "version": "1",
                "publisher": "me",
                "attacks": [{"id": "a", "family": "x", "prompt": "x"}],
            }
        )
    )
    invoke(["packs", "verify", pack])
    invoke(["packs", "official"])
    manifest = tmp_path / "plugin.json"
    manifest.write_text(
        json.dumps(
            {"name": "x", "command": ["python"], "output_schema": {"required": ["findings"]}}
        )
    )
    invoke(["plugins", "audit", manifest])
    assert "semgrep" in invoke(["engines"]).output
    spec = tmp_path / "openapi.json"
    spec.write_text(json.dumps({"paths": {"/x": {"get": {}}}}))
    assert "GET" in invoke(["openapi", spec]).output


def test_cli_cve_sync_incrementally_preserves_existing_records(tmp_path, monkeypatch):
    cache = tmp_path / "cve.json"
    VulnerabilityCache(cache).save([Vulnerability("CVE-OLD", "old", 4)])

    async def search(client, query):
        client.response_metadata = {"etag": '"current"'}
        return [Vulnerability("CVE-NEW", query, 8)]

    monkeypatch.setattr("secgraphai.cli.NVDClient.search", search)
    result = invoke(["cve", "sync", "--query", "demo", "--cache", cache])
    output = json.loads(result.output)
    assert output["fetched"] == 1 and output["cached"] == 2
    assert output["metadata"]["etag"] == '"current"'
    assert {item.id for item in VulnerabilityCache(cache).search("")} == {
        "CVE-OLD",
        "CVE-NEW",
    }


def test_cli_init_doctor_discover_self_audit_and_scan(tmp_path):
    config = tmp_path / "secgraph.yaml"
    invoke(["init", config])
    invoke(["doctor", "--config", config])
    invoke(["discover", tmp_path])
    invoke(["self-audit", "--config", config])
    result = invoke(["scan", "--callback", f"{__name__}:callback", "--format", "json"])
    assert "SG-SCAN" in result.output
