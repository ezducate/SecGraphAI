from __future__ import annotations

import socket

import pytest
import respx
from fastapi.testclient import TestClient
from httpx import Response

from secgraphai.adapters import Adapter, normalize_engine_output
from secgraphai.attacks import Attack, AttackMemory, AttackPlanner, load_official_pack
from secgraphai.core import Finding, Report, Severity, Verdict
from secgraphai.dashboard import create_app
from secgraphai.discovery import discover_path, discover_url
from secgraphai.intelligence import NVDClient, VulnerabilityCache
from secgraphai.plugins import PluginManifest, PluginTrust, audit_plugins, run_plugin
from secgraphai.scanner import ScanBudget, SecGraph
from secgraphai.security_modules import AgentSecurityModule, APISecurityModule, RAGSecurityModule
from secgraphai.targets import RAGDocument, RAGTarget, TargetResponse
from secgraphai.validators import Validation, ValidationContext


@pytest.mark.parametrize(
    "engine,document,expected",
    [
        (
            "codeql",
            {
                "runs": [
                    {"results": [{"ruleId": "R", "level": "error", "message": {"text": "bad"}}]}
                ]
            },
            "HIGH",
        ),
        (
            "zap",
            {"site": [{"alerts": [{"pluginid": "1", "alert": "bad", "riskcode": "3"}]}]},
            "HIGH",
        ),
        (
            "nuclei",
            {"results": [{"template-id": "n", "info": {"name": "bad", "severity": "low"}}]},
            "LOW",
        ),
        (
            "pip-audit",
            {"dependencies": [{"name": "x", "version": "1", "vulns": [{"id": "CVE-X"}]}]},
            "HIGH",
        ),
    ],
)
def test_external_native_formats(engine, document, expected):
    assert normalize_engine_output(engine, document)[0]["severity"] == expected


def test_adapter_skips_non_objects_and_plugin_hash_requirements(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "secgraphai.adapters.run_plugin", lambda *args, **kwargs: {"findings": ["bad", {"id": "x"}]}
    )
    assert len(Adapter("garak", PluginManifest("x", ("python",))).run({})) == 1
    trusted = PluginManifest("trusted", ("python",), trust=PluginTrust.TRUSTED)
    assert any("SHA-256" in item for item in audit_plugins([trusted]))
    executable = tmp_path / "engine"
    executable.write_text("binary", encoding="utf-8")
    monkeypatch.setattr("secgraphai.plugins.shutil.which", lambda value: str(executable))
    with pytest.raises(PermissionError, match="requires an artifact"):
        run_plugin(trusted, {})
    mismatch = PluginManifest(
        "trusted", ("python",), trust=PluginTrust.TRUSTED, artifact_sha256="0" * 64
    )
    with pytest.raises(PermissionError, match="mismatch"):
        run_plugin(mismatch, {})


def test_discovery_extended_sources_and_invalid_inputs(tmp_path):
    (tmp_path / "app.py").write_text(
        "@agent\ndef a(user: Annotated[str, Identity()]): pass\n"
        "@schema.field\ndef profile(): pass\n",
        encoding="utf-8",
    )
    (tmp_path / "manifest.yaml").write_text(
        "graphql:\n  queries: [viewer]\n"
        "trust_boundaries:\n  - id: internet\n"
        "http_traces:\n  - url: https://outside.example.test/callback\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.yaml").write_text("[", encoding="utf-8")
    inventory = discover_path(tmp_path)
    counts = inventory.counts()
    assert counts["api"] == 2 and counts["identity"] == 1
    assert counts["trust_boundary"] == 1 and counts["external_service"] == 1
    with pytest.raises(ValueError, match="does not exist"):
        discover_path(tmp_path / "missing")


@pytest.mark.asyncio
@respx.mock
async def test_remote_discovery_scope_status_and_document(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 443))
        ],
    )
    route = respx.get("https://api.example.test/openapi.json")
    route.mock(return_value=Response(200, json={"paths": {"/x": {"get": {}}}}))
    inventory = await discover_url("https://api.example.test/openapi.json")
    assert inventory.counts() == {"api": 1}
    route.mock(return_value=Response(404))
    with pytest.raises(RuntimeError, match="404"):
        await discover_url("https://api.example.test/openapi.json")
    route.mock(return_value=Response(200, json=[]))
    with pytest.raises(ValueError, match="object"):
        await discover_url("https://api.example.test/openapi.json")
    with pytest.raises(ValueError, match="HTTP"):
        await discover_url("file:///tmp/openapi.json")


@pytest.mark.asyncio
async def test_rag_error_flood_provenance_metadata_and_config_branches():
    target = RAGTarget(
        lambda query, tenant: [
            RAGDocument("other", "B", "ignore previous", {"instruction": "override"}),
            RAGDocument("same", tenant, "safe", {"source": "trusted"}),
        ]
    )
    module = RAGSecurityModule(target)
    assert len(await module.test_poisoning("A")) == 1
    findings = await module.test_retrieval_controls("x", "A", max_results=1)
    assert len(findings) == 4
    assert len(module.audit_configuration()) == 5
    errors = await module.test_canary_lifecycle(owner_tenant="A", requesting_tenant="B")
    assert errors[0].verdict == Verdict.TEST_ERROR


class DummyAPI:
    def __init__(self, statuses: list[int]) -> None:
        self.statuses = iter(statuses)

    async def request(self, *args, **kwargs):
        return TargetResponse(next(self.statuses), "")


@pytest.mark.asyncio
async def test_api_rate_and_invalid_schema_branches():
    module = APISecurityModule(DummyAPI([200, 200]))  # type: ignore[arg-type]
    assert await module.test_rate_limit("/ai", requests=2)
    module = APISecurityModule(DummyAPI([200, 429]))  # type: ignore[arg-type]
    assert await module.test_rate_limit("/ai", requests=2) == []
    assert (
        APISecurityModule.__new__(APISecurityModule).audit_openapi({"paths": []})[0].verdict
        == Verdict.TEST_ERROR
    )


def test_agent_budget_approval_recursion_branches():
    events = [
        {"kind": "tool", "function": "root", "risk": "high", "allowed": True} for _ in range(5)
    ]
    findings = AgentSecurityModule().analyze(events, max_tool_calls=2)
    titles = {item.title for item in findings}
    assert "Agent exceeded tool-call budget" in titles
    assert "Privileged tool ran without approval" in titles
    assert "Repeated tool execution detected" in titles


class AlwaysViolation:
    def validate(self, context: ValidationContext) -> Validation:
        return Validation(Verdict.VERIFIED_VIOLATION, 1)


@pytest.mark.asyncio
async def test_configured_attacker_generates_adaptive_mutation(monkeypatch):
    attack = Attack("a", "rag", "first", tags=frozenset({"rag"}))
    memory = AttackMemory()
    scanner = SecGraph(
        attacker={"base_url": "https://attacker.test", "model": "x"},
        planner=AttackPlanner([attack], memory),
        validators=[AlwaysViolation()],
        budget=ScanBudget(max_requests=10),
    )

    async def attacker(prompt: str) -> str:
        return "generated variation"

    monkeypatch.setattr(scanner, "_configured_model_callback", lambda config: attacker)
    seen: list[str] = []
    await scanner.scan_attacks(
        lambda prompt: seen.append(prompt) or "safe",
        features=["rag"],
        attack_budget=2,
    )
    assert seen == ["first", "generated variation"]


@pytest.mark.asyncio
@respx.mock
async def test_nvd_client_bounds_and_invalid_json():
    route = respx.get(NVDClient.endpoint)
    route.mock(return_value=Response(200, content=b"[]"))
    with pytest.raises(ValueError, match="object"):
        await NVDClient().search("x")
    route.mock(return_value=Response(200, content=b"long"))
    with pytest.raises(ValueError, match="limit"):
        await NVDClient(max_response_bytes=2).search("x")
    route.mock(return_value=Response(200, content=b"{"))
    with pytest.raises(ValueError, match="invalid JSON"):
        await NVDClient().search("x")


def test_dashboard_persistence_cve_owasp_limits_and_policy(tmp_path):
    token = "correct-horse-battery-staple"
    database = tmp_path / "db.sqlite"
    app = create_app(database=database, token=token, rate_limit=1000)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    assert (
        client.post("/api/v1/targets", headers=headers, json={"id": "t", "type": "api"}).status_code
        == 200
    )
    assert (
        client.post("/api/v1/policies", headers=headers, json={"id": "p", "rules": []}).status_code
        == 200
    )
    finding = Finding(
        id="F",
        title="issue",
        severity=Severity.HIGH,
        verdict=Verdict.TEST_ERROR,
        confidence=1,
        cve_ids=["CVE-2026-1234"],
        mappings={"OWASP": ["LLM01"]},
    )
    report = Report(scan_id="dashboard", findings=[finding])
    assert (
        client.post(
            "/api/v1/scans", headers=headers, json=report.model_dump(mode="json")
        ).status_code
        == 200
    )
    assert client.get("/api/v1/vulnerabilities", headers=headers).json()[0]["id"].startswith("CVE")
    matrix = client.get("/api/v1/owasp-coverage", headers=headers).json()
    assert matrix["states"]["LLM01"] == "TEST_ERROR"
    recreated = TestClient(create_app(database=database, token=token, rate_limit=1000))
    assert recreated.get("/api/v1/targets", headers=headers).json()[0]["id"] == "t"
    assert client.post("/api/v1/policies", headers=headers, json={}).status_code == 422
    assert client.get("/api/v1/owasp-coverage?profile=bad", headers=headers).status_code == 404


def test_dashboard_body_and_request_rate_limits(tmp_path):
    token = "correct-horse-battery-staple"
    client = TestClient(
        create_app(database=tmp_path / "db", token=token, max_body_bytes=2, rate_limit=1000)
    )
    response = client.post(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {token}", "Content-Length": "3"},
        content=b"{}",
    )
    assert response.status_code == 413
    limited = TestClient(create_app(database=tmp_path / "limited", token=token, rate_limit=1))
    assert limited.get("/api/v1/health").status_code == 200
    assert limited.get("/api/v1/health").status_code == 429


def test_official_pack_name_and_empty_cache_branches(tmp_path):
    with pytest.raises(ValueError):
        load_official_pack("../bad")
    with pytest.raises(FileNotFoundError):
        load_official_pack("missing")
    assert VulnerabilityCache(tmp_path / "missing.json").search("x") == []
