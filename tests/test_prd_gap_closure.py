from __future__ import annotations

from dataclasses import dataclass, field

import pytest
import respx
from httpx import Response

from secgraphai.adapters import normalize_engine_output
from secgraphai.attacks import (
    BUILTIN_ATTACKS,
    Attack,
    AttackMemory,
    AttackPlanner,
    load_official_pack,
)
from secgraphai.core import Evidence, Finding, Report, Severity, Verdict
from secgraphai.discovery import discover_path
from secgraphai.graph import EdgeType, NodeType, SecurityGraph
from secgraphai.intelligence import (
    Component,
    CoverageState,
    Vulnerability,
    VulnerabilityCache,
    affected,
    owasp_gate,
    parse_nvd,
)
from secgraphai.model import Model
from secgraphai.policy import Effect, PolicyEngine, Rule
from secgraphai.reporting import to_html, to_markdown
from secgraphai.runtime import PolicyDenied, RuntimePolicyAspect, SecurityContext
from secgraphai.scanner import SecGraph
from secgraphai.security_modules import (
    AgentSecurityModule,
    APISecurityModule,
    MCPSecurityModule,
    RAGSecurityModule,
)
from secgraphai.self_security import run_self_audit
from secgraphai.storage import Storage
from secgraphai.targets import MCPClient, RAGDocument, RAGTarget
from secgraphai.validators import Validation, ValidationContext


@dataclass
class RecordingGuard:
    urls: list[str] = field(default_factory=list)

    def authorize(self, url: str) -> None:
        self.urls.append(url)


@pytest.mark.asyncio
@respx.mock
async def test_model_authorizes_the_exact_completion_endpoint_before_request():
    guard = RecordingGuard()
    model = Model(
        base_url="https://model.test/v1",
        model="safe",
        scope_guard=guard,  # type: ignore[arg-type]
    )
    respx.post("https://model.test/v1/chat/completions").mock(
        return_value=Response(200, json={"choices": [{"message": {"content": "ok"}}]})
    )
    assert await model.complete([]) == "ok"
    assert guard.urls == ["https://model.test/v1/chat/completions"]


def test_affected_ranges_are_conjunctive_and_malformed_is_unknown():
    bounded = Vulnerability("CVE-X", "demo", 8, affected_versions=(">=1", "<2"))
    assert affected(Component("demo", "1.5"), bounded) is True
    assert affected(Component("demo", "2.5"), bounded) is False
    malformed = Vulnerability("CVE-Y", "demo", 8, affected_versions=("definitely-not-a-range",))
    assert affected(Component("demo", "1.5"), malformed) is None


def test_runtime_policy_enforces_rate_sandbox_and_safe_transform():
    context = SecurityContext()
    rate = RuntimePolicyAspect(
        PolicyEngine(
            [Rule("limited", Effect.RATE_LIMIT, {}, options={"maximum": 1, "window_seconds": 60})]
        )
    )
    rate.before_sync(context, {"kind": "tool"})
    with pytest.raises(PolicyDenied, match="rate limit"):
        rate.before_sync(context, {"kind": "tool"})

    sandbox = RuntimePolicyAspect(PolicyEngine([Rule("sandbox", Effect.SANDBOX)]))
    with pytest.raises(PolicyDenied, match="sandbox"):
        sandbox.before_sync(context, {"kind": "tool"})
    sandbox.before_sync(context, {"kind": "tool", "sandboxed": True})

    transform = RuntimePolicyAspect(
        PolicyEngine(
            [
                Rule(
                    "fields",
                    Effect.TRANSFORM,
                    options={"transform": "drop_fields", "fields": ["secret"]},
                )
            ]
        )
    )
    assert transform.after_sync(context, {}, {"secret": "x", "public": "y"}) == {"public": "y"}


def test_discovery_builds_inventory_and_graph_without_importing_code(tmp_path):
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app=FastAPI()\n"
        "@app.get('/items')\n"
        "def items(): return []\n"
        "@secgraph.tool()\n"
        "def refund(): return 1\n"
        "raise RuntimeError('must not import')\n",
        encoding="utf-8",
    )
    (tmp_path / "architecture.yaml").write_text(
        "agents:\n  - id: support\nmodels:\n  - id: assistant\nidentities:\n  - id: customer\n",
        encoding="utf-8",
    )
    inventory = discover_path(tmp_path)
    assert inventory.counts() == {"agent": 1, "api": 1, "identity": 1, "model": 1, "tool": 1}
    graph = inventory.to_graph()
    assert {attributes["kind"] for _, attributes in graph.nodes} >= {
        NodeType.AGENT.value,
        NodeType.API_ENDPOINT.value,
        NodeType.TOOL.value,
    }


def test_all_prd_graph_risk_path_categories_are_detected():
    graph = SecurityGraph()
    graph.add_node("anon", NodeType.IDENTITY, anonymous=True, privilege="low", trust="untrusted")
    graph.add_node("tool", NodeType.TOOL, privileged=True, privilege="high")
    graph.add_node("control", NodeType.API_ENDPOINT, protected=True, control_plane=True)
    graph.add_node("rag", NodeType.DOCUMENT)
    graph.add_edge("anon", "tool", EdgeType.CAN_CALL)
    graph.add_edge("tool", "control", EdgeType.SENDS_TO)
    graph.add_edge("rag", "tool", EdgeType.CAN_INFLUENCE)
    categories = {item["category"] for item in graph.risk_paths()}
    assert {
        "UNTRUSTED_TO_PRIVILEGED",
        "ANONYMOUS_TO_PROTECTED",
        "LOW_TO_HIGH_PRIVILEGE",
        "TOOL_OUTPUT_TO_CONTROL_PLANE",
        "RAG_CONTENT_TO_PRIVILEGED_TOOL",
    } <= categories


class AlwaysViolation:
    def validate(self, context: ValidationContext) -> Validation:
        return Validation(Verdict.VERIFIED_VIOLATION, 1)


@pytest.mark.asyncio
async def test_adaptive_scan_records_feedback_and_empty_budget_runs_nothing():
    attack = Attack("rag", "rag", "probe", tags=frozenset({"rag"}))
    memory = AttackMemory()
    scanner = SecGraph(
        planner=AttackPlanner([attack], memory), validators=[AlwaysViolation()], seed=7
    )
    prompts: list[str] = []

    async def callback(prompt: str) -> str:
        prompts.append(prompt)
        return "safe"

    report = await scanner.scan_attacks(
        callback, features=(value for value in ["rag"]), attack_budget=2, strategy="adaptive"
    )
    assert len(prompts) == 2
    assert memory.observations[0].stage == "verified"
    assert report.manifest.artifact_hashes["tests"]

    prompts.clear()
    empty = await scanner.scan_attacks(callback, features=["rag"], attack_budget=0)
    assert prompts == [] and empty.interactions == []


def test_storage_materializes_prd_tables_and_persists_documents(tmp_path):
    report = Report(
        scan_id="scan",
        findings=[
            Finding(
                id="finding",
                title="issue",
                severity=Severity.HIGH,
                verdict=Verdict.VERIFIED_VIOLATION,
                confidence=1,
                evidence=[Evidence(kind="test", description="evidence")],
            )
        ],
        graph={
            "nodes": [{"id": "a"}],
            "edges": [{"source": "a", "target": "b"}],
            "risk_paths": [{"path": ["a", "b"]}],
        },
    )
    storage = Storage(tmp_path / "secgraph.db")
    storage.save(report)
    storage.put_document("targets", "target", {"id": "target", "token": "secret"})
    assert storage.list_documents("targets") == [{"id": "target", "token": "[REDACTED]"}]
    assert storage.attack_paths("scan") == [{"path": ["a", "b"]}]
    with storage._connect() as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert {
        "targets",
        "scans",
        "findings",
        "events",
        "attack_paths",
        "graph_nodes",
        "graph_edges",
        "policies",
        "evidence",
        "reports",
        "baselines",
        "bundles",
        "plugin_registry",
    } <= tables


@pytest.mark.asyncio
async def test_rag_canary_lifecycle_cleanup_and_retrieval_controls():
    documents: list[RAGDocument] = []

    async def retrieve(query: str, tenant: str):
        return list(documents)

    async def write(document: RAGDocument):
        documents.append(document)

    async def delete(document_id: str, tenant: str):
        documents[:] = [item for item in documents if item.id != document_id]

    target = RAGTarget(
        retrieve,
        writer=write,
        deleter=delete,
        configuration={
            "namespace_isolation": True,
            "authorization_before_retrieval": True,
            "provenance": True,
            "metadata_filtering": True,
            "max_results": 10,
        },
    )
    module = RAGSecurityModule(target)
    findings = await module.test_canary_lifecycle(owner_tenant="a", requesting_tenant="b")
    assert any("tenant boundary" in item.title for item in findings)
    assert documents == [] and module.audit_configuration() == []


@pytest.mark.asyncio
async def test_mcp_capability_drift_permissions_and_transport():
    async def transport(method: str, params: dict[str, object]):
        if method == "initialize":
            return {"url": "http://mcp.example.test"}
        if method == "tools/list":
            return {
                "tools": [
                    {
                        "name": "refund",
                        "description": "refund",
                        "inputSchema": {"additionalProperties": False},
                        "risk": "high",
                    }
                ]
            }
        return {"resources" if method == "resources/list" else "prompts": []}

    client = MCPClient(transport)
    findings = await MCPSecurityModule(client).audit(baseline_fingerprint="different")
    titles = {item.title for item in findings}
    assert "MCP server capabilities drifted from the approved baseline" in titles
    assert "High-risk MCP tool does not require human approval" in titles
    assert "Remote MCP transport does not declare TLS" in titles


def test_api_schema_and_agent_event_security_families():
    api = APISecurityModule.__new__(APISecurityModule)
    findings = api.audit_openapi(
        {
            "paths": {
                "/fetch": {
                    "get": {
                        "parameters": [
                            {"name": "url", "schema": {"type": "string"}},
                            {"name": "limit", "schema": {"type": "integer"}},
                        ]
                    }
                }
            }
        }
    )
    titles = {item.title for item in findings}
    assert "API operation does not declare authentication" in titles
    assert "URL-handling operation requires explicit SSRF policy review" in titles
    agent_findings = AgentSecurityModule().analyze(
        [
            {"kind": "goal_change", "provenance": "rag"},
            {"kind": "delegation"},
            {"kind": "memory_write", "provenance": "untrusted"},
            {
                "kind": "tool",
                "function": "email",
                "external": True,
                "allowed": True,
                "in_intent": False,
            },
        ]
    )
    assert len(agent_findings) == 4


def test_nvd_cpe_ranges_and_corrupt_cache_are_not_marked_safe(tmp_path):
    document = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-12345",
                    "metrics": {},
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:demo:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "1.0",
                                            "versionEndExcluding": "2.0",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }
    vulnerability = parse_nvd(document)[0]
    assert vulnerability.component == "demo"
    assert affected(Component("demo", "1.5"), vulnerability) is True
    assert affected(Component("demo", "2.0"), vulnerability) is False
    path = tmp_path / "broken.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        VulnerabilityCache(path).search("demo")


def test_official_pack_and_builtin_owasp_mappings_are_reviewable():
    pack = load_official_pack()
    assert pack.trust.value == "TRUSTED_OFFICIAL" and pack.signature
    assert all(
        attack.mappings
        and all(
            mapping.version and mapping.strength == "strong" and mapping.rationale
            for mapping in attack.mappings
        )
        for attack in BUILTIN_ATTACKS
    )


def test_owasp_test_error_is_never_counted_as_covered():
    passed, matrix = owasp_gate(
        "llm-2026",
        [
            ("LLM01", CoverageState.TEST_ERROR),
            *((f"LLM{index:02d}", CoverageState.TESTED) for index in range(2, 11)),
        ],
        minimum_percent=90,
    )
    assert passed is False
    assert matrix["percent"] == 90.0
    assert matrix["states"]["LLM01"] == "TEST_ERROR"


def test_native_external_engine_formats_are_normalized():
    semgrep = normalize_engine_output(
        "semgrep",
        {
            "results": [
                {
                    "check_id": "python.lang.issue",
                    "extra": {
                        "message": "unsafe call",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-78"]},
                    },
                }
            ]
        },
    )
    assert semgrep[0]["severity"] == "HIGH" and semgrep[0]["mappings"]["CWE"] == ["CWE-78"]


def test_reports_include_audience_resources_manifest_and_self_audit_checks(tmp_path):
    report = Report(scan_id="audience", limitations=["authorized scope only"])
    assert "Executive summary" in to_html(report)
    assert "## Resource usage" in to_markdown(report)
    audit = run_self_audit(
        config={"dashboard": {"host": "127.0.0.1"}}, database=tmp_path / "missing"
    )
    names = {item.name for item in audit.checks}
    assert {
        "Package integrity",
        "Plugin signatures",
        "Dashboard bind",
        "TLS configuration",
    } <= names
