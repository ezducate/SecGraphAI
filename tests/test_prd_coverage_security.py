from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from secgraphai.adapters import Adapter
from secgraphai.canary import CanaryFactory
from secgraphai.config import Config
from secgraphai.core import Verdict
from secgraphai.dashboard import create_app
from secgraphai.graph import EdgeType, NodeType, SecurityGraph
from secgraphai.instrumentation import (
    TraceRecorder,
    httpx_event_hooks,
    instrument,
    instrument_fastapi,
    instrument_langchain,
    instrument_langgraph,
    instrument_mcp,
    instrument_openai,
)
from secgraphai.plugins import PluginManifest
from secgraphai.runtime import (
    ApprovalAspect,
    AuthorizationAspect,
    PolicyDenied,
    RateLimitAspect,
    SecurityContext,
    current_context,
    secgraph,
)
from secgraphai.validators import (
    AuthorizationValidator,
    CanaryValidator,
    CostValidator,
    CrossTenantValidator,
    DatabaseStateValidator,
    FileStateValidator,
    HTTPCallbackValidator,
    JSONSchemaValidator,
    LatencyValidator,
    PolicyDecisionValidator,
    ResponseCodeValidator,
    SecretLeakValidator,
    StateValidator,
    ToolInvocationValidator,
    ValidationContext,
    Validators,
)


@pytest.mark.parametrize(
    "validator,context,verdict",
    [
        (CanaryValidator("MARK"), ValidationContext(output="MARK"), Verdict.VERIFIED_VIOLATION),
        (
            AuthorizationValidator(),
            ValidationContext(status_code=403, expected_status=frozenset({403})),
            Verdict.PASS,
        ),
        (
            AuthorizationValidator(("secret",)),
            ValidationContext(output="secret", status_code=403, expected_status=frozenset({403})),
            Verdict.VERIFIED_VIOLATION,
        ),
        (StateValidator(), ValidationContext(before=1, after=2), Verdict.VERIFIED_VIOLATION),
        (DatabaseStateValidator(), ValidationContext(before=1, after=1), Verdict.PASS),
        (
            ToolInvocationValidator(frozenset({"read"})),
            ValidationContext(metadata={"tools": ["read"]}),
            Verdict.PASS,
        ),
        (
            HTTPCallbackValidator("token"),
            ValidationContext(metadata={"callbacks": ["token"]}),
            Verdict.VERIFIED_VIOLATION,
        ),
        (
            JSONSchemaValidator({"required": ["id"]}),
            ValidationContext(output='{"id": 1}'),
            Verdict.PASS,
        ),
        (
            JSONSchemaValidator({"required": ["id"]}),
            ValidationContext(output="bad"),
            Verdict.VERIFIED_VIOLATION,
        ),
        (
            CrossTenantValidator("A", frozenset({"B"})),
            ValidationContext(metadata={"tenant": "B"}),
            Verdict.VERIFIED_VIOLATION,
        ),
        (
            SecretLeakValidator((r"sk-[a-z]+",)),
            ValidationContext(output="sk-secret"),
            Verdict.VERIFIED_VIOLATION,
        ),
        (
            PolicyDecisionValidator(frozenset({"allow"})),
            ValidationContext(metadata={"effect": "deny"}),
            Verdict.VERIFIED_VIOLATION,
        ),
        (CostValidator(1), ValidationContext(cost_usd=0.5), Verdict.PASS),
        (LatencyValidator(10), ValidationContext(latency_ms=11), Verdict.VERIFIED_VIOLATION),
        (
            ResponseCodeValidator(frozenset({200})),
            ValidationContext(status_code=500),
            Verdict.VERIFIED_VIOLATION,
        ),
    ],
)
def test_all_validator_interfaces(validator, context, verdict):
    assert validator.validate(context).verdict == verdict


def test_json_path_and_file_snapshot(tmp_path):
    assert Validators.json_path("bad", "$.x", 1).verdict == Verdict.INCONCLUSIVE
    assert Validators.json_path('{"x": 2}', "$.x", 1).verdict == Verdict.PASS
    path = tmp_path / "x"
    assert FileStateValidator.snapshot(path) is None
    path.write_text("value")
    assert FileStateValidator.snapshot(path)


@pytest.mark.asyncio
async def test_runtime_aspects_async_success_error_approval_and_rate_limit():
    context = SecurityContext(permissions=frozenset({"read"}), approved=True)
    await AuthorizationAspect().before(context, {"permission": "read"})
    await ApprovalAspect().before(context, {"approval": True})
    with pytest.raises(PolicyDenied):
        await AuthorizationAspect().before(context, {"permission": "write"})
    limiter = RateLimitAspect(1, 100)
    await limiter.before(context, {})
    with pytest.raises(PolicyDenied):
        await limiter.before(context, {})
    secgraph.aspects = [AuthorizationAspect(), ApprovalAspect()]
    token = current_context.set(context)
    try:

        @secgraph.tool(permission="read", approval=True)
        async def works():
            return "ok"

        assert await works() == "ok"

        @secgraph.tool(permission="read")
        async def fails():
            raise RuntimeError("x")

        with pytest.raises(RuntimeError):
            await fails()
        assert context.events[-1]["allowed"] is False
    finally:
        current_context.reset(token)


@pytest.mark.asyncio
async def test_instrumentation_async_httpx_and_framework_helpers():
    recorder = TraceRecorder()

    async def call(value=1):
        return value

    assert await instrument(call, recorder=recorder)() == 1
    for wrapper in (instrument_mcp(call), instrument_langchain(call), instrument_langgraph(call)):
        assert await wrapper() == 1
    hooks = httpx_event_hooks(recorder)
    request = httpx.Request("GET", "https://example.test")
    await hooks["request"][0](request)
    await hooks["response"][0](httpx.Response(200, request=request))
    assert any(item.kind == "httpx" for item in recorder.events)

    class Completions:
        async def create(self):
            return "ok"

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    assert await instrument_openai(client, recorder).chat.completions.create() == "ok"
    with pytest.raises(TypeError):
        instrument_openai(object())


def test_fastapi_instrumentation_and_secgraph_helpers():
    app = FastAPI()
    recorder = instrument_fastapi(app)

    @app.get("/")
    def root():
        return {"ok": True}

    response = TestClient(app).get("/")
    assert response.headers["x-secgraph-trace"] and recorder.events
    assert secgraph.instrument(lambda: 2)() == 2
    app2 = FastAPI()
    assert secgraph.instrument_fastapi(app2)
    assert secgraph.instrument_httpx()["request"]


def test_graph_tenants_cycles_features_and_paths():
    graph = SecurityGraph()
    graph.add_node("a", NodeType.USER, tenant="A", trust="untrusted")
    graph.add_node("b", NodeType.TOOL, tenant="B", privileged=True)
    graph.add_edge("a", "b", EdgeType.CAN_CALL)
    graph.add_edge("b", "a", EdgeType.CAN_CALL)
    categories = {item["category"] for item in graph.risk_paths()}
    assert {"UNTRUSTED_TO_PRIVILEGED", "CROSS_TENANT", "EXECUTION_CYCLE"} <= categories
    assert "multiple-tenants" in graph.features() and graph.attack_paths()[0]["score"]
    with pytest.raises(ValueError):
        graph.add_edge("a", "missing", EdgeType.CAN_CALL)


def test_config_validation_and_canary_variants(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"actors": {"a": {"token_env": "TOKEN_ENV"}}}))
    assert Config.load(path).actors["a"].token_env == "TOKEN_ENV"
    with pytest.raises(ValueError):
        Config.model_validate({"actors": {"a": {"token_env": "bad value"}}})
    factory = CanaryFactory()
    assert {
        factory.document(tenant="A").kind,
        factory.identifier().kind,
        factory.memory().kind,
        factory.tool_result().kind,
    } == {"document", "id", "memory", "tool"}


def test_adapter_normalization(monkeypatch):
    monkeypatch.setattr(
        "secgraphai.adapters.run_plugin",
        lambda *a, **k: {
            "findings": [{"id": "X", "title": "issue", "severity": "high", "confidence": 0.8}]
        },
    )
    adapter = Adapter("semgrep", PluginManifest("x", ("python",)))
    findings = adapter.run({"path": "."})
    assert findings[0].severity.value == "HIGH"
    with pytest.raises(ValueError):
        Adapter("unknown", PluginManifest("x", ("python",)))


def test_dashboard_remaining_routes_and_failures(tmp_path):
    token = "strong-dashboard-token"
    headers = {"Authorization": f"Bearer {token}"}
    client = TestClient(create_app(database=tmp_path / "db", token=token, rate_limit=1000))
    assert client.post("/api/v1/targets", headers=headers, json={}).status_code == 422
    assert (
        client.post("/api/v1/targets", headers=headers, json={"id": "t", "type": "api"}).status_code
        == 200
    )
    assert client.get("/api/v1/targets", headers=headers).json()[0]["id"] == "t"
    assert client.get("/api/v1/scans/missing", headers=headers).status_code == 404
    assert client.get("/api/v1/findings/missing", headers=headers).status_code == 404
    assert client.post("/api/v1/findings/missing/replay", headers=headers).status_code == 404
    assert client.get("/api/v1/graph", headers=headers).json()["nodes"] == []
    policy = {
        "rules": [{"id": "d", "effect": "deny", "match": {"tool": "x"}}],
        "events": [{"tool": "x"}],
    }
    assert (
        client.post("/api/v1/policies/test", headers=headers, json=policy).json()["would_block"]
        == 1
    )
    assert client.get("/api/v1/policies", headers=headers).status_code == 200
    assert client.get("/api/v1/reports", headers=headers).status_code == 200
    assert client.get("/api/v1/self-audit", headers=headers).status_code == 200
