from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secgraphai.core import Evidence, Finding, Report, Severity, Verdict
from secgraphai.dashboard import create_app
from secgraphai.instrumentation import TraceRecorder, instrument
from secgraphai.invariants import invariant
from secgraphai.scanner import ScanBudget, SecGraph, TargetResult
from secgraphai.validators import CostValidator, ToolInvocationValidator


@pytest.mark.asyncio
async def test_scanner_connects_validators_invariants_traces_and_manifest():
    scanner = SecGraph(
        invariants=[
            invariant(
                "NO_EXTERNAL",
                source={"trust": "untrusted"},
                destination={"trust": "external"},
                expected="deny",
            )
        ],
        validators=[ToolInvocationValidator(frozenset({"read"})), CostValidator(0.10)],
        budget=ScanBudget(max_requests=2),
        seed=42,
    )

    async def callback(prompt):
        return TargetResult(
            "safe",
            tools=("shell",),
            cost_usd=0.25,
            metadata={
                "flow": {"source": {"trust": "untrusted"}, "destination": {"trust": "external"}}
            },
        )

    report = await scanner.scan(callback, prompts=["probe"])
    assert len(report.findings) == 3
    assert report.interactions[0].tool_calls == 1
    assert report.manifest.seed == 42 and report.manifest.target_hash


@pytest.mark.asyncio
async def test_scanner_uses_configured_model_and_module_plan(monkeypatch):
    async def complete(self, messages, **parameters):
        return f"safe: {messages[0]['content']}"

    monkeypatch.setattr("secgraphai.model.Model.complete", complete)
    scanner = SecGraph(target={"base_url": "http://127.0.0.1/v1", "model": "target"})
    report = await scanner.scan(modules=["rag-exfiltration"], strategy="adaptive")
    assert report.interactions and not report.errors

    with pytest.raises(ValueError, match="strategy"):
        await scanner.scan(lambda prompt: "safe", strategy="unknown")


def test_scanner_budget_error_is_not_pass():
    scanner = SecGraph(budget=ScanBudget(max_requests=1))
    report = scanner.scan_callback(lambda prompt: "safe", prompts=["one", "two"])
    assert report.summary()["TEST_ERROR"] == 1


def test_scanner_records_reported_cost_and_enforces_limit():
    budget = ScanBudget(max_cost_usd=0.10)
    scanner = SecGraph(budget=budget)
    report = scanner.scan_callback(
        lambda prompt: TargetResult("safe", cost_usd=0.11), prompts=["one"]
    )
    assert report.summary()["TEST_ERROR"] == 1
    assert budget.requests == 1
    assert budget.cost_usd == 0

    with pytest.raises(ValueError, match="cannot be negative"):
        budget.record_cost(-0.01)


def test_instrumentation_records_success_and_failure():
    recorder = TraceRecorder()

    @instrument
    def works():
        return 3

    assert works() == 3
    generated = works.__secgraph_recorder__
    assert generated.events[0].success

    def fails():
        raise RuntimeError("x")

    wrapped = instrument(fails, recorder=recorder)
    with pytest.raises(RuntimeError):
        wrapped()
    assert recorder.events[0].success is False


def sample_report():
    return Report(
        scan_id="SG-DASH",
        findings=[
            Finding(
                id="SG-F",
                title="finding",
                severity=Severity.HIGH,
                verdict=Verdict.VERIFIED_VIOLATION,
                confidence=1,
                evidence=[Evidence(kind="x", description="x")],
            )
        ],
        graph={"risk_paths": [{"path": ["a", "b"]}]},
    )


def test_dashboard_auth_routes_headers_limits_and_frontend(tmp_path):
    token = "correct-horse-battery-staple"
    client = TestClient(
        create_app(
            database=tmp_path / "db.sqlite", token=token, max_body_bytes=100_000, rate_limit=1000
        )
    )
    assert client.get("/").status_code == 200
    health = client.get("/api/v1/health")
    assert health.status_code == 200 and health.headers["x-frame-options"] == "DENY"
    assert client.get("/api/v1/scans").status_code == 401
    headers = {"Authorization": f"Bearer {token}"}
    assert (
        client.post(
            "/api/v1/scans", headers=headers, json=sample_report().model_dump(mode="json")
        ).status_code
        == 200
    )
    assert client.get("/api/v1/scans/SG-DASH", headers=headers).status_code == 200
    assert client.get("/api/v1/findings/SG-F", headers=headers).status_code == 200
    assert client.post("/api/v1/findings/SG-F/replay", headers=headers).status_code == 200
    assert client.get("/api/v1/attack-paths", headers=headers).json()[0]["path"] == ["a", "b"]


def test_dashboard_rejects_weak_token_and_remote_bind(tmp_path):
    with pytest.raises(ValueError):
        create_app(database=tmp_path / "x", token="short")
    with pytest.raises(ValueError):
        create_app(database=tmp_path / "x", token="a-strong-token-value", bind_host="0.0.0.0")


def test_dashboard_background_scan_jobs_and_live_events(tmp_path):
    token = "correct-horse-battery-staple"
    completed = Report(scan_id="SG-BACKGROUND")

    async def scan_runner(request):
        assert request["target_id"] == "target-1"
        return completed

    app = create_app(
        database=tmp_path / "jobs.db",
        token=token,
        rate_limit=1000,
        scan_runner=scan_runner,
    )
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(app) as client:
        assert (
            client.post(
                "/api/v1/targets",
                headers=headers,
                json={"id": "target-1", "type": "model"},
            ).status_code
            == 200
        )
        with client.websocket_connect("/api/v1/events", headers=headers) as websocket:
            response = client.post(
                "/api/v1/scan-jobs",
                headers=headers,
                json={"target_id": "target-1", "modules": ["agent"]},
            )
            assert response.status_code == 202
            event_types = {websocket.receive_json()["type"] for _ in range(3)}
            assert event_types == {"scan.queued", "scan.running", "scan.completed"}
        job = client.get(
            f"/api/v1/scan-jobs/{response.json()['job_id']}", headers=headers
        ).json()
        assert job["state"] == "COMPLETED" and job["scan_id"] == "SG-BACKGROUND"
        assert client.get("/api/v1/scans/SG-BACKGROUND", headers=headers).status_code == 200


def test_dashboard_scan_job_validation_and_failure_state(tmp_path):
    token = "correct-horse-battery-staple"

    async def broken_runner(request):
        raise RuntimeError("sensitive target detail")

    client = TestClient(
        create_app(
            database=tmp_path / "failed.db",
            token=token,
            rate_limit=1000,
            scan_runner=broken_runner,
        )
    )
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/v1/scan-jobs", headers=headers, json={}).status_code == 422
    assert (
        client.post(
            "/api/v1/scan-jobs", headers=headers, json={"target_id": "missing"}
        ).status_code
        == 404
    )
    client.post(
        "/api/v1/targets",
        headers=headers,
        json={"id": "target-1", "type": "model"},
    )
    response = client.post(
        "/api/v1/scan-jobs", headers=headers, json={"target_id": "target-1"}
    )
    job = client.get(
        f"/api/v1/scan-jobs/{response.json()['job_id']}", headers=headers
    ).json()
    assert job["state"] == "FAILED" and job["error"] == "RuntimeError"
    assert "sensitive" not in str(job)
