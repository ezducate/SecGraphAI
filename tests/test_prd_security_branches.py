from __future__ import annotations

import subprocess

import pytest
from fastapi.testclient import TestClient

from secgraphai.core import Verdict
from secgraphai.dashboard import create_app
from secgraphai.scanner import ScanBudget, SecGraph
from secgraphai.security import Scope, ScopeGuard, doctor
from secgraphai.self_security import AuditStatus, dependency_audit


def guard(**changes):
    values = {
        "allowed_hosts": frozenset({"example.test"}),
        "allowed_ports": frozenset({443}),
        "blocked_networks": (),
        "max_total_requests": 10,
        "max_requests_per_second": 100,
        "max_duration_seconds": 100,
    }
    values.update(changes)
    return ScopeGuard(Scope(**values))


def test_scope_guard_rejects_all_dangerous_branches(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo", lambda *a, **k: [(None, None, None, None, ("8.8.8.8", 443))]
    )
    with pytest.raises(PermissionError, match="HTTP"):
        guard().authorize("file:///x")
    with pytest.raises(PermissionError, match="credentials"):
        guard().authorize("https://u:p@example.test")
    with pytest.raises(PermissionError, match="scope"):
        guard().authorize("https://other.test")
    with pytest.raises(PermissionError, match="prohibited"):
        guard().authorize("https://example.test", action="account_deletion")
    with pytest.raises(PermissionError, match="blocked"):
        guard(blocked_networks=("8.8.8.0/24",)).authorize("https://example.test")
    budget = guard(max_total_requests=0)
    with pytest.raises(PermissionError, match="budget"):
        budget.authorize("https://example.test")
    rate = guard(max_requests_per_second=1)
    rate.authorize("https://example.test")
    with pytest.raises(PermissionError, match="rate"):
        rate.authorize("https://example.test")
    duration = guard(max_duration_seconds=0.000001)
    duration._started = 0
    with pytest.raises(PermissionError, match="duration"):
        duration.authorize("https://example.test")


def test_doctor_all_extended_findings():
    problems = doctor(
        {
            "api_key": "secret",
            "scope": {},
            "dashboard": {"host": "0.0.0.0", "debug": True, "cors": ["*"]},
            "plugins": [{"mode": "in_process"}],
            "evidence": {"redact": False},
        }
    )
    assert len(problems) >= 8


def test_dependency_audit_deep_outcomes(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0))
    assert dependency_audit(True).status == AuditStatus.PASS
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1))
    assert dependency_audit(True).status == AuditStatus.FAIL
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    assert dependency_audit(True).status == AuditStatus.WARN


@pytest.mark.asyncio
async def test_scanner_judge_attack_plan_and_event_loop_guard():
    async def judge(prompt, output):
        return True, 0.9

    scanner = SecGraph(judges=[judge], budget=ScanBudget(max_requests=20))
    report = await scanner.scan_attacks(
        lambda prompt: "semantic unsafe", features={"prompt-injection"}, attack_budget=1
    )
    assert report.findings[0].verdict == Verdict.LIKELY_VIOLATION
    with pytest.raises(RuntimeError, match="event loop"):
        scanner.scan_callback(lambda prompt: "x")


def test_dashboard_body_and_rate_limits(tmp_path):
    client = TestClient(
        create_app(
            database=tmp_path / "db", token="strong-token-value", max_body_bytes=5, rate_limit=1
        )
    )
    assert client.post("/api/v1/scans", content="123456").status_code == 413
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 429
