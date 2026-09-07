import pytest

from secgraphai.security import Scope, ScopeGuard, doctor, redact


def test_recursive_redaction():
    result = redact({"api_key": "live-value", "nested": ["token=abc", "sk-abcdefghijkl"]})
    assert result == {"api_key": "[REDACTED]", "nested": ["token=[REDACTED]", "[REDACTED]"]}


def test_scope_requires_allowlist():
    guard = ScopeGuard(Scope())
    with pytest.raises(PermissionError, match="explicit scan scope"):
        guard.authorize("https://example.com/path")


def test_doctor_finds_remote_unauthenticated_dashboard_and_secret():
    issues = doctor({"api_key": "bad", "scope": {}, "dashboard": {"host": "0.0.0.0"}})
    assert len(issues) == 4

