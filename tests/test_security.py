import pytest

from secgraphai.security import Scope, ScopeGuard, doctor, redact


def test_recursive_redaction():
    result = redact({"api_key": "live-value", "nested": ["token=abc", "sk-abcdefghijkl"]})
    assert result == {"api_key": "[REDACTED]", "nested": ["token=[REDACTED]", "[REDACTED]"]}


def test_cookie_session_and_proxy_credentials_are_redacted():
    assert redact(
        {
            "Cookie": "session=live",
            "Set-Cookie": "sid=live",
            "Proxy-Authorization": "Bearer live",
            "message": "cookie=live session=live",
        }
    ) == {
        "Cookie": "[REDACTED]",
        "Set-Cookie": "[REDACTED]",
        "Proxy-Authorization": "[REDACTED]",
        "message": "cookie=[REDACTED] session=[REDACTED]",
    }

    assert redact("Contact user@example.test or 212-555-0100", mask_pii=True) == (
        "Contact [PII] or [PII]"
    )


def test_scope_requires_allowlist():
    guard = ScopeGuard(Scope())
    with pytest.raises(PermissionError, match="explicit scan scope"):
        guard.authorize("https://example.com/path")


def test_doctor_finds_remote_unauthenticated_dashboard_and_secret():
    issues = doctor({"api_key": "bad", "scope": {}, "dashboard": {"host": "0.0.0.0"}})
    assert len(issues) == 4
